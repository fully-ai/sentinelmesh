package detection

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Condition defines a single field predicate or compound logical node.
type Condition struct {
	Field    string   `yaml:"field" json:"field"`
	Op       string   `yaml:"op" json:"op"` // equals, contains, prefix, suffix, regex, in, cidr, gt, lt
	Value    string   `yaml:"value" json:"value"`
	Values   []string `yaml:"values" json:"values"`
	CaseFold bool     `yaml:"case_fold" json:"case_fold"`
	compiled *regexp.Regexp
	prefix   *netip.Prefix
}

// CorrelationSpec configures sliding-window counting or multi-step sequence correlation.
type CorrelationSpec struct {
	WindowSeconds int      `yaml:"window_seconds" json:"window_seconds"`
	Threshold     int      `yaml:"threshold" json:"threshold"`
	GroupBy       []string `yaml:"group_by" json:"group_by"`
	Sequence      []Step   `yaml:"sequence" json:"sequence"`
}

// Step defines one ordered stage inside a sequence correlation rule.
type Step struct {
	Name  string      `yaml:"name" json:"name"`
	Match []Condition `yaml:"match" json:"match"`
}

// RuleSpec defines a declarative YAML detection or correlation rule.
type RuleSpec struct {
	ID           string           `yaml:"id" json:"id"`
	Name         string           `yaml:"name" json:"name"`
	Description  string           `yaml:"description" json:"description"`
	Version      int              `yaml:"version" json:"version"`
	Enabled      bool             `yaml:"enabled" json:"enabled"`
	Severity     domain.Severity  `yaml:"severity" json:"severity"`
	Priority     int              `yaml:"priority" json:"priority"`
	MITRE        []string         `yaml:"mitre" json:"mitre"`
	DedupSeconds int              `yaml:"dedup_seconds" json:"dedup_seconds"`
	All          []Condition      `yaml:"all" json:"all"`
	Any          []Condition      `yaml:"any" json:"any"`
	Not          []Condition      `yaml:"not" json:"not"`
	Correlation  *CorrelationSpec `yaml:"correlation,omitempty" json:"correlation,omitempty"`
}

// ParseRuleYAML unmarshals and validates a YAML rule specification, precompiling regex/CIDR predicates.
func ParseRuleYAML(raw string) (*RuleSpec, error) {
	var spec RuleSpec
	if err := yaml.Unmarshal([]byte(raw), &spec); err != nil {
		return nil, fmt.Errorf("parse yaml rule: %w", err)
	}
	if strings.TrimSpace(spec.ID) == "" || strings.TrimSpace(spec.Name) == "" {
		return nil, fmt.Errorf("rule requires non-empty id and name")
	}
	if spec.Version <= 0 {
		spec.Version = 1
	}
	if spec.Severity == "" {
		spec.Severity = domain.SeverityMedium
	}
	if spec.Priority <= 0 {
		spec.Priority = domain.SeverityRank(spec.Severity) * 20
	}
	compileList := func(conds []Condition) error {
		for i := range conds {
			if err := compileCondition(&conds[i]); err != nil {
				return err
			}
		}
		return nil
	}
	if err := compileList(spec.All); err != nil {
		return nil, err
	}
	if err := compileList(spec.Any); err != nil {
		return nil, err
	}
	if err := compileList(spec.Not); err != nil {
		return nil, err
	}
	if spec.Correlation != nil {
		for i := range spec.Correlation.Sequence {
			if err := compileList(spec.Correlation.Sequence[i].Match); err != nil {
				return nil, err
			}
		}
	}
	return &spec, nil
}

func compileCondition(c *Condition) error {
	if c.Field == "" {
		return fmt.Errorf("condition missing field")
	}
	switch c.Op {
	case "", "equals", "contains", "prefix", "suffix", "in", "gt", "lt":
		if c.Op == "" {
			c.Op = "equals"
		}
	case "regex":
		pattern := c.Value
		if c.CaseFold && !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regex %q on field %s: %w", c.Value, c.Field, err)
		}
		c.compiled = re
	case "cidr":
		p, err := netip.ParsePrefix(strings.TrimSpace(c.Value))
		if err != nil {
			return fmt.Errorf("invalid cidr %q: %w", c.Value, err)
		}
		c.prefix = &p
	default:
		return fmt.Errorf("unsupported condition operator %q", c.Op)
	}
	return nil
}

func evalCondition(ev domain.Event, c Condition) (bool, string) {
	actual, ok := ev.LookupField(c.Field)
	if !ok {
		return false, ""
	}
	lhs := actual
	rhs := c.Value
	if c.CaseFold {
		lhs = strings.ToLower(lhs)
		rhs = strings.ToLower(rhs)
	}
	var matched bool
	switch c.Op {
	case "equals":
		matched = lhs == rhs
	case "contains":
		matched = strings.Contains(lhs, rhs)
	case "prefix":
		matched = strings.HasPrefix(lhs, rhs)
	case "suffix":
		matched = strings.HasSuffix(lhs, rhs)
	case "regex":
		matched = c.compiled != nil && c.compiled.MatchString(actual)
	case "in":
		for _, candidate := range c.Values {
			cmp := candidate
			if c.CaseFold {
				cmp = strings.ToLower(cmp)
			}
			if lhs == cmp {
				matched = true
				break
			}
		}
	case "cidr":
		if c.prefix != nil {
			if addr, err := netip.ParseAddr(strings.TrimSpace(actual)); err == nil {
				matched = c.prefix.Contains(addr)
			}
		}
	case "gt", "lt":
		aNum, errA := strconv.ParseFloat(actual, 64)
		bNum, errB := strconv.ParseFloat(c.Value, 64)
		if errA == nil && errB == nil {
			if c.Op == "gt" {
				matched = aNum > bNum
			} else {
				matched = aNum < bNum
			}
		}
	}
	if !matched {
		return false, ""
	}
	return true, fmt.Sprintf("%s %s %q (observed %q)", c.Field, c.Op, c.Value, truncate(actual, 120))
}

func matchRuleBase(ev domain.Event, r *RuleSpec) (bool, []string) {
	var reasons []string
	for _, cond := range r.All {
		ok, reason := evalCondition(ev, cond)
		if !ok {
			return false, nil
		}
		reasons = append(reasons, reason)
	}
	if len(r.Any) > 0 {
		anyOK := false
		for _, cond := range r.Any {
			if ok, reason := evalCondition(ev, cond); ok {
				anyOK = true
				reasons = append(reasons, reason)
			}
		}
		if !anyOK {
			return false, nil
		}
	}
	for _, cond := range r.Not {
		if ok, _ := evalCondition(ev, cond); ok {
			return false, nil
		}
	}
	return true, reasons
}

// Engine evaluates YAML rules, correlation windows, sequence patterns, and EWMA baselines.
type Engine struct {
	mu           sync.RWMutex
	rules        []*RuleSpec
	corrWindows  map[string][]corrHit
	seqState     map[string]seqTracker
	suppressions map[string]time.Time
	anomaly      *AnomalyTracker
}

type corrHit struct {
	eventID string
	ts      time.Time
}

type seqTracker struct {
	stageIndex int
	startedAt  time.Time
	eventIDs   []string
	reasons    []string
}

// NewEngine initializes a rule engine loaded with provided RuleSpecs.
func NewEngine(rules []*RuleSpec) *Engine {
	return &Engine{
		rules:        rules,
		corrWindows:  make(map[string][]corrHit),
		seqState:     make(map[string]seqTracker),
		suppressions: make(map[string]time.Time),
		anomaly:      NewAnomalyTracker(0.25, 3.2, 15),
	}
}

// SetRules atomically replaces active detection rules.
func (e *Engine) SetRules(rules []*RuleSpec) {
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

// Rules returns a snapshot of loaded rule specs.
func (e *Engine) Rules() []*RuleSpec {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*RuleSpec, len(e.rules))
	copy(out, e.rules)
	return out
}

// SuppressDedupKey suppresses alerts for dedupKey until the duration expires.
func (e *Engine) SuppressDedupKey(dedupKey string, dur time.Duration) {
	e.mu.Lock()
	e.suppressions[dedupKey] = time.Now().UTC().Add(dur)
	e.mu.Unlock()
}

// Evaluate runs all enabled rules and statistical EWMA anomaly checks against ev.
func (e *Engine) Evaluate(ev domain.Event) []domain.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := ev.OccurredAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var alerts []domain.Alert
	for _, r := range e.rules {
		if !r.Enabled {
			continue
		}
		if r.Correlation != nil && len(r.Correlation.Sequence) > 0 {
			if alert := e.evalSequenceRule(ev, r, now); alert != nil {
				alerts = append(alerts, *alert)
			}
			continue
		}

		matched, reasons := matchRuleBase(ev, r)
		if !matched {
			continue
		}

		groupKey := e.buildGroupKey(ev, r)
		dedupKey := fmt.Sprintf("%s|%s", r.ID, groupKey)
		if until, sup := e.suppressions[dedupKey]; sup && now.Before(until) {
			continue
		}

		if r.Correlation != nil && r.Correlation.Threshold > 1 {
			win := time.Duration(r.Correlation.WindowSeconds) * time.Second
			if win <= 0 {
				win = 60 * time.Second
			}
			cutoff := now.Add(-win)
			hits := e.corrWindows[dedupKey]
			kept := hits[:0]
			for _, h := range hits {
				if h.ts.After(cutoff) {
					kept = append(kept, h)
				}
			}
			kept = append(kept, corrHit{eventID: ev.ID, ts: now})
			e.corrWindows[dedupKey] = kept
			if len(kept) < r.Correlation.Threshold {
				continue
			}
			evIDs := make([]string, 0, len(kept))
			for _, h := range kept {
				evIDs = append(evIDs, h.eventID)
			}
			explanation := fmt.Sprintf("Correlation rule %q matched %d events within %ds (key=%s): %s",
				r.Name, len(kept), int(win.Seconds()), groupKey, strings.Join(reasons, "; "))
			alerts = append(alerts, buildAlert(r, ev, dedupKey, explanation, evIDs, map[string]string{
				"correlation_hits": strconv.Itoa(len(kept)),
				"window_seconds":   strconv.Itoa(int(win.Seconds())),
				"group_key":        groupKey,
			}))
			// Reset window slice after firing so repeated bursts require another window or dedup handles it
			e.corrWindows[dedupKey] = nil
			continue
		}

		explanation := fmt.Sprintf("Rule %q matched: %s", r.Name, strings.Join(reasons, "; "))
		alerts = append(alerts, buildAlert(r, ev, dedupKey, explanation, []string{ev.ID}, map[string]string{
			"category": string(ev.Category),
			"action":   ev.Action,
		}))
	}

	if anomalyAlert := e.anomaly.Observe(ev); anomalyAlert != nil {
		alerts = append(alerts, *anomalyAlert)
	}
	return alerts
}

func (e *Engine) evalSequenceRule(ev domain.Event, r *RuleSpec, now time.Time) *domain.Alert {
	groupKey := e.buildGroupKey(ev, r)
	seqKey := fmt.Sprintf("%s|%s", r.ID, groupKey)
	win := time.Duration(r.Correlation.WindowSeconds) * time.Second
	if win <= 0 {
		win = 300 * time.Second
	}

	tr, exists := e.seqState[seqKey]
	if exists && now.Sub(tr.startedAt) > win {
		delete(e.seqState, seqKey)
		exists = false
	}

	nextStage := 0
	if exists {
		nextStage = tr.stageIndex
	}
	steps := r.Correlation.Sequence
	if nextStage >= len(steps) {
		nextStage = 0
	}

	matchStep := func(s Step) (bool, []string) {
		var rs []string
		for _, c := range s.Match {
			ok, why := evalCondition(ev, c)
			if !ok {
				return false, nil
			}
			rs = append(rs, why)
		}
		return true, rs
	}

	if ok, rs := matchStep(steps[nextStage]); ok {
		if !exists {
			tr = seqTracker{startedAt: now}
		}
		tr.stageIndex = nextStage + 1
		tr.eventIDs = append(tr.eventIDs, ev.ID)
		tr.reasons = append(tr.reasons, fmt.Sprintf("[%s: %s]", steps[nextStage].Name, strings.Join(rs, ", ")))
		if tr.stageIndex == len(steps) {
			delete(e.seqState, seqKey)
			explanation := fmt.Sprintf("Sequence correlation %q completed %d stages in %s (key=%s): %s",
				r.Name, len(steps), now.Sub(tr.startedAt).Round(time.Millisecond), groupKey, strings.Join(tr.reasons, " -> "))
			a := buildAlert(r, ev, seqKey, explanation, tr.eventIDs, map[string]string{
				"sequence_stages": strconv.Itoa(len(steps)),
				"group_key":       groupKey,
			})
			return &a
		}
		e.seqState[seqKey] = tr
	}
	return nil
}

func (e *Engine) buildGroupKey(ev domain.Event, r *RuleSpec) string {
	if r.Correlation == nil || len(r.Correlation.GroupBy) == 0 {
		return ev.AgentID
	}
	parts := make([]string, 0, len(r.Correlation.GroupBy))
	for _, f := range r.Correlation.GroupBy {
		v, ok := ev.LookupField(f)
		if !ok {
			v = "_"
		}
		parts = append(parts, f+"="+v)
	}
	return strings.Join(parts, ",")
}

func buildAlert(r *RuleSpec, ev domain.Event, dedupKey, explanation string, eventIDs []string, evidence map[string]string) domain.Alert {
	now := ev.OccurredAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return domain.Alert{
		ID:          uuid.NewString(),
		TenantID:    ev.TenantID,
		RuleID:      r.ID,
		RuleName:    r.Name,
		RuleVersion: r.Version,
		AgentID:     ev.AgentID,
		Host:        ev.Host,
		Severity:    r.Severity,
		Status:      domain.AlertOpen,
		Priority:    r.Priority,
		MITRE:       r.MITRE,
		Explanation: explanation,
		DedupKey:    dedupKey,
		HitCount:    1,
		EventIDs:    eventIDs,
		Evidence:    evidence,
		CreatedAt:   now,
		LastSeenAt:  now,
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// AnomalyTracker implements an explainable per-(agent, category) EWMA + Z-score event rate anomaly baseline.
type AnomalyTracker struct {
	alpha      float64
	zThreshold float64
	minSamples int
	buckets    map[string]*rateBucket
}

type rateBucket struct {
	currentWindowStart time.Time
	currentCount       int
	samples            int
	mean               float64
	variance           float64
}

// NewAnomalyTracker builds a statistical EWMA rate baseline detector.
func NewAnomalyTracker(alpha, zThreshold float64, minSamples int) *AnomalyTracker {
	return &AnomalyTracker{
		alpha:      alpha,
		zThreshold: zThreshold,
		minSamples: minSamples,
		buckets:    make(map[string]*rateBucket),
	}
}

// Observe tracks per-minute rate per (agent, category) and flags spikes exceeding zThreshold once calibrated.
func (a *AnomalyTracker) Observe(ev domain.Event) *domain.Alert {
	if ev.Category == domain.CategoryHealth {
		return nil
	}
	ts := ev.OccurredAt
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	winStart := ts.Truncate(time.Minute)
	key := ev.AgentID + "|" + string(ev.Category)
	b, ok := a.buckets[key]
	if !ok {
		a.buckets[key] = &rateBucket{currentWindowStart: winStart, currentCount: 1}
		return nil
	}
	if winStart.Equal(b.currentWindowStart) {
		b.currentCount++
		// Check live intra-minute spike only if baseline is already calibrated
		if b.samples >= a.minSamples {
			std := math.Sqrt(math.Max(b.variance, 1.0))
			z := (float64(b.currentCount) - b.mean) / std
			if z >= a.zThreshold && b.currentCount >= 10 {
				return &domain.Alert{
					ID:          uuid.NewString(),
					TenantID:    ev.TenantID,
					RuleID:      "SM-ANOM-EWMA-001",
					RuleName:    "Statistical Event Rate Spike (EWMA Z-Score)",
					RuleVersion: 1,
					AgentID:     ev.AgentID,
					Host:        ev.Host,
					Severity:    domain.SeverityMedium,
					Status:      domain.AlertOpen,
					Priority:    60,
					MITRE:       []string{"TA0005", "TA0011"},
					Explanation: fmt.Sprintf("Observed %d %s events in 1m window vs EWMA baseline mean=%.2f std=%.2f (Z=%.2f >= %.2f)",
						b.currentCount, ev.Category, b.mean, std, z, a.zThreshold),
					DedupKey: fmt.Sprintf("ewma|%s|%s", key, winStart.Format(time.RFC3339)),
					HitCount: 1,
					EventIDs: []string{ev.ID},
					Evidence: map[string]string{
						"observed_count": strconv.Itoa(b.currentCount),
						"baseline_mean":  fmt.Sprintf("%.2f", b.mean),
						"baseline_std":   fmt.Sprintf("%.2f", std),
						"z_score":        fmt.Sprintf("%.2f", z),
					},
					CreatedAt:  ts,
					LastSeenAt: ts,
				}
			}
		}
		return nil
	}

	// Fold closed window into EWMA mean & variance
	x := float64(b.currentCount)
	if b.samples == 0 {
		b.mean = x
		b.variance = 1.0
	} else {
		diff := x - b.mean
		b.mean = (1-a.alpha)*b.mean + a.alpha*x
		b.variance = (1-a.alpha)*b.variance + a.alpha*diff*diff
	}
	b.samples++
	b.currentWindowStart = winStart
	b.currentCount = 1
	return nil
}
