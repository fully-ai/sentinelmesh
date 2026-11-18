package pipeline

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/detection"
	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/fully-ai/sentinelmesh/internal/storage"
	"github.com/fully-ai/sentinelmesh/internal/threatintel"
	"github.com/google/uuid"
)

// ErrQueueFull indicates bounded ingestion backpressure saturation.
var ErrQueueFull = errors.New("ingestion pipeline saturated")

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9\-_\.=]+`),
	regexp.MustCompile(`(?i)(--?(?:password|passwd|token|secret|api[-_]?key)[=\s]+)([^\s'"]+)`),
	regexp.MustCompile(`(gh[pousr]_[A-Za-z0-9_]{12,})`),
}

// RedactSecrets masks credential tokens in event command lines and summaries before persistence.
func RedactSecrets(ev *domain.Event) {
	redact := func(s string) string {
		out := s
		for idx, re := range secretPatterns {
			if idx == 2 {
				out = re.ReplaceAllString(out, "[REDACTED_TOKEN]")
			} else {
				out = re.ReplaceAllString(out, "${1}[REDACTED]")
			}
		}
		return out
	}
	if ev.Summary != "" {
		ev.Summary = redact(ev.Summary)
	}
	if ev.Process != nil && ev.Process.Cmdline != "" {
		ev.Process.Cmdline = redact(ev.Process.Cmdline)
	}
}

// Metrics captures live pipeline throughput and backpressure counters.
type Metrics struct {
	Enqueued  uint64 `json:"enqueued"`
	Processed uint64 `json:"processed"`
	Dropped   uint64 `json:"dropped"`
	Alerts    uint64 `json:"alerts_generated"`
	QueueLen  int    `json:"queue_len"`
	QueueCap  int    `json:"queue_cap"`
}

// Pipeline processes ingested events asynchronously with bounded queues, redaction, IOC matching, and rule evaluation.
type Pipeline struct {
	store     *storage.Store
	engine    *detection.Engine
	iocs      *threatintel.Matcher
	queue     chan domain.Event
	wg        sync.WaitGroup
	stopOnce  sync.Once
	stopCh    chan struct{}
	enqueued  atomic.Uint64
	processed atomic.Uint64
	dropped   atomic.Uint64
	alertsGen atomic.Uint64
}

// New creates an ingestion pipeline with bounded queue capacity.
func New(store *storage.Store, engine *detection.Engine, iocs *threatintel.Matcher, capacity int) *Pipeline {
	if capacity <= 0 {
		capacity = 4096
	}
	return &Pipeline{
		store:  store,
		engine: engine,
		iocs:   iocs,
		queue:  make(chan domain.Event, capacity),
		stopCh: make(chan struct{}),
	}
}

// Start launches background worker goroutines draining and persisting events.
func (p *Pipeline) Start(workers int) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.workerLoop()
	}
}

// Stop flushes queued events cleanly and waits for workers to exit.
func (p *Pipeline) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
	p.wg.Wait()
}

// Enqueue validates, redacts, and submits events under non-blocking backpressure.
func (p *Pipeline) Enqueue(events []domain.Event) error {
	for i := range events {
		if events[i].ID == "" {
			events[i].ID = uuid.NewString()
		}
		if err := events[i].Validate(); err != nil {
			return err
		}
		RedactSecrets(&events[i])
		select {
		case p.queue <- events[i]:
			p.enqueued.Add(1)
		default:
			p.dropped.Add(1)
			return ErrQueueFull
		}
	}
	return nil
}

// ProcessSync validates, persists, and evaluates events synchronously (used by CLI & deterministic tests).
func (p *Pipeline) ProcessSync(ctx context.Context, events []domain.Event) ([]domain.Alert, error) {
	for i := range events {
		if events[i].ID == "" {
			events[i].ID = uuid.NewString()
		}
		if err := events[i].Validate(); err != nil {
			return nil, err
		}
		RedactSecrets(&events[i])
	}
	if err := p.store.InsertEventsBatch(ctx, events); err != nil {
		return nil, err
	}
	p.processed.Add(uint64(len(events)))

	var emitted []domain.Alert
	for _, ev := range events {
		alerts := p.evaluateEvent(ctx, ev)
		emitted = append(emitted, alerts...)
	}
	return emitted, nil
}

// Stats returns a thread-safe snapshot of pipeline metrics.
func (p *Pipeline) Stats() Metrics {
	return Metrics{
		Enqueued:  p.enqueued.Load(),
		Processed: p.processed.Load(),
		Dropped:   p.dropped.Load(),
		Alerts:    p.alertsGen.Load(),
		QueueLen:  len(p.queue),
		QueueCap:  cap(p.queue),
	}
}

func (p *Pipeline) workerLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]domain.Event, 0, 64)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := p.store.InsertEventsBatch(ctx, batch); err == nil {
			p.processed.Add(uint64(len(batch)))
			for _, ev := range batch {
				p.evaluateEvent(ctx, ev)
			}
		}
		cancel()
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-p.queue:
			batch = append(batch, ev)
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-p.stopCh:
			for {
				select {
				case ev := <-p.queue:
					batch = append(batch, ev)
					if len(batch) >= 64 {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (p *Pipeline) evaluateEvent(ctx context.Context, ev domain.Event) []domain.Alert {
	var emitted []domain.Alert

	// 1. Threat Intel IOC Matching
	if p.iocs != nil {
		matches := p.iocs.MatchEvent(ev)
		for _, m := range matches {
			alert := domain.Alert{
				ID:          uuid.NewString(),
				TenantID:    ev.TenantID,
				RuleID:      "SM-TI-IOC-MATCH",
				RuleName:    fmt.Sprintf("Threat Intel IOC Match (%s)", strings.ToUpper(string(m.Indicator.Type))),
				RuleVersion: 1,
				AgentID:     ev.AgentID,
				Host:        ev.Host,
				Severity:    m.Indicator.Severity,
				Status:      domain.AlertOpen,
				Priority:    domain.SeverityRank(m.Indicator.Severity)*20 + (m.Indicator.Confidence / 10),
				MITRE:       []string{"TA0011"},
				Explanation: fmt.Sprintf("Event field %s=%q matched IOC %s (%s, confidence=%d%%, source=%s)",
					m.Field, m.Value, m.Indicator.Value, m.Indicator.Type, m.Indicator.Confidence, m.Indicator.Source),
				DedupKey: fmt.Sprintf("ioc|%s|%s|%s", ev.AgentID, m.Indicator.Type, m.Indicator.Value),
				HitCount: 1,
				EventIDs: []string{ev.ID},
				Evidence: map[string]string{
					"ioc_id":     m.Indicator.ID,
					"ioc_source": m.Indicator.Source,
					"field":      m.Field,
					"matched":    m.Value,
				},
				CreatedAt:  ev.OccurredAt,
				LastSeenAt: ev.OccurredAt,
			}
			if _, err := p.store.UpsertOrDedupAlert(ctx, &alert, 5*time.Minute); err == nil {
				p.alertsGen.Add(1)
				emitted = append(emitted, alert)
			}
		}
	}

	// 2. Declarative YAML Rules + Correlation Windows + EWMA Anomaly
	if p.engine != nil {
		ruleAlerts := p.engine.Evaluate(ev)
		for i := range ruleAlerts {
			a := ruleAlerts[i]
			if _, err := p.store.UpsertOrDedupAlert(ctx, &a, 2*time.Minute); err == nil {
				p.alertsGen.Add(1)
				emitted = append(emitted, a)
			}
		}
	}
	return emitted
}
