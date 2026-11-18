package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
)

// PluginSpec registers an isolated subprocess integration (notifier or enricher).
type PluginSpec struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"` // enricher, notifier
	Binary  string `json:"binary"`
	Enabled bool   `json:"enabled"`
}

// InvocationResult captures bounded sandboxed plugin stdout response.
type InvocationResult struct {
	PluginID string            `json:"plugin_id"`
	Success  bool              `json:"success"`
	Tags     []string          `json:"tags,omitempty"`
	Message  string            `json:"message,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// Runner executes plugins out-of-process with scrubbed env, timeout, and output size cap.
type Runner struct {
	plugins     []PluginSpec
	timeout     time.Duration
	maxOutBytes int
}

// NewRunner constructs a sandboxed subprocess plugin runner.
func NewRunner(plugins []PluginSpec, timeout time.Duration) *Runner {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Runner{
		plugins:     plugins,
		timeout:     timeout,
		maxOutBytes: 64 * 1024,
	}
}

// List returns configured plugin specs.
func (r *Runner) List() []PluginSpec {
	out := make([]PluginSpec, len(r.plugins))
	copy(out, r.plugins)
	return out
}

// InvokeAlert runs an enabled plugin on an alert with stripped environment variables.
func (r *Runner) InvokeAlert(ctx context.Context, pluginID string, alert domain.Alert) InvocationResult {
	var spec *PluginSpec
	for i := range r.plugins {
		if r.plugins[i].ID == pluginID && r.plugins[i].Enabled {
			spec = &r.plugins[i]
			break
		}
	}
	if spec == nil {
		return InvocationResult{PluginID: pluginID, Success: false, Error: "plugin not found or disabled"}
	}
	cleanPath := filepath.Clean(spec.Binary)
	payload, err := json.Marshal(map[string]any{
		"type":  "alert",
		"alert": alert,
	})
	if err != nil {
		return InvocationResult{PluginID: pluginID, Success: false, Error: err.Error()}
	}

	cctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, cleanPath)
	// Scrubbed environment: inherit zero server secrets or API keys.
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"SENTINELMESH_PLUGIN_ID=" + spec.ID,
		"SENTINELMESH_PLUGIN_KIND=" + spec.Kind,
	}
	cmd.Stdin = bytes.NewReader(payload)

	var stdout, stderr cappedBuffer
	stdout.max = r.maxOutBytes
	stderr.max = 8 * 1024
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return InvocationResult{
			PluginID: pluginID,
			Success:  false,
			Error:    fmt.Sprintf("%v: %s", err, stderr.String()),
		}
	}

	var res InvocationResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return InvocationResult{
			PluginID: pluginID,
			Success:  true,
			Message:  stdout.String(),
		}
	}
	res.PluginID = pluginID
	res.Success = true
	return res
}

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	rem := c.max - c.buf.Len()
	if rem > 0 {
		take := len(p)
		if take > rem {
			take = rem
		}
		_, _ = c.buf.Write(p[:take])
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte  { return c.buf.Bytes() }
func (c *cappedBuffer) String() string { return c.buf.String() }
