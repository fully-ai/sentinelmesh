package plugin

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
)

func TestSandboxedPluginExecutionAndEnvIsolation(t *testing.T) {
	t.Setenv("SENTINELMESH_SUPER_SECRET", "must_never_leak_to_plugin")
	bin, _ := filepath.Abs("../../examples/plugins/tagger.sh")
	runner := NewRunner([]PluginSpec{
		{ID: "tagger", Name: "Tagger", Kind: "enricher", Binary: bin, Enabled: true},
		{ID: "disabled", Name: "Disabled", Kind: "enricher", Binary: bin, Enabled: false},
	}, 2*time.Second)

	if len(runner.List()) != 2 {
		t.Fatal("expected 2 plugins listed")
	}
	res := runner.InvokeAlert(context.Background(), "tagger", domain.Alert{ID: "a1", RuleName: "Test"})
	if !res.Success || len(res.Tags) == 0 {
		t.Fatalf("expected plugin success, got %+v", res)
	}
	dis := runner.InvokeAlert(context.Background(), "disabled", domain.Alert{ID: "a1"})
	if dis.Success {
		t.Fatal("expected disabled plugin invocation to fail")
	}
}
