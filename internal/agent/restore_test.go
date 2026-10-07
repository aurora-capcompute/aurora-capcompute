package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// vanishedToolDispatchers refuses one tool type, standing in for a driver set
// that no longer compiles in a capability historical manifests still name.
type vanishedToolDispatchers struct{ runtimeDispatchers }

func (p *vanishedToolDispatchers) ValidateConfig(toolType string, settings json.RawMessage) error {
	if toolType == "core.gone" {
		return errors.New("unsupported tool type")
	}
	return p.runtimeDispatchers.ValidateConfig(toolType, settings)
}

// A historical run whose manifest names a decommissioned tool type must not
// prevent the runtime from booting: it is quarantined — restored verbatim and
// visible — and a retry fails with the provider's error instead of running.
func TestRestoreQuarantinesStaleManifests(t *testing.T) {
	store := newRuntimeStore()
	now := time.Now().UTC().Add(-time.Hour)
	store.seed(
		durable.Process{
			TenantID: "local", ID: "run_old", SessionID: "ses_old", Revision: 1,
			Input: "old work", Status: durable.ProcessFailed,
			CreatedAt: now, UpdatedAt: now,
			Manifest: manifest.Manifest{
				Version:  manifest.Version,
				Program:  "program@1",
				Syscalls: []manifest.Syscall{{Syscall: "core.gone"}},
			},
			ProgramDigest: "stale-digest",
		},
	)
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: &vanishedToolDispatchers{},
		Log:         store.log,
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("boot with stale manifest: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Close(ctx)
	})

	// The quarantined run is visible with its manifest intact.
	snap, err := runtime.GetProcess("run_old")
	if err != nil {
		t.Fatalf("get quarantined run: %v", err)
	}
	if len(snap.Manifest.Syscalls) != 1 || snap.Manifest.Syscalls[0].Syscall != "core.gone" {
		t.Fatalf("quarantined manifest = %+v", snap.Manifest)
	}

	// Re-driving it fails at manifest/driver build, not silently.
	if _, err := runtime.Retry("run_old", RetryRestart); err == nil {
		proc := waitForProcessFailed(t, runtime, "run_old")
		if proc.Error == "" {
			t.Fatal("retried quarantined run finished without an error")
		}
	}
}
