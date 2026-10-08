package capability

import "testing"

func TestNormalizeLabels(t *testing.T) {
	got, err := NormalizeLabels("labels", []string{" untrusted_web ", "untrusted_web", "", "secret"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(got) != 2 || got[0] != "secret" || got[1] != "untrusted_web" {
		t.Fatalf("got %v, want [secret untrusted_web] (trimmed, deduped, sorted)", got)
	}
	if out, err := NormalizeLabels("labels", nil); err != nil || out != nil {
		t.Fatalf("empty set = (%v, %v), want (nil, nil)", out, err)
	}
	if _, err := NormalizeLabels("labels", []string{"syscall:core.memory"}); err == nil {
		t.Fatal("expected the reserved syscall: prefix to be rejected")
	}
}
