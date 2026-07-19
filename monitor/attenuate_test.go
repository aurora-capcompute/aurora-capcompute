package monitor

import (
	"strings"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

func TestAttenuateGrantsSubset(t *testing.T) {
	parent := []sys.Capability{{Name: "internet.read"}, {Name: "sys.timer"}, {Name: "k8s.get"}}
	requested := []sys.Capability{{Name: "sys.timer"}, {Name: "internet.read"}}

	granted, err := Attenuate(parent, requested)
	if err != nil {
		t.Fatalf("attenuate: %v", err)
	}
	if len(granted) != 2 || granted[0].Name != "sys.timer" || granted[1].Name != "internet.read" {
		t.Fatalf("granted = %+v", granted)
	}
}

func TestAttenuateRefusesEscalation(t *testing.T) {
	parent := []sys.Capability{{Name: "sys.timer"}}
	requested := []sys.Capability{{Name: "sys.timer"}, {Name: "k8s.delete"}, {Name: "internet.read"}}

	if _, err := Attenuate(parent, requested); err == nil {
		t.Fatal("expected attenuation violation")
	} else if !strings.Contains(err.Error(), "internet.read, k8s.delete") {
		t.Fatalf("error = %v, want sorted missing names", err)
	}
}

func TestAttenuateEmptyRequestIsEmptyGrant(t *testing.T) {
	granted, err := Attenuate([]sys.Capability{{Name: "sys.timer"}}, nil)
	if err != nil {
		t.Fatalf("attenuate: %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("granted = %+v, want empty", granted)
	}
}
