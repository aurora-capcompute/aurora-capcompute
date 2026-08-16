// The label vocabulary: the alphabet Entry.Labels and Entry.Forbid are written
// in, and the reserved namespace the flow monitor stamps its own provenance in.
package capability

import (
	"fmt"
	"sort"
	"strings"
)

// SyscallLabelPrefix namespaces the automatic provenance the flow monitor stamps on
// every result ("syscall:<name>"). It is reserved: a manifest may not declare a
// label in this namespace, or a grant could forge the provenance the Labeler
// itself stamps.
const SyscallLabelPrefix = "syscall:"

// NormalizeLabels canonicalizes a declared label set (a capability's source
// classes, or the sink labels it forbids): trim, drop empties, de-duplicate,
// and sort so journal digests are deterministic. A label in the reserved
// SyscallLabelPrefix namespace is rejected — that provenance is the monitor's
// to stamp, never the manifest's to claim. An empty set normalizes to nil. `what`
// names the field for the error message ("labels", "taints").
func NormalizeLabels(what string, labels []string) ([]string, error) {
	seen := make(map[string]struct{}, len(labels))
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		if strings.HasPrefix(label, SyscallLabelPrefix) {
			return nil, fmt.Errorf("%s label %q uses the reserved %q prefix", what, label, SyscallLabelPrefix)
		}
		if _, dup := seen[label]; dup {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, label)
	}
	if len(out) == 0 {
		return nil, nil
	}
	sort.Strings(out)
	return out, nil
}

// BlockedBy returns the sorted intersection of a call's forbidden labels and the
// process's accumulated taint (Taint) — the labels a self-classifying driver
// must refuse to let flow into this operation. Empty means the sink is clear.
// A driver checks this before its side effect; the runtime's flow monitor performs
// the same check for any Forbid its entry declares.
func BlockedBy(taint, forbid []string) []string {
	if len(taint) == 0 || len(forbid) == 0 {
		return nil
	}
	has := make(map[string]struct{}, len(taint))
	for _, label := range taint {
		has[label] = struct{}{}
	}
	var blocked []string
	for _, label := range forbid {
		if _, ok := has[label]; ok {
			blocked = append(blocked, label)
		}
	}
	sort.Strings(blocked)
	return blocked
}
