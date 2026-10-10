package capability

import (
	"fmt"
	"slices"
	"strings"
)

// SyscallLabelPrefix namespaces the provenance the flow monitor stamps on every
// result ("syscall:<name>"). A manifest may not declare a label in it, or a
// grant could forge that provenance.
const SyscallLabelPrefix = "syscall:"

// NormalizeLabels canonicalizes a declared label set (an operation's source
// classes, or the labels it forbids): trimmed, without empties, deduplicated
// and sorted. It refuses a label in the reserved SyscallLabelPrefix namespace.
// An empty set normalizes to nil. what names the field in the error ("labels",
// "taints").
func NormalizeLabels(what string, labels []string) ([]string, error) {
	var out []string
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		if strings.HasPrefix(label, SyscallLabelPrefix) {
			return nil, fmt.Errorf("%s label %q uses the reserved %q prefix", what, label, SyscallLabelPrefix)
		}
		out = append(out, label)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
