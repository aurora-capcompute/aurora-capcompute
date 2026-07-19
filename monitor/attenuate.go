package monitor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Attenuate returns the requested capabilities, verifying that delegation
// only shrinks authority: every requested capability must exist in parent
// (matched by name). This is the KeyKOS/seL4 delegation law — a parent cannot
// grant what it does not hold. Per-capability settings lattices (e.g. allowed
// origins narrower than the parent's) are the granting registration's
// responsibility; this helper owns the name-level subset check all grants
// share.
func Attenuate(parent, requested []sys.Capability) ([]sys.Capability, error) {
	held := make(map[string]struct{}, len(parent))
	for _, capability := range parent {
		held[capability.Name] = struct{}{}
	}

	var missing []string
	granted := make([]sys.Capability, 0, len(requested))
	for _, capability := range requested {
		if _, ok := held[capability.Name]; !ok {
			missing = append(missing, capability.Name)
			continue
		}
		granted = append(granted, capability)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("attenuation violation: parent does not hold %s", strings.Join(missing, ", "))
	}
	return granted, nil
}
