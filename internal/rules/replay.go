package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ratuhin1122/taintwatch/internal/policy"
)

// Increment when matcher/trace semantics change so old facts are not silently
// interpreted as results of a different matching implementation.
const matchSchemaVersion = 3

// Snapshot is a complete predicate-match vector for frozen historical state.
// Only IDs and a configuration digest are retained, never raw predicate inputs.
type Snapshot struct {
	Version     int      `json:"version"`
	Fingerprint string   `json:"match_policy_sha256"`
	Matches     []string `json:"matches"`
}

// MatchFingerprint excludes only rule action/enabled and settings irrelevant to
// successful decisions. Other changes invalidate replay rather than guessing.
func MatchFingerprint(c policy.Config) string {
	type def struct{ ID, When string }
	defs := []def{}
	for _, r := range defaults {
		defs = append(defs, def{r.ID, r.When})
	}
	extra := map[string][]string{}
	for id, r := range c.Rules {
		if len(r.ExtraMatch) > 0 {
			extra[id] = r.ExtraMatch
		}
	}
	v := struct {
		Version         int
		Profile         string
		Sources         policy.Sources
		Egress, Secrets any
		Protected       []string
		Extra           map[string][]string
		LogPath         string
		Retention       int
		Definitions     []def
	}{matchSchemaVersion, c.Profile, c.Sources, c.Egress, c.Secrets, c.ProtectedWrites, extra, c.Log.Path, c.State.RetentionDays, defs}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Reevaluate applies current rule actions to all recorded matches, preserving
// production order and highest-action precedence. It never reruns predicates.
func Reevaluate(s Snapshot, c policy.Config, tainted bool) (Decision, error) {
	if s.Version != matchSchemaVersion {
		return Decision{}, errors.New("unsupported replay snapshot version")
	}
	if len(s.Fingerprint) != 64 {
		return Decision{}, errors.New("invalid snapshot fingerprint")
	}
	if _, e := hex.DecodeString(s.Fingerprint); e != nil {
		return Decision{}, errors.New("invalid snapshot fingerprint")
	}
	if s.Fingerprint != MatchFingerprint(c) {
		return Decision{}, errors.New("matching/source policy differs; original inputs and provenance are omitted")
	}
	if s.Matches == nil || len(s.Matches) > len(defaults) {
		return Decision{}, errors.New("missing or oversized rule-match vector")
	}
	seen := map[string]bool{}
	known := map[string]Rule{}
	for _, r := range defaults {
		known[r.ID] = r
	}
	for _, id := range s.Matches {
		r, ok := known[id]
		if !ok || seen[id] {
			return Decision{}, errors.New("invalid or duplicate rule in snapshot")
		}
		if r.When == "tainted" && !tainted {
			return Decision{}, errors.New("snapshot contradicts recorded clean state")
		}
		seen[id] = true
	}
	chosen := Decision{Action: Allow, RuleID: "default.allow", Reason: "No recorded match is enabled with a restrictive action."}
	rank := map[Action]int{Allow: 0, Ask: 1, Deny: 2}
	matched := false
	for _, r := range defaults {
		if !seen[r.ID] {
			continue
		}
		if o, ok := c.Rules[r.ID]; ok {
			if !o.Enabled {
				continue
			}
			r.Action = Action(o.Action)
		}
		if _, ok := rank[r.Action]; !ok {
			return Decision{}, errors.New("invalid candidate rule action")
		}
		if !matched || rank[r.Action] > rank[chosen.Action] {
			chosen = Decision{Action: r.Action, RuleID: r.ID, Reason: "Re-ranked recorded predicate matches under candidate actions."}
			matched = true
		}
	}
	return chosen, nil
}
