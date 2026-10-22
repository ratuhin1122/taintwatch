package eval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/hookio"
	"github.com/ratuhin1122/taintwatch/internal/hooks"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

type Case struct {
	Class    string
	Scenario Scenario
}
type Observation struct {
	Scenario  string       `json:"scenario"`
	Category  string       `json:"category"`
	Step      string       `json:"step"`
	Decision  string       `json:"decision"`
	Rule      string       `json:"rule"`
	Reason    string       `json:"reason"`
	KnownMiss bool         `json:"known_miss"`
	Expected  *Expectation `json:"expected,omitempty"`
}
type Failure struct {
	Observation
	ExpectedFailure bool `json:"expected_failure"`
}
type Rate struct {
	Defined  bool    `json:"defined"`
	Total    int     `json:"total"`
	Caught   int     `json:"caught"`
	Fraction float64 `json:"fraction"`
}
type BenignMetrics struct {
	Sessions        int     `json:"sessions"`
	ToolCalls       int     `json:"tool_calls"`
	Asks            int     `json:"asks"`
	Denies          int     `json:"denies"`
	AsksPerSession  float64 `json:"asks_per_session"`
	AsksPer100Calls float64 `json:"asks_per_100_tool_calls"`
}
type RuleHits struct {
	Rule   string `json:"rule"`
	Hits   int    `json:"hits"`
	Asks   int    `json:"asks"`
	Denies int    `json:"denies"`
}
type Category struct {
	Name        string        `json:"name"`
	Attacks     Rate          `json:"attacks"`
	KnownMisses Rate          `json:"known_misses"`
	Benign      BenignMetrics `json:"benign"`
}
type ScenarioResult struct {
	ID                  string        `json:"id"`
	Class               string        `json:"class"`
	Category            string        `json:"category"`
	KnownMiss           bool          `json:"known_miss"`
	KnownMissReason     string        `json:"known_miss_reason,omitempty"`
	HarmfulSteps        int           `json:"harmful_steps"`
	GuardedHarmfulSteps int           `json:"guarded_harmful_steps"`
	Caught              bool          `json:"caught"`
	Actions             []Observation `json:"actions"`
}
type EncodedMetrics struct {
	Responses    int     `json:"benign_post_responses"`
	Scanned      int     `json:"benign_scanned_responses"`
	Flagged      int     `json:"benign_flagged_responses"`
	Limited      int     `json:"benign_limited_scans"`
	DecodedBlobs int     `json:"benign_decoded_blobs"`
	TextBlobs    int     `json:"benign_decoded_text_blobs"`
	Defined      bool    `json:"false_positive_rate_defined"`
	Fraction     float64 `json:"response_false_positive_fraction"`
}
type Report struct {
	SchemaVersion    int              `json:"schema_version"`
	CorpusSHA256     string           `json:"corpus_sha256"`
	PolicySHA256     string           `json:"policy_sha256"`
	Attacks          Rate             `json:"attacks"`
	KnownMisses      Rate             `json:"known_misses"`
	Benign           BenignMetrics    `json:"benign"`
	Rules            []RuleHits       `json:"rules"`
	Categories       []Category       `json:"categories"`
	Scenarios        []ScenarioResult `json:"scenarios"`
	Misses           []Observation    `json:"misses"`
	BenignAsks       []Observation    `json:"benign_asks"`
	BenignDenies     []Observation    `json:"benign_denies"`
	Failures         []Failure        `json:"expectation_failures"`
	GateFailures     int              `json:"gate_failures"`
	ExpectedFailures int              `json:"expected_failures"`
	Encoded          EncodedMetrics   `json:"encoded_telemetry"`
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Run invokes the exact pre/post processor used by CLI hooks. It never executes
// a proposed tool, changes global environment, or discovers operator policy.
func Run(ctx context.Context, root string) (Report, error) {
	cases, _, err := load(root)
	if err != nil {
		return Report{}, err
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return Report{}, state.ErrUnsupportedPlatform
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Scenario.ID < cases[j].Scenario.ID })
	cfg := policy.Defaults()
	// Canonical platform-dependent defaults represent a virtual Unix user and
	// temp tree; host HOME/TMPDIR must not alter classification or policy digest.
	cfg.Sources.Read.TempPaths = []string{"/tmp", "/var/tmp"}
	cfg.Sources.Read.DownloadedPaths = []string{"/home/eval/Downloads"}
	r := Report{SchemaVersion: 1, CorpusSHA256: digest(cases), PolicySHA256: digest(cfg)}
	base, err := os.MkdirTemp("", "taintwatch-eval-")
	if err != nil {
		return r, err
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return r, err
	}
	// Canonicalize the private temp root (macOS /var may be a symlink).
	if resolved, e := filepath.EvalSymlinks(base); e == nil {
		base = resolved
	}
	// Remove only this explicitly owned, absolute temporary directory.
	defer func() {
		if filepath.IsAbs(base) && strings.HasPrefix(filepath.Base(base), "taintwatch-eval-") {
			_ = os.RemoveAll(base)
		}
	}()
	fixed := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range cases {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		sandbox := filepath.Join(base, c.Scenario.ID)
		project := filepath.Join(sandbox, "fs", "workspace", "project")
		home := filepath.Join(sandbox, "fs", "home", "eval")
		storeHome := filepath.Join(sandbox, "state")
		for _, dir := range []string{project, home} {
			if err = os.MkdirAll(dir, 0700); err != nil {
				return r, err
			}
		}
		replace := strings.NewReplacer("/workspace/project", filepath.ToSlash(project), "/home/eval", filepath.ToSlash(home), "/var/tmp", filepath.ToSlash(filepath.Join(sandbox, "fs", "var", "tmp")), "/tmp", filepath.ToSlash(filepath.Join(sandbox, "fs", "tmp")), "~/", filepath.ToSlash(home)+"/")
		normalize := strings.NewReplacer(filepath.ToSlash(project), "/workspace/project", filepath.ToSlash(home), "/home/eval", filepath.ToSlash(storeHome), "<state>", filepath.ToSlash(sandbox), "<sandbox>")
		local := cfg
		local.Sources = cfg.Sources
		local.Sources.Read.TempPaths = []string{replace.Replace("/tmp"), replace.Replace("/var/tmp")}
		local.Sources.Read.DownloadedPaths = []string{replace.Replace("/home/eval/Downloads")}
		store, err := state.New(state.Options{Home: storeHome, Now: func() time.Time { return fixed }, AuditMaxBytes: 10 << 20, AuditKeep: 3, Retention: 7 * 24 * time.Hour})
		if err != nil {
			return r, err
		}
		loaded := func() (policy.Effective, error) { return policy.Effective{Config: local, Files: []string{}}, nil }
		rt := hooks.Runtime{Bootstrap: loaded, LoadPolicy: func(string, string, string) (policy.Effective, error) { return loaded() }, Store: func(policy.Config) (*state.Store, error) { return store, nil }, StateHome: func() (string, error) { return storeHome, nil }}
		result := ScenarioResult{ID: c.Scenario.ID, Class: c.Class, Category: c.Scenario.Category, KnownMiss: c.Scenario.KnownMiss, KnownMissReason: c.Scenario.KnownMissReason, Actions: []Observation{}}
		for _, step := range c.Scenario.Steps {
			payload, err := hookio.RemapReplay(step.Payload, replace)
			if err != nil {
				return r, fmt.Errorf("%s/%s: remap payload: %w", result.ID, step.ID, err)
			}
			var outcome hooks.Outcome
			if step.Event == "PreToolUse" {
				outcome = hooks.Pre(ctx, bytes.NewReader(payload), "", nil, rt)
			} else {
				outcome = hooks.Post(ctx, bytes.NewReader(payload), "", "", nil, nil, rt)
			}
			if outcome.Failure != "" {
				return r, fmt.Errorf("%s/%s: hook infrastructure failure at %s", result.ID, step.ID, outcome.Failure)
			}
			if step.Event != "PreToolUse" {
				if c.Class == "benign" {
					h, e := audit.Query(store, result.ID, 1)
					if e != nil || len(h.Records) != 1 || h.Records[0].Hook != "PostToolUse" {
						return r, fmt.Errorf("%s/%s: missing post-hook telemetry audit", result.ID, step.ID)
					}
					r.Encoded.Responses++
					if e := h.Records[0].Encoded; e != nil {
						r.Encoded.Scanned++
						r.Encoded.DecodedBlobs += e.DecodedBlobs
						r.Encoded.TextBlobs += e.TextBlobs
						if len(e.Findings) > 0 {
							r.Encoded.Flagged++
						}
						if e.Truncated || e.LimitReached {
							r.Encoded.Limited++
						}
					}
				}
				continue
			}
			h, err := audit.Query(store, result.ID, 1)
			if err != nil {
				return r, fmt.Errorf("%s/%s: audit read failed", result.ID, step.ID)
			}
			if len(h.Records) != 1 || h.Records[0].Hook != "PreToolUse" {
				return r, fmt.Errorf("%s/%s: missing pre-hook audit", result.ID, step.ID)
			}
			a := h.Records[0]
			if a.Decision != outcome.Result.Permission() {
				return r, fmt.Errorf("%s/%s: audit/output disagreement", result.ID, step.ID)
			}
			result.Actions = append(result.Actions, Observation{Scenario: result.ID, Category: result.Category, Step: step.ID, Decision: a.Decision, Rule: a.Rule, Reason: normalize.Replace(a.Reason), KnownMiss: result.KnownMiss, Expected: step.Expect})
		}
		r.Scenarios = append(r.Scenarios, result)
	}
	aggregate(&r)
	r.Encoded.Defined = r.Encoded.Scanned > 0
	r.Encoded.Fraction = fraction(r.Encoded.Flagged, r.Encoded.Scanned)
	return r, nil
}

func fraction(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
func finishRate(r *Rate) { r.Defined = r.Total > 0; r.Fraction = fraction(r.Caught, r.Total) }
func finishBenign(b *BenignMetrics) {
	b.AsksPerSession = fraction(b.Asks, b.Sessions)
	b.AsksPer100Calls = 100 * fraction(b.Asks, b.ToolCalls)
}
func aggregate(r *Report) {
	r.Rules = []RuleHits{}
	r.Categories = []Category{}
	r.Misses = []Observation{}
	r.BenignAsks = []Observation{}
	r.BenignDenies = []Observation{}
	r.Failures = []Failure{}
	rules := map[string]*RuleHits{}
	categories := map[string]*Category{}
	for i := range r.Scenarios {
		s := &r.Scenarios[i]
		cat := categories[s.Category]
		if cat == nil {
			cat = &Category{Name: s.Category}
			categories[s.Category] = cat
		}
		for _, a := range s.Actions {
			guarded := a.Decision == "ask" || a.Decision == "deny"
			if a.Rule != "default.allow" {
				h := rules[a.Rule]
				if h == nil {
					h = &RuleHits{Rule: a.Rule}
					rules[a.Rule] = h
				}
				h.Hits++
				if a.Decision == "ask" {
					h.Asks++
				}
				if a.Decision == "deny" {
					h.Denies++
				}
			}
			if s.Class == "benign" {
				for _, b := range []*BenignMetrics{&r.Benign, &cat.Benign} {
					b.ToolCalls++
					if a.Decision == "ask" {
						b.Asks++
					}
					if a.Decision == "deny" {
						b.Denies++
					}
				}
				if a.Decision == "ask" {
					r.BenignAsks = append(r.BenignAsks, a)
				}
				if a.Decision == "deny" {
					r.BenignDenies = append(r.BenignDenies, a)
				}
			}
			e := a.Expected
			if e == nil {
				continue
			}
			harmful := e.Decision == "ask" || e.Decision == "deny"
			if s.Class == "attacks" && harmful {
				s.HarmfulSteps++
				if guarded {
					s.GuardedHarmfulSteps++
				} else {
					r.Misses = append(r.Misses, a)
				}
			}
			if a.Decision != e.Decision || e.Rule != "" && a.Rule != e.Rule {
				xfail := s.Class == "attacks" && s.KnownMiss && harmful && a.Decision == "allow"
				r.Failures = append(r.Failures, Failure{Observation: a, ExpectedFailure: xfail})
				if xfail {
					r.ExpectedFailures++
				} else {
					r.GateFailures++
				}
			}
		}
		if s.Class == "benign" {
			r.Benign.Sessions++
			cat.Benign.Sessions++
		} else {
			s.Caught = s.HarmfulSteps > 0 && s.HarmfulSteps == s.GuardedHarmfulSteps
			a, b := &r.Attacks, &cat.Attacks
			if s.KnownMiss {
				a, b = &r.KnownMisses, &cat.KnownMisses
			}
			a.Total++
			b.Total++
			if s.Caught {
				a.Caught++
				b.Caught++
			}
		}
	}
	finishRate(&r.Attacks)
	finishRate(&r.KnownMisses)
	finishBenign(&r.Benign)
	for _, h := range rules {
		r.Rules = append(r.Rules, *h)
	}
	sort.Slice(r.Rules, func(i, j int) bool { return r.Rules[i].Rule < r.Rules[j].Rule })
	for _, c := range categories {
		finishRate(&c.Attacks)
		finishRate(&c.KnownMisses)
		finishBenign(&c.Benign)
		r.Categories = append(r.Categories, *c)
	}
	sort.Slice(r.Categories, func(i, j int) bool { return r.Categories[i].Name < r.Categories[j].Name })
}
