package replay

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/rules"
)

const maxLogBytes = 64 << 20
const maxRecords = 100000

type Change struct {
	Line                       int
	Session                    string
	Time                       time.Time
	Old, New, OldRule, NewRule string
}
type Unknown struct {
	Line                       int
	Session, Rule, Old, Reason string
}
type Group struct {
	Rule    string
	Changes []Change
}
type Report struct {
	Records, Ignored, Replayed, Unchanged, DecisionChanges, RuleChanges int
	Groups                                                              []Group
	Unreplayable                                                        []Unknown
}

// Run reads only the selected log and candidate YAML. It creates no store,
// applies no policy, reads no original files, and never executes hook/tool code.
func Run(log, policyFile string) (Report, error) {
	p, err := policy.LoadStandalone(policyFile)
	if err != nil {
		return Report{}, err
	}
	info, err := os.Lstat(log)
	if err != nil {
		return Report{}, err
	}
	if !info.Mode().IsRegular() {
		return Report{}, fmt.Errorf("audit log must be a regular non-symlink file")
	}
	if info.Size() > maxLogBytes {
		return Report{}, fmt.Errorf("audit log exceeds 64 MiB")
	}
	f, err := os.Open(log)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return Report{}, fmt.Errorf("audit log changed while opening")
	}
	// Capture the open file's current prefix; later appends/rotations do not
	// extend the analysis or require modifying/acquiring the store's lock.
	r, err := Compare(io.NewSectionReader(f, 0, opened.Size()), p.Config)
	if err == nil {
		if final, e := f.Stat(); e != nil || final.Size() < opened.Size() {
			return Report{}, fmt.Errorf("audit snapshot was truncated while reading")
		}
	}
	return r, err
}

type counted struct {
	r    io.Reader
	n    int
	last byte
}

func (c *counted) Read(b []byte) (int, error) {
	n, e := c.r.Read(b)
	c.n += n
	if n > 0 {
		c.last = b[n-1]
	}
	return n, e
}

// Compare consumes at most 64 MiB with 64 KiB JSONL records. Unknown historical
// facts remain unknown; text reasons/evidence are never parsed as rule inputs.
func Compare(reader io.Reader, c policy.Config) (Report, error) {
	r := Report{Groups: []Group{}, Unreplayable: []Unknown{}}
	input := &counted{r: io.LimitReader(reader, maxLogBytes+1)}
	s := bufio.NewScanner(input)
	s.Buffer(make([]byte, 4096), (64<<10)+2)
	groups := map[string][]Change{}
	line := 0
	for s.Scan() {
		line++
		if input.n > maxLogBytes {
			return r, fmt.Errorf("audit log exceeds 64 MiB")
		}
		b := bytes.TrimSpace(s.Bytes())
		if len(b) == 0 {
			continue
		}
		r.Records++
		if r.Records > maxRecords {
			return r, fmt.Errorf("audit log exceeds 100000 records")
		}
		a, err := audit.DecodeRecord(b)
		if err != nil {
			return r, fmt.Errorf("line %d: invalid audit JSON object", line)
		}
		if a.Hook != "PreToolUse" {
			r.Ignored++
			continue
		}
		unknown := func(reason string) {
			r.Unreplayable = append(r.Unreplayable, Unknown{Line: line, Session: a.Session, Rule: a.Rule, Old: a.Decision, Reason: reason})
		}
		if a.Replay == nil {
			unknown("legacy record has no complete rule-match snapshot; raw inputs and other matches were omitted")
			continue
		}
		if !a.StateKnown {
			unknown("historical state is unknown or processing failed")
			continue
		}
		if a.Decision != "allow" && a.Decision != "ask" && a.Decision != "deny" {
			unknown("historical decision is not a permission action")
			continue
		}
		if a.Rule == "default.allow" && a.Decision != "allow" {
			unknown("historical default rule contradicts the recorded decision")
			continue
		}
		validRule := a.Rule == "default.allow"
		selectedMatched := a.Rule == "default.allow"
		for _, def := range rules.Defaults() {
			if def.ID == a.Rule {
				validRule = true
			}
		}
		for _, id := range a.Replay.Matches {
			if id == a.Rule {
				selectedMatched = true
			}
		}
		if !validRule || !selectedMatched {
			unknown("historical selected rule is missing or inconsistent with the snapshot")
			continue
		}
		d, err := rules.Reevaluate(*a.Replay, c, a.Tainted)
		if err != nil {
			unknown(err.Error())
			continue
		}
		r.Replayed++
		next := string(d.Action)
		if next == a.Decision && d.RuleID == a.Rule {
			r.Unchanged++
			continue
		}
		if next != a.Decision {
			r.DecisionChanges++
		} else {
			r.RuleChanges++
		}
		group := d.RuleID
		if next == "allow" {
			group = a.Rule
		}
		groups[group] = append(groups[group], Change{Line: line, Session: a.Session, Time: a.TS, Old: a.Decision, New: next, OldRule: a.Rule, NewRule: d.RuleID})
	}
	if input.n > maxLogBytes {
		return r, fmt.Errorf("audit log exceeds 64 MiB")
	}
	if err := s.Err(); err != nil {
		return r, fmt.Errorf("line %d: unreadable or oversized audit record", line+1)
	}
	if input.n > 0 && input.last != '\n' {
		return r, fmt.Errorf("audit log has an incomplete trailing record (missing newline)")
	}
	for rule, changes := range groups {
		r.Groups = append(r.Groups, Group{Rule: rule, Changes: changes})
	}
	sort.Slice(r.Groups, func(i, j int) bool { return r.Groups[i].Rule < r.Groups[j].Rule })
	return r, nil
}

// Render groups confirmed action/rule changes and explicitly separates missing
// information. Quoting and redaction prevent terminal-control/secret leakage.
func Render(w io.Writer, r Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Policy replay — frozen recorded matches, not a tool/session rerun\nRecords: %d; ignored non-pre events: %d; replayed: %d; unchanged: %d\nDecision changes: %d; rule-only changes: %d; unreplayable: %d\n", r.Records, r.Ignored, r.Replayed, r.Unchanged, r.DecisionChanges, r.RuleChanges, len(r.Unreplayable))
	for _, g := range r.Groups {
		fmt.Fprintf(&b, "\nRule %s\n", display(g.Rule))
		for _, c := range g.Changes {
			stamp := "unknown time"
			if !c.Time.IsZero() {
				stamp = c.Time.UTC().Format(time.RFC3339Nano)
			}
			fmt.Fprintf(&b, "  line %d session %s at %s: %s -> %s (%s -> %s)\n", c.Line, display(c.Session), stamp, display(c.Old), display(c.New), display(c.OldRule), display(c.NewRule))
		}
	}
	if len(r.Groups) == 0 {
		fmt.Fprintln(&b, "\nNo confirmed changes among replayable records.")
	}
	if len(r.Unreplayable) > 0 {
		fmt.Fprintln(&b, "\nUnreplayable (no decision inferred)")
		for _, u := range r.Unreplayable {
			fmt.Fprintf(&b, "  line %d session %s [%s], was %s: %s\n", u.Line, display(u.Session), display(u.Rule), display(u.Old), display(u.Reason))
		}
	}
	fmt.Fprintln(&b, "\nOnly action/enabled changes with identical matching/source settings are replayable.\nHistorical taint and match facts are held fixed; omitted inputs are never reconstructed.\nNo policy, state, log, or original tool files were modified.")
	_, err := io.WriteString(w, b.String())
	return err
}
