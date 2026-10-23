package audit

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/state"
)

type Source interface {
	ScanAudit(func([]byte) error) error
}

// History contains recent decisions and ask counts across retained files only.
type History struct {
	Degraded       bool     `json:"degraded,omitempty"`
	DegradedReason string   `json:"degraded_reason,omitempty"`
	Session        string   `json:"session"`
	Records        []Record `json:"records"`
	Asks           int      `json:"asks_retained"`
}

// Query defaults to the session with the latest audit timestamp. Explicit IDs
// are normalized like writes. Scans are locked snapshots individually.
func Query(source Source, session string, last int) (History, error) {
	if last < 1 || last > 1000 {
		return History{}, errors.New("last must be between 1 and 1000")
	}
	if session != "" {
		session = Redact(state.SanitizeSessionID(session))
	} else {
		var latest time.Time
		if err := source.ScanAudit(func(b []byte) error {
			var r Record
			if err := json.Unmarshal(b, &r); err != nil {
				return err
			}
			if !r.TS.Before(latest) {
				latest = r.TS
				session = r.Session
			}
			return nil
		}); err != nil {
			return History{}, err
		}
	}
	h := History{Session: Redact(session), Records: []Record{}}
	if session == "" {
		return h, nil
	}
	err := source.ScanAudit(func(b []byte) error {
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			return err
		}
		if r.Session != session {
			return nil
		}
		if r.Decision == "ask" && r.Hook == "PreToolUse" {
			h.Asks++
		}
		h.Records = append(h.Records, sanitize(r))
		sort.SliceStable(h.Records, func(i, j int) bool { return h.Records[i].TS.Before(h.Records[j].TS) })
		if len(h.Records) > last {
			h.Records = h.Records[1:]
		}
		return nil
	})
	return h, err
}
