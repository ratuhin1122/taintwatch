package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxAuditBytes = 16 << 20

// AppendAudit stores one compact JSON object in home/audit.jsonl. State owns the
// secure filesystem primitive; internal/audit owns record schema and redaction.
// The same persistent lock and atomic replacement protect concurrent processes.
// A full log returns an error rather than silently discarding historical records.
func (s *Store) AppendAudit(record []byte) error {
	record = bytes.TrimSpace(record)
	if len(record) == 0 || len(record) > 64<<10 || record[0] != '{' || !json.Valid(record) || bytes.ContainsAny(record, "\r\n") {
		return errors.New("audit record must be one compact JSON object of at most 64 KiB")
	}
	err := s.withLock(func() error {
		path := filepath.Join(s.home, "audit.jsonl")
		var data []byte
		f, err := openRegular(path, os.O_RDONLY)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("open audit log: %w", err)
		}
		if err == nil {
			data, err = io.ReadAll(io.LimitReader(f, maxAuditBytes+1))
			closeErr := f.Close()
			if err != nil {
				return fmt.Errorf("read audit log: %w", err)
			}
			if closeErr != nil {
				return fmt.Errorf("close audit log: %w", closeErr)
			}
			if len(data) > 0 && data[len(data)-1] != '\n' {
				return errors.New("audit log has an incomplete trailing record")
			}
		}
		if len(data)+len(record)+1 > maxAuditBytes {
			return errors.New("audit log exceeds 16 MiB; rotation is not implemented yet")
		}
		data = append(data, record...)
		data = append(data, '\n')
		return atomicWrite(path, data)
	})
	if err != nil {
		return fmt.Errorf("append audit record: %w", err)
	}
	return nil
}
