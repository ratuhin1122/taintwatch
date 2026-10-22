package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AppendAudit performs one O_APPEND Write under the shared process lock.
// Rotation renames whole files under the same lock.
func (s *Store) AppendAudit(record []byte) error {
	record = bytes.TrimSpace(record)
	if len(record) == 0 || len(record) > 64<<10 || record[0] != '{' || !json.Valid(record) || bytes.ContainsAny(record, "\r\n") {
		return errors.New("audit record must be one compact JSON object of at most 64 KiB")
	}
	line := append(append([]byte(nil), record...), '\n')
	return s.withLock(func() error {
		p := s.auditFile
		f, e := openRegular(p, os.O_CREATE|os.O_RDWR|os.O_APPEND)
		if e != nil {
			return e
		}
		info, e := f.Stat()
		if e != nil {
			f.Close()
			return e
		}
		originalSize := info.Size()
		if originalSize > 0 {
			var tail [1]byte
			if _, e = f.ReadAt(tail[:], originalSize-1); e != nil || tail[0] != '\n' {
				f.Close()
				return errors.New("audit log has an incomplete trailing record")
			}
		}
		if originalSize > 0 && originalSize+int64(len(line)) > s.auditMaxBytes {
			if e = f.Close(); e != nil {
				return e
			}
			if e = s.rotateAudit(); e != nil {
				return e
			}
			f, e = openRegular(p, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND)
			if e != nil {
				return e
			}
			originalSize = 0
		}
		n, writeErr := f.Write(line)
		if writeErr == nil && n != len(line) {
			writeErr = io.ErrShortWrite
		}
		if writeErr != nil {
			_ = f.Truncate(originalSize)
		} else {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		if originalSize == 0 {
			dir, e := os.Open(filepath.Dir(s.auditFile))
			if e != nil {
				return e
			}
			syncErr := dir.Sync()
			closeErr := dir.Close()
			if syncErr != nil {
				return syncErr
			}
			return closeErr
		}
		return nil
	})
}
func (s *Store) auditPath(n int) string {
	p := s.auditFile
	if n > 0 {
		p += fmt.Sprintf(".%d", n)
	}
	return p
}
func (s *Store) rotateAudit() error {
	for n := 0; n <= s.auditKeep; n++ {
		f, e := openRegular(s.auditPath(n), os.O_RDONLY)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
	}
	if e := os.Remove(s.auditPath(s.auditKeep)); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	for n := s.auditKeep - 1; n >= 0; n-- {
		if e := os.Rename(s.auditPath(n), s.auditPath(n+1)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	return nil
}

// ScanAudit opens a bounded-prefix snapshot under the lock, then reads outside
// it so inspecting history does not hold up hooks. Open handles survive rotation.
func (s *Store) ScanAudit(visit func([]byte) error) error {
	type snapshot struct {
		file *os.File
		size int64
	}
	var files []snapshot
	defer func() {
		for _, v := range files {
			_ = v.file.Close()
		}
	}()
	err := s.withLock(func() error {
		for n := s.auditKeep; n >= 0; n-- {
			f, e := openRegular(s.auditPath(n), os.O_RDONLY)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return e
			}
			info, e := f.Stat()
			if e != nil {
				f.Close()
				return e
			}
			files = append(files, snapshot{f, info.Size()})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, v := range files {
		reader := bufio.NewReaderSize(io.NewSectionReader(v.file, 0, v.size), (64<<10)+2)
		for {
			line, readErr := reader.ReadSlice('\n')
			if readErr == io.EOF && len(line) == 0 {
				break
			}
			if readErr != nil {
				return fmt.Errorf("invalid or incomplete audit line: %w", readErr)
			}
			if len(line) > (64<<10)+1 || !json.Valid(bytes.TrimSpace(line)) {
				return errors.New("invalid audit record")
			}
			if e := visit(bytes.TrimSpace(line)); e != nil {
				return e
			}
		}
	}
	return nil
}
