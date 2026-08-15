package filestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// ReadJSON strictly decodes exactly one JSON value. Unknown struct fields and
// trailing non-whitespace data are rejected.
func (s *Store) ReadJSON(name string, destination any) error {
	if destination == nil {
		return fmt.Errorf("JSON destination is nil")
	}
	if err := s.checkReady(); err != nil {
		return err
	}
	path, err := s.resolve(name)
	if err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	file, info, err := s.openVerifiedRead(path)
	if err != nil {
		return fmt.Errorf("read JSON %q: %w", name, err)
	}
	defer file.Close()
	if info.Size() > s.maxJSONBytes {
		return fmt.Errorf("read JSON %q: file size %d exceeds limit %d", name, info.Size(), s.maxJSONBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, s.maxJSONBytes+1))
	if err != nil {
		return fmt.Errorf("read JSON %q: read: %w", name, err)
	}
	if int64(len(data)) > s.maxJSONBytes {
		return fmt.Errorf("read JSON %q: content exceeds limit %d", name, s.maxJSONBytes)
	}
	if err := decodeStrictJSON(bytes.NewReader(data), destination); err != nil {
		return fmt.Errorf("read JSON %q: %w", name, err)
	}
	return nil
}

func decodeStrictJSON(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode JSON: trailing JSON value")
		}
		return fmt.Errorf("decode JSON trailing data: %w", err)
	}
	return nil
}

// WriteJSON atomically replaces name with one JSON value. Data is written to a
// private temporary file in the destination directory, synchronized, closed,
// renamed, and followed by a directory synchronization where supported.
func (s *Store) WriteJSON(name string, value any) error {
	if err := s.checkReady(); err != nil {
		return err
	}
	path, err := s.resolve(name)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("write JSON %q: encode: %w", name, err)
	}
	if int64(len(encoded))+1 > s.maxJSONBytes {
		return fmt.Errorf("write JSON %q: stored size %d exceeds limit %d", name, len(encoded)+1, s.maxJSONBytes)
	}
	encoded = append(encoded, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	parent, err := s.secureParent(path)
	if err != nil {
		return fmt.Errorf("write JSON %q: %w", name, err)
	}
	if err := s.verifyPath(path, true); err != nil {
		return fmt.Errorf("write JSON %q: %w", name, err)
	}
	temporary, err := os.CreateTemp(parent, ".filestore-*.tmp")
	if err != nil {
		return fmt.Errorf("write JSON %q: create temporary file: %w", name, err)
	}
	temporaryName := temporary.Name()
	installed := false
	defer func() {
		if !installed {
			temporary.Close()
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("write JSON %q: secure temporary file: %w", name, err)
	}
	if err := writeAll(temporary, encoded); err != nil {
		return fmt.Errorf("write JSON %q: write temporary file: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("write JSON %q: sync temporary file: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("write JSON %q: close temporary file: %w", name, err)
	}

	// Recheck after writing so an externally introduced symlink is not used as
	// the rename destination. Portable standard-library APIs cannot eliminate
	// every hostile external TOCTOU race, but each observable link is rejected.
	if err := s.verifyPath(parent, false); err != nil && parent != s.root {
		return fmt.Errorf("write JSON %q: recheck parent: %w", name, err)
	}
	if err := s.verifyPath(path, true); err != nil {
		return fmt.Errorf("write JSON %q: recheck destination: %w", name, err)
	}
	if err := rejectNonRegularDestination(path); err != nil {
		return fmt.Errorf("write JSON %q: %w", name, err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("write JSON %q: atomic rename: %w", name, err)
	}
	installed = true
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("write JSON %q: persist rename: %w", name, err)
	}
	return nil
}

func rejectNonRegularDestination(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect destination: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: destination", ErrSymlink)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("destination is not a regular file")
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

// ValidateJSON checks strict single-value syntax without retaining the value.
func ValidateJSON(data []byte) error {
	var value json.RawMessage
	if err := decodeStrictJSON(bytes.NewReader(data), &value); err != nil {
		return err
	}
	return nil
}
