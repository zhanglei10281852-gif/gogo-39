package filestore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
)

// LineError reports the one-based JSONL line that failed validation or decode.
type LineError struct {
	Line int
	Err  error
}

func (e *LineError) Error() string {
	return fmt.Sprintf("JSONL line %d: %v", e.Line, e.Err)
}

func (e *LineError) Unwrap() error { return e.Err }

// AppendJSONL appends one compact JSON value followed by a newline and syncs
// it before returning. Calls through Stores using the same root share a lock.
func (s *Store) AppendJSONL(name string, value any) error {
	if err := s.checkReady(); err != nil {
		return err
	}
	path, err := s.resolve(name)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("append JSONL %q: encode: %w", name, err)
	}
	if len(encoded) > s.maxJSONLLineBytes {
		return fmt.Errorf("append JSONL %q: line size %d exceeds limit %d", name, len(encoded), s.maxJSONLLineBytes)
	}
	encoded = append(encoded, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	parent, err := s.secureParent(path)
	if err != nil {
		return fmt.Errorf("append JSONL %q: %w", name, err)
	}
	if err := s.verifyPath(path, true); err != nil {
		return fmt.Errorf("append JSONL %q: %w", name, err)
	}
	if err := rejectNonRegularDestination(path); err != nil {
		return fmt.Errorf("append JSONL %q: %w", name, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("append JSONL %q: open: %w", name, err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("append JSONL %q: secure file permissions: %w", name, err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("append JSONL %q: stat open file: %w", name, err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("append JSONL %q: recheck file: %w", name, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return fmt.Errorf("append JSONL %q: %w or file changed while opening", name, ErrSymlink)
	}
	if !openedInfo.Mode().IsRegular() {
		return fmt.Errorf("append JSONL %q: destination is not a regular file", name)
	}
	if openedInfo.Size() > s.maxJSONLBytes-int64(len(encoded)) {
		return fmt.Errorf("append JSONL %q: resulting file exceeds limit %d", name, s.maxJSONLBytes)
	}
	if err := writeAll(file, encoded); err != nil {
		return fmt.Errorf("append JSONL %q: write: %w", name, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("append JSONL %q: sync: %w", name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("append JSONL %q: close: %w", name, err)
	}
	closed = true
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("append JSONL %q: persist directory entry: %w", name, err)
	}
	return nil
}

// ReadJSONL strictly decodes each non-optional line into destination, which
// must be a non-nil pointer to a slice. Empty lines, unknown struct fields,
// malformed values, oversized lines, and trailing values are errors. The
// destination is replaced only after every line succeeds.
func (s *Store) ReadJSONL(name string, destination any) error {
	slice, elementType, err := jsonlDestination(destination)
	if err != nil {
		return err
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
		return fmt.Errorf("read JSONL %q: %w", name, err)
	}
	defer file.Close()
	if info.Size() > s.maxJSONLBytes {
		return fmt.Errorf("read JSONL %q: file size %d exceeds limit %d", name, info.Size(), s.maxJSONLBytes)
	}

	result := reflect.MakeSlice(slice.Type(), 0, initialJSONLCapacity(info.Size()))
	limited := &io.LimitedReader{R: file, N: s.maxJSONLBytes + 1}
	scanner := bufio.NewScanner(limited)
	initialBuffer := s.maxJSONLLineBytes
	if initialBuffer > 64<<10 {
		initialBuffer = 64 << 10
	}
	// Scanner needs headroom for its split function and newline. The explicit
	// length check remains the authoritative configured line limit.
	scanner.Buffer(make([]byte, initialBuffer), s.maxJSONLLineBytes+64)
	line := 0
	for scanner.Scan() {
		line++
		data := scanner.Bytes()
		if len(data) == 0 {
			return &LineError{Line: line, Err: fmt.Errorf("empty line is not valid JSON")}
		}
		if len(data) > s.maxJSONLLineBytes {
			return &LineError{Line: line, Err: fmt.Errorf("line size %d exceeds limit %d", len(data), s.maxJSONLLineBytes)}
		}
		decoded, decodeTarget := newJSONLElement(elementType)
		if err := decodeStrictJSONBytes(data, decodeTarget.Interface()); err != nil {
			return &LineError{Line: line, Err: err}
		}
		result = reflect.Append(result, decoded)
	}
	if err := scanner.Err(); err != nil {
		return &LineError{Line: line + 1, Err: fmt.Errorf("scan failed (line may exceed %d bytes): %w", s.maxJSONLLineBytes, err)}
	}
	if limited.N == 0 {
		return fmt.Errorf("read JSONL %q: content exceeds limit %d", name, s.maxJSONLBytes)
	}
	slice.Set(result)
	return nil
}

func jsonlDestination(destination any) (reflect.Value, reflect.Type, error) {
	if destination == nil {
		return reflect.Value{}, nil, fmt.Errorf("JSONL destination is nil")
	}
	pointer := reflect.ValueOf(destination)
	if pointer.Kind() != reflect.Pointer || pointer.IsNil() {
		return reflect.Value{}, nil, fmt.Errorf("JSONL destination must be a non-nil pointer to a slice")
	}
	slice := pointer.Elem()
	if slice.Kind() != reflect.Slice {
		return reflect.Value{}, nil, fmt.Errorf("JSONL destination must point to a slice")
	}
	return slice, slice.Type().Elem(), nil
}

func newJSONLElement(elementType reflect.Type) (reflect.Value, reflect.Value) {
	if elementType.Kind() == reflect.Pointer {
		pointer := reflect.New(elementType.Elem())
		return pointer, pointer
	}
	pointer := reflect.New(elementType)
	return pointer.Elem(), pointer
}

func decodeStrictJSONBytes(data []byte, destination any) error {
	// A Scanner token remains valid only until the next Scan, so decode it now.
	return decodeStrictJSON(bytes.NewReader(data), destination)
}

func initialJSONLCapacity(size int64) int {
	if size <= 0 {
		return 0
	}
	estimate := size / 128
	if estimate < 1 {
		return 1
	}
	if estimate > 4096 {
		return 4096
	}
	return int(estimate)
}
