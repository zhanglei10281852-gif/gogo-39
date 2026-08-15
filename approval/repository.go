package approval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const repositoryVersion = 1

type diskSnapshot struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

// FileRepository stores the full approval collection in one strict JSON file.
type FileRepository struct {
	mu   sync.Mutex
	path string
	mode os.FileMode
}

// NewFileRepository constructs a repository using owner-only file permissions.
func NewFileRepository(path string) *FileRepository {
	return &FileRepository{path: filepath.Clean(path), mode: 0o600}
}

// OpenFile creates a Service backed by a JSON file.
func OpenFile(path string) (*Service, error) {
	return New(NewFileRepository(path))
}

func (r *FileRepository) Load() ([]Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Record{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read approval repository %s: %w", r.path, err)
	}
	return decodeSnapshot(data)
}
func (r *FileRepository) Save(records []Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ordered, err := validateSnapshot(records)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(diskSnapshot{Version: repositoryVersion, Records: ordered}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode approval repository: %w", err)
	}
	payload = append(payload, '\n')
	return r.atomicWrite(payload)
}

func (r *FileRepository) atomicWrite(payload []byte) (resultErr error) {
	directory := filepath.Dir(r.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create approval repository directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".approval-*.tmp")
	if err != nil {
		return fmt.Errorf("create approval temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			if closeErr := temporary.Close(); resultErr == nil && closeErr != nil {
				resultErr = fmt.Errorf("close approval temporary file: %w", closeErr)
			}
		}
		if resultErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(r.mode); err != nil {
		return fmt.Errorf("set approval temporary file permissions: %w", err)
	}
	writer := bufio.NewWriter(temporary)
	if _, err := writer.Write(payload); err != nil {
		return fmt.Errorf("write approval temporary file: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush approval temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync approval temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close approval temporary file: %w", err)
	}
	closed = true
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return fmt.Errorf("replace approval repository: %w", err)
	}
	if directoryFile, err := os.Open(directory); err == nil {
		_ = directoryFile.Sync()
		_ = directoryFile.Close()
	}
	return nil
}
func decodeSnapshot(data []byte) ([]Record, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("approval repository is empty")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot diskSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode approval repository: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("decode approval repository: trailing JSON value")
		}
		return nil, fmt.Errorf("decode approval repository trailing data: %w", err)
	}
	if snapshot.Version != repositoryVersion {
		return nil, fmt.Errorf("unsupported approval repository version %d", snapshot.Version)
	}
	return validateSnapshot(snapshot.Records)
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return fmt.Errorf("validate approval JSON: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("validate approval JSON: trailing token %v", token)
		}
		return fmt.Errorf("validate approval JSON trailing data: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
func validateSnapshot(records []Record) ([]Record, error) {
	ordered := make([]Record, len(records))
	seen := make(map[string]struct{}, len(records))
	for index, record := range records {
		if err := validateRecord(record); err != nil {
			return nil, fmt.Errorf("approval record %d: %w", index, err)
		}
		if _, exists := seen[record.Request.ID]; exists {
			return nil, fmt.Errorf("duplicate approval id %q", record.Request.ID)
		}
		seen[record.Request.ID] = struct{}{}
		ordered[index] = cloneRecord(record)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Request.ID < ordered[j].Request.ID })
	return ordered, nil
}

// MemoryRepository is a concurrency-safe repository useful for embedded use
// and tests that do not require durability.
type MemoryRepository struct {
	mu      sync.RWMutex
	records []Record
}

func NewMemoryRepository() *MemoryRepository { return &MemoryRepository{} }

func (r *MemoryRepository) Load() ([]Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Record, len(r.records))
	for index, record := range r.records {
		result[index] = cloneRecord(record)
	}
	return result, nil
}

func (r *MemoryRepository) Save(records []Record) error {
	ordered, err := validateSnapshot(records)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = ordered
	return nil
}
