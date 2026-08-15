// Package filestore provides a root-confined, durable JSON file store.
package filestore

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	defaultMaxJSONBytes      int64 = 16 << 20
	defaultMaxJSONLBytes     int64 = 64 << 20
	defaultMaxJSONLLineBytes       = 1 << 20
	maxInt64Value            int64 = int64(^uint64(0) >> 1)
)

// Store confines all operations to one canonical root directory.
type Store struct {
	root              string
	maxJSONBytes      int64
	maxJSONLBytes     int64
	maxJSONLLineBytes int
	mu                *sync.RWMutex
}

// Option configures resource limits for a Store.
type Option func(*Store) error

var rootLocks = struct {
	sync.Mutex
	m map[string]*sync.RWMutex
}{m: make(map[string]*sync.RWMutex)}

// WithMaxJSONBytes sets the largest JSON document accepted by ReadJSON.
func WithMaxJSONBytes(n int64) Option {
	return func(s *Store) error {
		if n <= 0 || n == maxInt64Value {
			return fmt.Errorf("maximum JSON size must be positive and leave limit-reader headroom")
		}
		s.maxJSONBytes = n
		return nil
	}
}

// WithMaxJSONLBytes sets the largest JSONL file accepted by ReadJSONL.
func WithMaxJSONLBytes(n int64) Option {
	return func(s *Store) error {
		if n <= 0 || n == maxInt64Value {
			return fmt.Errorf("maximum JSONL size must be positive and leave limit-reader headroom")
		}
		s.maxJSONLBytes = n
		return nil
	}
}

// WithMaxJSONLLineBytes sets the largest individual JSONL line.
func WithMaxJSONLLineBytes(n int) Option {
	return func(s *Store) error {
		maxInt := int(^uint(0) >> 1)
		if n <= 0 || n > maxInt-64 {
			return fmt.Errorf("maximum JSONL line size must be positive and leave scanner headroom")
		}
		s.maxJSONLLineBytes = n
		return nil
	}
}

// New creates or opens a secure store rooted at root. The returned Root is
// absolute and has symbolic links in the root itself resolved.
func New(root string, options ...Option) (*Store, error) {
	if root == "" {
		return nil, fmt.Errorf("filestore root is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("make root absolute: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("create root: %w", err)
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("secure root permissions: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return nil, fmt.Errorf("canonicalize root: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("filestore root is not a directory")
	}

	s := &Store{
		root:              filepath.Clean(canonical),
		maxJSONBytes:      defaultMaxJSONBytes,
		maxJSONLBytes:     defaultMaxJSONLBytes,
		maxJSONLLineBytes: defaultMaxJSONLLineBytes,
	}
	for i, option := range options {
		if option == nil {
			return nil, fmt.Errorf("option %d is nil", i)
		}
		if err := option(s); err != nil {
			return nil, fmt.Errorf("option %d: %w", i, err)
		}
	}
	lockKey := s.root
	if runtime.GOOS == "windows" {
		lockKey = strings.ToLower(lockKey)
	}
	rootLocks.Lock()
	s.mu = rootLocks.m[lockKey]
	if s.mu == nil {
		s.mu = new(sync.RWMutex)
		rootLocks.m[lockKey] = s.mu
	}
	rootLocks.Unlock()
	return s, nil
}

// Root returns the canonical absolute root directory.
func (s *Store) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

func (s *Store) checkReady() error {
	if s == nil || s.mu == nil || s.root == "" {
		return fmt.Errorf("filestore is not initialized")
	}
	return nil
}

// syncDirectory makes a completed rename durable where the platform supports
// directory synchronization. Windows does not expose portable directory fsync
// through os.File, so a failure there is treated as a platform limitation.
func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if runtime.GOOS == "windows" {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close directory after sync: %w", closeErr)
	}
	return nil
}
