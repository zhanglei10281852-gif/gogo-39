package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"agentguard/model"
)

// Options controls locking and durability behavior.
type Options struct {
	LockTimeout time.Duration
	LockPoll    time.Duration
	StaleLock   time.Duration
	FileMode    os.FileMode
	Clock       func() time.Time
}

// Ledger is a concurrency-safe append-only JSONL file.
type Ledger struct {
	path     string
	metaPath string
	lockPath string
	id       string
	opts     Options
	mu       sync.RWMutex
	closed   bool
}

func defaultOptions(opts Options) Options {
	if opts.LockTimeout <= 0 {
		opts.LockTimeout = 10 * time.Second
	}
	if opts.LockPoll <= 0 {
		opts.LockPoll = 25 * time.Millisecond
	}
	if opts.StaleLock <= 0 {
		opts.StaleLock = 2 * time.Minute
	}
	if opts.FileMode == 0 {
		opts.FileMode = 0o600
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return opts
}

// Open opens or creates a ledger at path.
func Open(path string, opts Options) (*Ledger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("audit: ledger path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve ledger path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create ledger directory: %w", err)
	}
	ledger := &Ledger{
		path: absolute, metaPath: absolute + ".meta",
		lockPath: absolute + ".lock", id: digestHex([]byte("ledger\x00" + filepath.Clean(absolute))),
		opts: defaultOptions(opts),
	}
	if err := ledger.initialize(context.Background()); err != nil {
		return nil, err
	}
	return ledger, nil
}

// New is a convenience alias for Open with default options.
func New(path string) (*Ledger, error) { return Open(path, Options{}) }

func (l *Ledger) Path() string { return l.path }
func (l *Ledger) ID() string   { return l.id }

// Close prevents future operations. It does not remove persistent data.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}
func (l *Ledger) initialize(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := l.acquireLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, l.opts.FileMode)
	if err != nil {
		return fmt.Errorf("audit: create ledger: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("audit: close ledger: %w", err)
	}
	report, _, err := scanFile(l.path, nil)
	if err != nil {
		return err
	}
	if !report.Valid {
		// Keep a corrupt ledger openable so Verify can report it and RepairTail
		// can recover a narrowly-defined invalid final record. Mutations still
		// refuse to proceed until the chain is valid.
		return nil
	}
	return l.writeMetadata(report)
}

// Append canonicalizes payload, assigns chain fields, appends one complete
// JSON line, fsyncs it, and atomically refreshes metadata.
func (l *Ledger) Append(ctx context.Context, input EventInput) (model.AuditEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return model.AuditEvent{}, ErrClosed
	}
	if strings.TrimSpace(input.Type) == "" {
		return model.AuditEvent{}, errors.New("audit: event type is required")
	}
	payload, err := rawPayload(input.Payload)
	if err != nil {
		return model.AuditEvent{}, err
	}
	unlock, err := l.acquireLock(ctx)
	if err != nil {
		return model.AuditEvent{}, err
	}
	defer unlock()
	report, _, err := scanFile(l.path, nil)
	if err != nil {
		return model.AuditEvent{}, err
	}
	if !report.Valid {
		return model.AuditEvent{}, reportError(report)
	}
	timestamp := input.Timestamp
	if timestamp.IsZero() {
		timestamp = l.opts.Clock().UTC()
	} else {
		timestamp = timestamp.UTC()
	}
	event := model.AuditEvent{
		Sequence: report.LastSequence + 1, Timestamp: timestamp,
		Type: input.Type, RequestID: input.RequestID, SessionID: input.SessionID,
		ActorID: input.ActorID, PolicyID: input.PolicyID, Payload: payload,
		PreviousHash: report.LastHash,
	}
	event.Hash, err = EventHash(event)
	if err != nil {
		return model.AuditEvent{}, err
	}
	line, err := CanonicalJSON(event)
	if err != nil {
		return model.AuditEvent{}, err
	}
	line = append(line, '\n')
	file, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND, l.opts.FileMode)
	if err != nil {
		return model.AuditEvent{}, fmt.Errorf("audit: open append: %w", err)
	}
	written, writeErr := file.Write(line)
	if writeErr == nil && written != len(line) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return model.AuditEvent{}, fmt.Errorf("audit: append event: %w", writeErr)
	}
	if closeErr != nil {
		return model.AuditEvent{}, fmt.Errorf("audit: close appended event: %w", closeErr)
	}
	report.Events++
	report.LastSequence = event.Sequence
	report.LastHash = event.Hash
	report.ValidBytes += int64(len(line))
	report.FileBytes = report.ValidBytes
	if err := l.writeMetadata(report); err != nil {
		return event, err
	}
	return event, nil
}

// Verify performs a full byte-to-byte chain validation under the process lock.
func (l *Ledger) Verify(ctx context.Context) (VerifyReport, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return VerifyReport{}, ErrClosed
	}
	unlock, err := l.acquireLock(ctx)
	if err != nil {
		return VerifyReport{}, err
	}
	defer unlock()
	report, _, err := scanFile(l.path, nil)
	if err != nil {
		return report, err
	}
	if !report.Valid {
		return report, reportError(report)
	}
	return report, nil
}

func reportError(report VerifyReport) error {
	return &CorruptionError{Line: report.InvalidLine, Offset: report.ValidBytes, Reason: report.Reason}
}

type scanVisitor func(model.AuditEvent, int64, int64) error

func scanFile(path string, visit scanVisitor) (VerifyReport, []model.AuditEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return VerifyReport{}, nil, fmt.Errorf("audit: open ledger: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return VerifyReport{}, nil, fmt.Errorf("audit: stat ledger: %w", err)
	}
	report := VerifyReport{Valid: true, FileBytes: info.Size()}
	reader := bufio.NewReaderSize(file, 64*1024)
	var events []model.AuditEvent
	var offset int64
	previousHash := genesisHash
	expectedSequence := uint64(1)
	for lineNumber := uint64(1); ; lineNumber++ {
		line, readErr := reader.ReadBytes('\n')
		if len(line) == 0 && readErr == io.EOF {
			break
		}
		lineStart := offset
		offset += int64(len(line))
		trimmed := bytes.TrimSuffix(line, []byte{'\n'})
		trimmed = bytes.TrimSuffix(trimmed, []byte{'\r'})
		if len(bytes.TrimSpace(trimmed)) == 0 {
			return invalidReport(report, lineNumber, lineStart, "empty JSONL record"), events, nil
		}
		canonicalLine, err := Canonicalize(trimmed)
		if err != nil {
			return invalidReport(report, lineNumber, lineStart, "invalid event JSON: "+err.Error()), events, nil
		}
		var event model.AuditEvent
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&event); err != nil {
			return invalidReport(report, lineNumber, lineStart, "invalid event JSON: "+err.Error()), events, nil
		}
		encodedEvent, err := CanonicalJSON(event)
		if err != nil || !bytes.Equal(canonicalLine, encodedEvent) {
			return invalidReport(report, lineNumber, lineStart, "event is not in canonical schema form"), events, nil
		}
		if event.Sequence != expectedSequence {
			return invalidReport(report, lineNumber, lineStart, fmt.Sprintf("sequence is %d, expected %d", event.Sequence, expectedSequence)), events, nil
		}
		if event.Timestamp.IsZero() {
			return invalidReport(report, lineNumber, lineStart, "timestamp is required"), events, nil
		}
		if strings.TrimSpace(event.Type) == "" {
			return invalidReport(report, lineNumber, lineStart, "type is required"), events, nil
		}
		if event.PreviousHash != previousHash {
			return invalidReport(report, lineNumber, lineStart, "previous_hash mismatch"), events, nil
		}
		computed, err := EventHash(event)
		if err != nil {
			return invalidReport(report, lineNumber, lineStart, err.Error()), events, nil
		}
		if !constantStringEqual(event.Hash, computed) {
			return invalidReport(report, lineNumber, lineStart, "hash mismatch"), events, nil
		}
		if visit != nil {
			if err := visit(event, lineStart, offset); err != nil {
				return report, events, err
			}
		}
		events = append(events, event)
		report.Events++
		report.LastSequence = event.Sequence
		report.LastHash = event.Hash
		report.ValidBytes = offset
		previousHash = event.Hash
		expectedSequence++
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return report, events, fmt.Errorf("audit: read ledger: %w", readErr)
		}
	}
	return report, events, nil
}
func invalidReport(report VerifyReport, line uint64, offset int64, reason string) VerifyReport {
	report.Valid = false
	report.InvalidLine = line
	report.ValidBytes = offset
	report.Reason = reason
	return report
}

func constantStringEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}

type lockOwner struct {
	PID       int       `json:"pid"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

func (l *Ledger) acquireLock(ctx context.Context) (func(), error) {
	deadline := time.Now().Add(l.opts.LockTimeout)
	for {
		owner := lockOwner{PID: os.Getpid(), Token: randomToken(), CreatedAt: l.opts.Clock().UTC()}
		content, _ := json.Marshal(owner)
		file, err := os.OpenFile(l.lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if _, err = file.Write(content); err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				_ = os.Remove(l.lockPath)
				return nil, fmt.Errorf("audit: initialize lock: %w", err)
			}
			// A stale-lock breaker excludes creators while it rechecks and
			// renames. Yield if one appeared during our O_EXCL creation.
			if breakerInfo, breakerErr := os.Stat(l.lockPath + ".break"); breakerErr == nil {
				if time.Since(breakerInfo.ModTime()) > l.opts.StaleLock {
					_ = os.Remove(l.lockPath + ".break")
				} else {
					l.releaseLock(owner.Token)
					continue
				}
			}
			return l.holdLock(owner.Token), nil
		}
		if !errors.Is(err, os.ErrExist) && !isLockContention(err, l.lockPath) {
			return nil, fmt.Errorf("audit: create lock: %w", err)
		}
		l.removeStaleLock()
		if !time.Now().Before(deadline) {
			return nil, ErrLockTimeout
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(l.opts.LockPoll):
		}
	}
}

func (l *Ledger) removeStaleLock() {
	info, err := os.Stat(l.lockPath)
	if err != nil || time.Since(info.ModTime()) <= l.opts.StaleLock {
		return
	}
	breaker := l.lockPath + ".break"
	guard, err := os.OpenFile(breaker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if breakerInfo, statErr := os.Stat(breaker); statErr == nil && time.Since(breakerInfo.ModTime()) > l.opts.StaleLock {
			_ = os.Remove(breaker)
		}
		return
	}
	_ = guard.Close()
	defer os.Remove(breaker)
	// Creators observe the breaker and yield. Re-stat under that guard so an
	// active replacement can never be mistaken for the stale inode observed
	// before acquiring the breaker.
	info, err = os.Stat(l.lockPath)
	if err != nil || time.Since(info.ModTime()) <= l.opts.StaleLock {
		return
	}
	stale := l.lockPath + ".stale-" + randomToken()
	if os.Rename(l.lockPath, stale) == nil {
		_ = os.Remove(stale)
	}
}

func (l *Ledger) holdLock(token string) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	interval := l.opts.StaleLock / 3
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				content, err := os.ReadFile(l.lockPath)
				if err != nil {
					return
				}
				var owner lockOwner
				if json.Unmarshal(content, &owner) != nil || owner.Token != token {
					return
				}
				_ = os.Chtimes(l.lockPath, now, now)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			<-done
			l.releaseLock(token)
		})
	}
}

func (l *Ledger) releaseLock(token string) {
	content, err := os.ReadFile(l.lockPath)
	if err != nil {
		return
	}
	var owner lockOwner
	if json.Unmarshal(content, &owner) == nil && owner.Token == token {
		_ = os.Remove(l.lockPath)
	}
}

func isLockContention(err error, lockPath string) bool {
	if errors.Is(err, os.ErrPermission) {
		// On Windows, opening a lock path with O_EXCL can report a sharing
		// violation as permission denied while another process is replacing or
		// deleting the file. Treat that transient state exactly like ErrExist;
		// the bounded acquisition loop still returns ErrLockTimeout if it lasts.
		return true
	}
	_, statErr := os.Lstat(lockPath)
	return statErr == nil || errors.Is(statErr, os.ErrPermission)
}

func randomToken() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}
func (l *Ledger) writeMetadata(report VerifyReport) error {
	metadata := Metadata{
		Version: formatVersion, LedgerID: l.id, EventCount: report.Events,
		LastSequence: report.LastSequence, LastHash: report.LastHash,
		FileSize: report.ValidBytes, UpdatedAt: l.opts.Clock().UTC(),
	}
	data, err := CanonicalJSON(metadata)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary := l.metaPath + ".tmp-" + randomToken()
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, l.opts.FileMode)
	if err != nil {
		return fmt.Errorf("audit: create metadata temporary file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: write metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: sync metadata: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("audit: close metadata: %w", err)
	}
	if err := replaceFile(temporary, l.metaPath); err != nil {
		return fmt.Errorf("audit: replace metadata: %w", err)
	}
	cleanup = false
	return syncDirectory(filepath.Dir(l.metaPath))
}

func replaceFile(source, destination string) error {
	if err := os.Rename(source, destination); err == nil {
		return nil
	}
	// Windows does not replace an existing destination. Metadata is only a
	// cache, so a remove followed by rename is safe and is rebuilt on open.
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return nil // Some platforms do not permit opening directories for sync.
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return nil // Data and metadata files themselves have already been synced.
	}
	return nil
}

// Metadata reads the atomic cache and checks its identity and format.
func (l *Ledger) Metadata() (Metadata, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return Metadata{}, ErrClosed
	}
	data, err := os.ReadFile(l.metaPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("audit: read metadata: %w", err)
	}
	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return Metadata{}, fmt.Errorf("audit: decode metadata: %w", err)
	}
	if metadata.Version != formatVersion || metadata.LedgerID != l.id {
		return Metadata{}, errors.New("audit: metadata identity or version mismatch")
	}
	return metadata, nil
}
