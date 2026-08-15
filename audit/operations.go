package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"agentguard/model"
)

// Query returns copies of matching events after validating the complete chain.
func (l *Ledger) Query(ctx context.Context, query Query) ([]model.AuditEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrClosed
	}
	unlock, err := l.acquireLock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	report, events, err := scanFile(l.path, nil)
	if err != nil {
		return nil, err
	}
	if !report.Valid {
		return nil, reportError(report)
	}
	types := make(map[string]struct{}, len(query.Types))
	for _, eventType := range query.Types {
		types[eventType] = struct{}{}
	}
	matches := make([]model.AuditEvent, 0)
	for _, event := range events {
		if queryMatch(event, query, types) {
			event.Payload = append(json.RawMessage(nil), event.Payload...)
			matches = append(matches, event)
		}
	}
	if query.Reverse {
		for left, right := 0, len(matches)-1; left < right; left, right = left+1, right-1 {
			matches[left], matches[right] = matches[right], matches[left]
		}
	}
	if query.Limit > 0 && len(matches) > query.Limit {
		matches = matches[:query.Limit]
	}
	return matches, nil
}
func queryMatch(event model.AuditEvent, query Query, types map[string]struct{}) bool {
	if query.FromSequence > 0 && event.Sequence < query.FromSequence {
		return false
	}
	if query.ToSequence > 0 && event.Sequence > query.ToSequence {
		return false
	}
	if !query.FromTime.IsZero() && event.Timestamp.Before(query.FromTime) {
		return false
	}
	if !query.ToTime.IsZero() && event.Timestamp.After(query.ToTime) {
		return false
	}
	if len(types) > 0 {
		if _, ok := types[event.Type]; !ok {
			return false
		}
	}
	return (query.RequestID == "" || event.RequestID == query.RequestID) &&
		(query.SessionID == "" || event.SessionID == query.SessionID) &&
		(query.ActorID == "" || event.ActorID == query.ActorID) &&
		(query.PolicyID == "" || event.PolicyID == query.PolicyID)
}

// Statistics computes counts for exactly the events selected by query.
func (l *Ledger) Statistics(ctx context.Context, query Query) (Statistics, error) {
	events, err := l.Query(ctx, query)
	if err != nil {
		return Statistics{}, err
	}
	stats := Statistics{
		ByType: make(map[string]uint64), ByActor: make(map[string]uint64),
		ByPolicy: make(map[string]uint64),
	}
	for _, event := range events {
		stats.Total++
		stats.ByType[event.Type]++
		if event.ActorID != "" {
			stats.ByActor[event.ActorID]++
		}
		if event.PolicyID != "" {
			stats.ByPolicy[event.PolicyID]++
		}
		if stats.FirstSequence == 0 || event.Sequence < stats.FirstSequence {
			stats.FirstSequence, stats.FirstTime = event.Sequence, event.Timestamp
		}
		if event.Sequence > stats.LastSequence {
			stats.LastSequence, stats.LastTime = event.Sequence, event.Timestamp
		}
	}
	return stats, nil
}

// CreateCheckpoint captures the currently verified chain head.
func (l *Ledger) CreateCheckpoint(ctx context.Context) (Checkpoint, error) {
	report, err := l.Verify(ctx)
	if err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{
		Version: formatVersion, LedgerID: l.id, Sequence: report.LastSequence,
		Hash: report.LastHash, CreatedAt: l.opts.Clock().UTC(),
	}, nil
}

// VerifyCheckpoint verifies both the complete ledger and the named historical
// prefix, so a checkpoint remains useful after later appends.
func (l *Ledger) VerifyCheckpoint(ctx context.Context, checkpoint Checkpoint) error {
	if checkpoint.Version != formatVersion || checkpoint.LedgerID != l.id {
		return errors.New("audit: checkpoint identity or version mismatch")
	}
	events, err := l.Query(ctx, Query{FromSequence: checkpoint.Sequence, ToSequence: checkpoint.Sequence})
	if err != nil {
		return err
	}
	if checkpoint.Sequence == 0 {
		if checkpoint.Hash != genesisHash {
			return errors.New("audit: empty checkpoint has non-empty hash")
		}
		return nil
	}
	if len(events) != 1 || !constantStringEqual(events[0].Hash, checkpoint.Hash) {
		return errors.New("audit: checkpoint does not match ledger prefix")
	}
	return nil
}

// SaveCheckpoint writes a checkpoint using an atomic file replacement.
func SaveCheckpoint(path string, checkpoint Checkpoint) error {
	data, err := CanonicalJSON(checkpoint)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("audit: create checkpoint directory: %w", err)
	}
	temporary := path + ".tmp-" + randomToken()
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: create checkpoint: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: write checkpoint: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: sync checkpoint: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("audit: close checkpoint: %w", err)
	}
	if err := replaceFile(temporary, path); err != nil {
		return fmt.Errorf("audit: replace checkpoint: %w", err)
	}
	cleanup = false
	return syncDirectory(filepath.Dir(path))
}

func LoadCheckpoint(path string) (Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit: read checkpoint: %w", err)
	}
	var checkpoint Checkpoint
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&checkpoint); err != nil {
		return Checkpoint{}, fmt.Errorf("audit: decode checkpoint: %w", err)
	}
	if checkpoint.Version != formatVersion || checkpoint.LedgerID == "" {
		return Checkpoint{}, errors.New("audit: invalid checkpoint")
	}
	return checkpoint, nil
}

// RepairTail truncates only one invalid final JSONL record. It refuses to hide
// corruption followed by another non-empty record.
func (l *Ledger) RepairTail(ctx context.Context) (VerifyReport, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
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
	if report.Valid {
		return report, nil
	}
	file, err := os.Open(l.path)
	if err != nil {
		return report, err
	}
	if _, err := file.Seek(report.ValidBytes, io.SeekStart); err != nil {
		_ = file.Close()
		return report, err
	}
	tail, err := io.ReadAll(file)
	_ = file.Close()
	if err != nil {
		return report, fmt.Errorf("audit: inspect invalid tail: %w", err)
	}
	if newline := bytes.IndexByte(tail, '\n'); newline >= 0 && len(bytes.TrimSpace(tail[newline+1:])) > 0 {
		return report, ErrNotTail
	}
	writable, err := os.OpenFile(l.path, os.O_WRONLY, l.opts.FileMode)
	if err != nil {
		return report, fmt.Errorf("audit: open ledger for repair: %w", err)
	}
	if err := writable.Truncate(report.ValidBytes); err == nil {
		err = writable.Sync()
	}
	closeErr := writable.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return report, fmt.Errorf("audit: truncate invalid tail: %w", err)
	}
	repaired, _, err := scanFile(l.path, nil)
	if err != nil {
		return repaired, err
	}
	if err := l.writeMetadata(repaired); err != nil {
		return repaired, err
	}
	return repaired, nil
}

// Export writes the verified JSONL byte stream without closing writer.
func (l *Ledger) Export(ctx context.Context, writer io.Writer) error {
	if writer == nil {
		return errors.New("audit: export writer is nil")
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return ErrClosed
	}
	unlock, err := l.acquireLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	report, _, err := scanFile(l.path, nil)
	if err != nil {
		return err
	}
	if !report.Valid {
		return reportError(report)
	}
	file, err := os.Open(l.path)
	if err != nil {
		return fmt.Errorf("audit: open export: %w", err)
	}
	defer file.Close()
	if _, err := io.Copy(writer, file); err != nil {
		return fmt.Errorf("audit: export: %w", err)
	}
	return nil
}

// Import atomically installs a verified JSONL stream into an empty ledger.
// Existing events are never overwritten or merged implicitly.
func (l *Ledger) Import(ctx context.Context, reader io.Reader) error {
	if reader == nil {
		return errors.New("audit: import reader is nil")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	unlock, err := l.acquireLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	current, _, err := scanFile(l.path, nil)
	if err != nil {
		return err
	}
	if !current.Valid {
		return reportError(current)
	}
	if current.Events != 0 {
		return errors.New("audit: import requires an empty ledger")
	}
	temporary := l.path + ".import-" + randomToken()
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, l.opts.FileMode)
	if err != nil {
		return fmt.Errorf("audit: create import file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := io.Copy(file, reader); err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: copy import: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: sync import: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("audit: close import: %w", err)
	}
	report, _, err := scanFile(temporary, nil)
	if err != nil {
		return err
	}
	if !report.Valid {
		return reportError(report)
	}
	if err := replaceFile(temporary, l.path); err != nil {
		return fmt.Errorf("audit: install import: %w", err)
	}
	cleanup = false
	if err := syncDirectory(filepath.Dir(l.path)); err != nil {
		return err
	}
	return l.writeMetadata(report)
}

// Replay reevaluates decision events in sequence order. It compares only the
// decision fingerprint, deliberately ignoring timing and incidental fields.
func (l *Ledger) Replay(ctx context.Context, eventType string, evaluator Evaluator) (ReplayReport, error) {
	if evaluator == nil {
		return ReplayReport{}, errors.New("audit: replay evaluator is nil")
	}
	if eventType == "" {
		eventType = "decision"
	}
	events, err := l.Query(ctx, Query{Types: []string{eventType}})
	if err != nil {
		return ReplayReport{}, err
	}
	report := ReplayReport{}
	for _, event := range events {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}
		var recorded ReplayRecord
		dec := json.NewDecoder(bytes.NewReader(event.Payload))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&recorded); err != nil {
			return report, fmt.Errorf("audit: replay event %d payload: %w", event.Sequence, err)
		}
		report.Examined++
		actual, err := evaluator(ctx, recorded.Request)
		if err != nil {
			return report, fmt.Errorf("audit: replay event %d: %w", event.Sequence, err)
		}
		expectedFingerprint, err := decisionFingerprint(recorded.Result)
		if err != nil {
			return report, err
		}
		actualFingerprint, err := decisionFingerprint(actual)
		if err != nil {
			return report, err
		}
		if constantStringEqual(expectedFingerprint, actualFingerprint) {
			report.Matched++
			continue
		}
		report.Mismatches = append(report.Mismatches, ReplayMismatch{
			Sequence: event.Sequence, RequestID: recorded.Request.RequestID,
			ExpectedFingerprint: expectedFingerprint, ActualFingerprint: actualFingerprint,
		})
	}
	return report, nil
}

func decisionFingerprint(result model.DecisionResult) (string, error) {
	if result.Fingerprint != "" {
		return result.Fingerprint, nil
	}
	result.Normalize()
	// Exclude fields that are measurements or the fingerprint itself.
	result.Fingerprint = ""
	result.EvaluationNanos = 0
	return PayloadFingerprint(result)
}

// FileStore confines ledger names to a root directory.
type FileStore struct {
	root string
	opts Options
}

func NewFileStore(root string, opts Options) (*FileStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("audit: store root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve store root: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create store root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve store root links: %w", err)
	}
	return &FileStore{root: resolved, opts: opts}, nil
}

func (s *FileStore) Root() string { return s.root }

// Resolve accepts a single portable file name, preventing traversal, absolute
// paths, alternate separators, device names represented as paths, and symlinks.
func (s *FileStore) Resolve(name string) (string, error) {
	if name == "" || name == "." || filepath.IsAbs(name) || filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\\`) || strings.ContainsRune(name, os.PathSeparator) {
		return "", ErrUnsafePath
	}
	candidate := filepath.Join(s.root, name)
	if info, err := os.Lstat(candidate); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", ErrUnsafePath
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil || filepath.Dir(resolved) != s.root {
			return "", ErrUnsafePath
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("audit: inspect store path: %w", err)
	}
	return candidate, nil
}

func (s *FileStore) Open(name string) (*Ledger, error) {
	path, err := s.Resolve(name)
	if err != nil {
		return nil, err
	}
	return Open(path, s.opts)
}

// LedgerNames lists regular *.jsonl ledgers without following links.
func (s *FileStore) LedgerNames() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("audit: list store: %w", err)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() && strings.HasSuffix(entry.Name(), ".jsonl") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
