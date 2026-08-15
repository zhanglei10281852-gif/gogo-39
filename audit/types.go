// Package audit provides a durable, tamper-evident audit ledger.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"agentguard/model"
)

const (
	formatVersion = 1
	genesisHash   = ""
)

var (
	ErrClosed       = errors.New("audit: ledger is closed")
	ErrLockTimeout  = errors.New("audit: timed out acquiring lock")
	ErrChainInvalid = errors.New("audit: hash chain is invalid")
	ErrUnsafePath   = errors.New("audit: unsafe store path")
	ErrNotTail      = errors.New("audit: corruption is not confined to the tail")
)

// EventInput contains caller-controlled event fields. Sequence and hashes are
// assigned by the ledger. Payload may be any JSON-compatible Go value.
type EventInput struct {
	Timestamp time.Time
	Type      string
	RequestID string
	SessionID string
	ActorID   string
	PolicyID  string
	Payload   any
}

// VerifyReport describes a complete scan of a ledger.
type VerifyReport struct {
	Valid        bool   `json:"valid"`
	Events       uint64 `json:"events"`
	LastSequence uint64 `json:"last_sequence"`
	LastHash     string `json:"last_hash"`
	ValidBytes   int64  `json:"valid_bytes"`
	FileBytes    int64  `json:"file_bytes"`
	InvalidLine  uint64 `json:"invalid_line,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// Query selects events. Zero values impose no restriction.
type Query struct {
	FromSequence uint64
	ToSequence   uint64
	FromTime     time.Time
	ToTime       time.Time
	Types        []string
	RequestID    string
	SessionID    string
	ActorID      string
	PolicyID     string
	Limit        int
	Reverse      bool
}

// Statistics summarizes a selected event stream.
type Statistics struct {
	Total         uint64            `json:"total"`
	FirstSequence uint64            `json:"first_sequence,omitempty"`
	LastSequence  uint64            `json:"last_sequence,omitempty"`
	FirstTime     time.Time         `json:"first_time,omitempty"`
	LastTime      time.Time         `json:"last_time,omitempty"`
	ByType        map[string]uint64 `json:"by_type"`
	ByActor       map[string]uint64 `json:"by_actor"`
	ByPolicy      map[string]uint64 `json:"by_policy"`
}

// Checkpoint is a portable assertion about a verified ledger prefix.
type Checkpoint struct {
	Version   int       `json:"version"`
	LedgerID  string    `json:"ledger_id"`
	Sequence  uint64    `json:"sequence"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
}

// ReplayRecord is the conventional payload for decision events. Producers may
// store it directly as EventInput.Payload.
type ReplayRecord struct {
	Request model.EvaluationRequest `json:"request"`
	Result  model.DecisionResult    `json:"result"`
}

// Evaluator deterministically evaluates a recorded request.
type Evaluator func(context.Context, model.EvaluationRequest) (model.DecisionResult, error)

type ReplayMismatch struct {
	Sequence            uint64 `json:"sequence"`
	RequestID           string `json:"request_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	ActualFingerprint   string `json:"actual_fingerprint"`
}

type ReplayReport struct {
	Examined   uint64           `json:"examined"`
	Matched    uint64           `json:"matched"`
	Mismatches []ReplayMismatch `json:"mismatches,omitempty"`
}

// Metadata is a recoverable cache. The JSONL ledger remains authoritative.
type Metadata struct {
	Version      int       `json:"version"`
	LedgerID     string    `json:"ledger_id"`
	EventCount   uint64    `json:"event_count"`
	LastSequence uint64    `json:"last_sequence"`
	LastHash     string    `json:"last_hash"`
	FileSize     int64     `json:"file_size"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// CorruptionError identifies the first invalid line without exposing payloads.
type CorruptionError struct {
	Line   uint64
	Offset int64
	Reason string
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("%v at line %d byte %d: %s", ErrChainInvalid, e.Line, e.Offset, e.Reason)
}

func (e *CorruptionError) Unwrap() error { return ErrChainInvalid }

// PayloadFingerprint returns the SHA-256 fingerprint used by replay when a
// decision result did not carry its own fingerprint.
func PayloadFingerprint(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return digestHex(b), nil
}

func rawPayload(v any) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage("null"), nil
	}
	b, err := CanonicalJSON(v)
	if err != nil {
		return nil, fmt.Errorf("audit: canonical payload: %w", err)
	}
	return json.RawMessage(b), nil
}
