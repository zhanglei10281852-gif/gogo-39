// Package identity provides deterministic in-memory identity, session, and
// capability management for AgentGuard.
package identity

import (
	"errors"
	"time"

	"agentguard/model"
)

var (
	ErrNotFound        = errors.New("identity: not found")
	ErrAlreadyExists   = errors.New("identity: already exists")
	ErrInvalid         = errors.New("identity: invalid input")
	ErrUnauthenticated = errors.New("identity: principal is not authenticated")
	ErrExpired         = errors.New("identity: object is expired")
	ErrRevoked         = errors.New("identity: object is revoked")
	ErrReplay          = errors.New("identity: replay detected")
	ErrSequence        = errors.New("identity: invalid sequence")
	ErrNonce           = errors.New("identity: invalid nonce")
	ErrNotAuthorized   = errors.New("identity: capability is not authorized")
	ErrNotDelegable    = errors.New("identity: grant is not delegable")
	ErrUseLimit        = errors.New("identity: grant use limit exhausted")
	ErrConstraint      = errors.New("identity: constraint is not satisfied")
	ErrSnapshotVersion = errors.New("identity: unsupported snapshot version")
)

// Clock is the only source of current time used by Registry.
type Clock func() time.Time

// Option configures a Registry.
type Option func(*Registry) error

// WithClock installs a clock. It is ideal for deterministic tests.
func WithClock(clock Clock) Option {
	return func(r *Registry) error {
		if clock == nil {
			return errors.Join(ErrInvalid, errors.New("nil clock"))
		}
		r.clock = clock
		return nil
	}
}

// SessionRequest contains all inputs that determine a new session.
type SessionRequest struct {
	IdentityID      string
	TTL             time.Duration
	ParentSessionID string
	Tags            map[string]string
	Nonce           string
}

// GrantRequest contains all inputs used to issue a capability grant.
type GrantRequest struct {
	SubjectID      string
	SessionID      string
	Capabilities   []string
	ResourceScopes []string
	ToolScopes     []string
	Constraints    map[string]string
	NotBefore      time.Time
	TTL            time.Duration
	ExpiresAt      time.Time
	MaxUses        uint64
	Delegable      bool
}

// DelegationRequest narrows a parent grant for another subject.
type DelegationRequest struct {
	SubjectID      string
	SessionID      string
	Capabilities   []string
	ResourceScopes []string
	ToolScopes     []string
	Constraints    map[string]string
	NotBefore      time.Time
	TTL            time.Duration
	ExpiresAt      time.Time
	MaxUses        uint64
	Delegable      bool
}

// UseRequest describes one atomic authorization and grant-consumption attempt.
type UseRequest struct {
	GrantID    string
	SubjectID  string
	SessionID  string
	Capability string
	Resource   string
	Tool       string
	Context    map[string]string
	At         time.Time
}

// Snapshot is a portable complete registry image. Slices are sorted on export.
type Snapshot struct {
	Version    int                     `json:"version"`
	ExportedAt time.Time               `json:"exported_at"`
	Identities []model.Identity        `json:"identities"`
	Sessions   []model.Session         `json:"sessions"`
	Grants     []model.CapabilityGrant `json:"grants"`
	Nonces     []NonceRecord           `json:"nonces,omitempty"`
	Parents    []GrantParent           `json:"grant_parents,omitempty"`
}

// NonceRecord persists a consumed session nonce across snapshot round trips.
type NonceRecord struct {
	SessionID string `json:"session_id"`
	Nonce     string `json:"nonce"`
}

// GrantParent records the delegation relationship of a grant.
type GrantParent struct {
	GrantID  string `json:"grant_id"`
	ParentID string `json:"parent_id"`
}

// Authorization is returned after a successful grant use.
type Authorization struct {
	Grant   model.CapabilityGrant
	Uses    uint64
	Matched bool
}
