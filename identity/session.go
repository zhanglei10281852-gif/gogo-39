package identity

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"agentguard/model"
)

const defaultSessionTTL = 30 * time.Minute

// CreateSession creates a session with optional tags.
func (r *Registry) CreateSession(identityID string, ttl time.Duration, tags map[string]string) (model.Session, error) {
	return r.CreateSessionRequest(SessionRequest{IdentityID: identityID, TTL: ttl, Tags: tags})
}

// CreateSessionRequest creates a deterministic session from normalized inputs.
func (r *Registry) CreateSessionRequest(request SessionRequest) (model.Session, error) {
	request.IdentityID = strings.TrimSpace(request.IdentityID)
	request.ParentSessionID = strings.TrimSpace(request.ParentSessionID)
	if request.IdentityID == "" {
		return model.Session{}, wrap(ErrInvalid, "identity ID is empty")
	}
	if request.TTL == 0 {
		request.TTL = defaultSessionTTL
	}
	if request.TTL < 0 {
		return model.Session{}, wrap(ErrInvalid, "session TTL must be positive")
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.identities[request.IdentityID]
	if !ok {
		return model.Session{}, wrap(ErrNotFound, "identity %q", request.IdentityID)
	}
	if !identity.Authenticated {
		return model.Session{}, ErrUnauthenticated
	}

	if request.ParentSessionID != "" {
		parent, found := r.sessions[request.ParentSessionID]
		if !found {
			return model.Session{}, wrap(ErrNotFound, "parent session %q", request.ParentSessionID)
		}
		if err := validateSessionAt(parent, now); err != nil {
			return model.Session{}, fmt.Errorf("parent session: %w", err)
		}
		if parent.IdentityID != request.IdentityID {
			return model.Session{}, wrap(ErrInvalid, "parent session has a different identity")
		}
	}
	created := now
	expires := now.Add(request.TTL)
	id := DeterministicID("ses", request.IdentityID, request.ParentSessionID,
		created.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano), canonicalMap(request.Tags))
	nonce := strings.TrimSpace(request.Nonce)
	if nonce == "" {
		nonce = DeterministicID("nonce", id, "initial")
	}
	session := model.Session{
		ID: id, IdentityID: request.IdentityID, CreatedAt: created,
		ExpiresAt: expires, LastSeenAt: created, Nonce: nonce,
		ParentSessionID: request.ParentSessionID, Tags: cloneMap(request.Tags),
	}
	if existing, found := r.sessions[id]; found {
		return cloneSession(existing), nil
	}
	r.sessions[id] = cloneSession(session)
	r.nonces[id] = make(map[string]struct{})
	return cloneSession(session), nil
}

// GetSession retrieves an immutable session copy.
func (r *Registry) GetSession(id string) (model.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[strings.TrimSpace(id)]
	if !ok {
		return model.Session{}, wrap(ErrNotFound, "session %q", id)
	}
	return cloneSession(session), nil
}

// ValidateSession validates status at the registry clock's current instant.
func (r *Registry) ValidateSession(id string) (model.Session, error) {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[strings.TrimSpace(id)]
	if !ok {
		return model.Session{}, wrap(ErrNotFound, "session %q", id)
	}
	if _, ok := r.identities[session.IdentityID]; !ok {
		return model.Session{}, wrap(ErrNotFound, "session identity %q", session.IdentityID)
	}
	if err := validateSessionAt(session, now); err != nil {
		return model.Session{}, err
	}
	return cloneSession(session), nil
}

func validateSessionAt(session model.Session, at time.Time) error {
	if session.Revoked {
		return ErrRevoked
	}
	if at.Before(session.CreatedAt) {
		return wrap(ErrInvalid, "session %q is not active yet", session.ID)
	}
	if !at.Before(session.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

// RenewSession extends a live session from the later of now and its expiry.
func (r *Registry) RenewSession(id string, extension time.Duration) (model.Session, error) {
	if extension <= 0 {
		return model.Session{}, wrap(ErrInvalid, "renewal duration must be positive")
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[strings.TrimSpace(id)]
	if !ok {
		return model.Session{}, wrap(ErrNotFound, "session %q", id)
	}
	if err := validateSessionAt(session, now); err != nil {
		return model.Session{}, err
	}
	base := session.ExpiresAt
	if now.After(base) {
		base = now
	}
	session.ExpiresAt = base.Add(extension)
	session.LastSeenAt = now
	r.sessions[session.ID] = session
	return cloneSession(session), nil
}

// RevokeSession marks a session permanently unusable. It is idempotent.
func (r *Registry) RevokeSession(id, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[strings.TrimSpace(id)]
	if !ok {
		return wrap(ErrNotFound, "session %q", id)
	}
	if session.Revoked {
		return nil
	}
	session.Revoked = true
	session.RevocationNote = strings.TrimSpace(reason)
	r.sessions[session.ID] = session
	return nil
}

// AdvanceSession atomically verifies the next sequence and consumes a nonce.
// Sequence numbers start at one. A nonce may never be reused within a session.
func (r *Registry) AdvanceSession(id string, sequence uint64, nonce string) (model.Session, error) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return model.Session{}, ErrNonce
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[strings.TrimSpace(id)]
	if !ok {
		return model.Session{}, wrap(ErrNotFound, "session %q", id)
	}
	if err := validateSessionAt(session, now); err != nil {
		return model.Session{}, err
	}
	if sequence != session.Sequence+1 {
		if sequence <= session.Sequence {
			return model.Session{}, errors.Join(ErrReplay, ErrSequence)
		}
		return model.Session{}, wrap(ErrSequence, "got %d, want %d", sequence, session.Sequence+1)
	}
	used := r.nonces[session.ID]
	if used == nil {
		used = make(map[string]struct{})
		r.nonces[session.ID] = used
	}
	if _, exists := used[nonce]; exists {
		return model.Session{}, errors.Join(ErrReplay, ErrNonce)
	}
	used[nonce] = struct{}{}
	session.Sequence = sequence
	session.Nonce = nonce
	session.LastSeenAt = now
	r.sessions[session.ID] = session
	return cloneSession(session), nil
}

// UseNonce advances by exactly one sequence.
func (r *Registry) UseNonce(id, nonce string) (model.Session, error) {
	r.mu.RLock()
	session, ok := r.sessions[strings.TrimSpace(id)]
	r.mu.RUnlock()
	if !ok {
		return model.Session{}, wrap(ErrNotFound, "session %q", id)
	}
	return r.AdvanceSession(id, session.Sequence+1, nonce)
}

// CheckSequence reports whether a request is precisely the next request.
func (r *Registry) CheckSequence(id string, sequence uint64) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[strings.TrimSpace(id)]
	if !ok {
		return wrap(ErrNotFound, "session %q", id)
	}
	if sequence != session.Sequence+1 {
		return wrap(ErrSequence, "got %d, want %d", sequence, session.Sequence+1)
	}
	return nil
}

// ListSessions returns copies sorted by session ID.
func (r *Registry) ListSessions() []model.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.Session, 0, len(r.sessions))
	for _, session := range r.sessions {
		out = append(out, cloneSession(session))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SessionSequence returns the current committed sequence.
func (r *Registry) SessionSequence(id string) (uint64, error) {
	session, err := r.GetSession(id)
	if err != nil {
		return 0, err
	}
	return session.Sequence, nil
}

// NextNonce derives a deterministic caller nonce without mutating registry state.
func NextNonce(sessionID string, sequence uint64, payload string) string {
	return DeterministicID("nonce", sessionID, strconv.FormatUint(sequence, 10), payload)
}
