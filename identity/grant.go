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

const defaultGrantTTL = time.Hour

// IssueGrant validates and issues a capability grant.
func (r *Registry) IssueGrant(request GrantRequest) (model.CapabilityGrant, error) {
	now := r.now()
	grant, err := buildGrant(request, now)
	if err != nil {
		return model.CapabilityGrant{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.validateGrantReferencesLocked(grant, now); err != nil {
		return model.CapabilityGrant{}, err
	}
	if existing, ok := r.grants[grant.ID]; ok {
		return cloneGrant(existing), nil
	}
	r.grants[grant.ID] = cloneGrant(grant)
	return cloneGrant(grant), nil
}

func buildGrant(request GrantRequest, now time.Time) (model.CapabilityGrant, error) {
	request.SubjectID = strings.TrimSpace(request.SubjectID)
	request.SessionID = strings.TrimSpace(request.SessionID)
	capabilities := model.SortedUnique(request.Capabilities)
	resources := model.SortedUnique(request.ResourceScopes)
	tools := model.SortedUnique(request.ToolScopes)
	if request.SubjectID == "" || len(capabilities) == 0 {
		return model.CapabilityGrant{}, wrap(ErrInvalid, "grant subject and capabilities are required")
	}
	if err := validateScopes(resources, "resource"); err != nil {
		return model.CapabilityGrant{}, err
	}
	if err := validateScopes(tools, "tool"); err != nil {
		return model.CapabilityGrant{}, err
	}

	if request.TTL < 0 {
		return model.CapabilityGrant{}, wrap(ErrInvalid, "grant TTL cannot be negative")
	}
	notBefore := request.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = now
	}
	expires := request.ExpiresAt.UTC()
	if request.TTL > 0 && !expires.IsZero() {
		return model.CapabilityGrant{}, wrap(ErrInvalid, "provide TTL or ExpiresAt, not both")
	}
	if request.TTL > 0 {
		expires = now.Add(request.TTL)
	} else if expires.IsZero() {
		expires = now.Add(defaultGrantTTL)
	}
	if !expires.After(notBefore) {
		return model.CapabilityGrant{}, wrap(ErrInvalid, "grant expiry must follow not-before")
	}
	grant := model.CapabilityGrant{
		SubjectID: request.SubjectID, SessionID: request.SessionID,
		Capabilities: capabilities, ResourceScopes: resources, ToolScopes: tools,
		Constraints: cloneMap(request.Constraints), IssuedAt: now, NotBefore: notBefore,
		ExpiresAt: expires, MaxUses: request.MaxUses, Delegable: request.Delegable,
	}
	grant.ID = DeterministicID("grt", grant.SubjectID, grant.SessionID,
		canonicalStrings(grant.Capabilities), canonicalStrings(grant.ResourceScopes),
		canonicalStrings(grant.ToolScopes), canonicalMap(grant.Constraints),
		grant.IssuedAt.Format(time.RFC3339Nano), grant.NotBefore.Format(time.RFC3339Nano),
		grant.ExpiresAt.Format(time.RFC3339Nano), strconv.FormatUint(grant.MaxUses, 10),
		strconv.FormatBool(grant.Delegable))
	return grant, nil
}

func (r *Registry) validateGrantReferencesLocked(grant model.CapabilityGrant, now time.Time) error {
	identity, ok := r.identities[grant.SubjectID]
	if !ok {
		return wrap(ErrNotFound, "grant subject %q", grant.SubjectID)
	}
	if !identity.Authenticated {
		return ErrUnauthenticated
	}
	if grant.SessionID != "" {
		session, ok := r.sessions[grant.SessionID]
		if !ok {
			return wrap(ErrNotFound, "grant session %q", grant.SessionID)
		}
		if session.IdentityID != grant.SubjectID {
			return wrap(ErrInvalid, "grant session belongs to another identity")
		}
		if err := validateSessionAt(session, now); err != nil {
			return fmt.Errorf("grant session: %w", err)
		}
	}
	return nil
}

// GetGrant retrieves an immutable grant copy.
func (r *Registry) GetGrant(id string) (model.CapabilityGrant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	grant, ok := r.grants[strings.TrimSpace(id)]
	if !ok {
		return model.CapabilityGrant{}, wrap(ErrNotFound, "grant %q", id)
	}
	return cloneGrant(grant), nil
}

// RevokeGrant revokes a grant and all grants delegated from it.
func (r *Registry) RevokeGrant(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.grants[strings.TrimSpace(id)]; !ok {
		return wrap(ErrNotFound, "grant %q", id)
	}
	queue := []string{strings.TrimSpace(id)}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		grant := r.grants[current]
		grant.Revoked = true
		r.grants[current] = grant
		for child, parent := range r.parents {
			if parent == current {
				queue = append(queue, child)
			}
		}
	}
	return nil
}

// DelegateGrant issues a strictly bounded child grant.
func (r *Registry) DelegateGrant(parentID string, request DelegationRequest) (model.CapabilityGrant, error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	parent, ok := r.grants[strings.TrimSpace(parentID)]
	if !ok {
		return model.CapabilityGrant{}, wrap(ErrNotFound, "parent grant %q", parentID)
	}
	if err := validateGrantAt(parent, now); err != nil {
		return model.CapabilityGrant{}, err
	}
	if !parent.Delegable {
		return model.CapabilityGrant{}, ErrNotDelegable
	}
	grantRequest := GrantRequest{
		SubjectID: request.SubjectID, SessionID: request.SessionID,
		Capabilities: request.Capabilities, ResourceScopes: request.ResourceScopes,
		ToolScopes: request.ToolScopes, Constraints: request.Constraints,
		NotBefore: request.NotBefore, TTL: request.TTL, ExpiresAt: request.ExpiresAt,
		MaxUses: request.MaxUses, Delegable: request.Delegable,
	}
	child, err := buildGrant(grantRequest, now)
	if err != nil {
		return model.CapabilityGrant{}, err
	}
	if err := r.validateGrantReferencesLocked(child, now); err != nil {
		return model.CapabilityGrant{}, err
	}
	if err := validateDelegation(parent, child); err != nil {
		return model.CapabilityGrant{}, err
	}
	child.ID = DeterministicID("grt", parent.ID, child.ID)
	if existing, found := r.grants[child.ID]; found {
		return cloneGrant(existing), nil
	}
	r.grants[child.ID] = cloneGrant(child)
	r.parents[child.ID] = parent.ID
	return cloneGrant(child), nil
}

func validateDelegation(parent, child model.CapabilityGrant) error {
	for _, capability := range child.Capabilities {
		if !parent.HasCapability(capability) {
			return wrap(ErrNotAuthorized, "capability %q exceeds parent", capability)
		}
	}
	if !scopeSetContained(parent.ResourceScopes, child.ResourceScopes) {
		return wrap(ErrNotAuthorized, "resource scope exceeds parent")
	}
	if !scopeSetContained(parent.ToolScopes, child.ToolScopes) {
		return wrap(ErrNotAuthorized, "tool scope exceeds parent")
	}
	if child.NotBefore.Before(parent.NotBefore) || child.ExpiresAt.After(parent.ExpiresAt) {
		return wrap(ErrNotAuthorized, "delegated time window exceeds parent")
	}
	remaining := uint64(0)
	if parent.MaxUses > 0 {
		remaining = parent.MaxUses - parent.Uses
		if child.MaxUses == 0 || child.MaxUses > remaining {
			return wrap(ErrNotAuthorized, "delegated use limit exceeds parent remainder")
		}
	}
	if child.Delegable && !parent.Delegable {
		return ErrNotDelegable
	}
	for key, expected := range parent.Constraints {
		if actual, ok := child.Constraints[key]; !ok || actual != expected {
			return wrap(ErrNotAuthorized, "delegation drops constraint %q", key)
		}
	}
	return nil
}

func validateGrantAt(grant model.CapabilityGrant, now time.Time) error {
	if grant.Revoked {
		return ErrRevoked
	}
	if now.Before(grant.NotBefore) {
		return wrap(ErrInvalid, "grant %q is not active yet", grant.ID)
	}
	if !grant.ExpiresAt.IsZero() && !now.Before(grant.ExpiresAt) {
		return ErrExpired
	}
	if grant.MaxUses > 0 && grant.Uses >= grant.MaxUses {
		return ErrUseLimit
	}
	return nil
}

// UseGrant atomically validates and consumes one use of a grant.
func (r *Registry) UseGrant(request UseRequest) (Authorization, error) {
	at := request.At.UTC()
	if at.IsZero() {
		at = r.now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	grant, ok := r.grants[strings.TrimSpace(request.GrantID)]
	if !ok {
		return Authorization{}, wrap(ErrNotFound, "grant %q", request.GrantID)
	}
	if err := validateGrantAt(grant, at); err != nil {
		return Authorization{}, err
	}
	if err := r.validateAncestorsLocked(grant.ID, at); err != nil {
		return Authorization{}, err
	}
	if request.SubjectID != "" && grant.SubjectID != request.SubjectID {
		return Authorization{}, wrap(ErrNotAuthorized, "grant subject mismatch")
	}
	identity, ok := r.identities[grant.SubjectID]
	if !ok {
		return Authorization{}, wrap(ErrNotFound, "grant identity %q", grant.SubjectID)
	}
	if !identity.Authenticated {
		return Authorization{}, ErrUnauthenticated
	}
	sessionID := strings.TrimSpace(request.SessionID)
	if grant.SessionID != "" && sessionID != grant.SessionID {
		return Authorization{}, wrap(ErrNotAuthorized, "grant session mismatch")
	}
	var session model.Session
	if sessionID != "" {
		var found bool
		session, found = r.sessions[sessionID]
		if !found {
			return Authorization{}, wrap(ErrNotFound, "session %q", sessionID)
		}
		if session.IdentityID != grant.SubjectID {
			return Authorization{}, wrap(ErrNotAuthorized, "session subject mismatch")
		}
		if err := validateSessionAt(session, at); err != nil {
			return Authorization{}, err
		}
	} else if grant.SessionID != "" {
		return Authorization{}, wrap(ErrNotAuthorized, "session is required")
	}
	if !grant.HasCapability(strings.TrimSpace(request.Capability)) {
		return Authorization{}, wrap(ErrNotAuthorized, "capability %q", request.Capability)
	}
	if !MatchResourceScope(grant.ResourceScopes, request.Resource) {
		return Authorization{}, wrap(ErrNotAuthorized, "resource %q is outside scope", request.Resource)
	}
	if !MatchToolScope(grant.ToolScopes, request.Tool) {
		return Authorization{}, wrap(ErrNotAuthorized, "tool %q is outside scope", request.Tool)
	}
	if err := CheckConstraints(grant, identity, session, request.Context, at); err != nil {
		return Authorization{}, err
	}
	grant.Uses++
	r.grants[grant.ID] = grant
	return Authorization{Grant: cloneGrant(grant), Uses: grant.Uses, Matched: true}, nil
}

func (r *Registry) validateAncestorsLocked(grantID string, at time.Time) error {
	seen := make(map[string]struct{})
	for parentID := r.parents[grantID]; parentID != ""; parentID = r.parents[parentID] {
		if _, duplicate := seen[parentID]; duplicate {
			return wrap(ErrInvalid, "grant delegation cycle")
		}
		seen[parentID] = struct{}{}
		parent, ok := r.grants[parentID]
		if !ok {
			return wrap(ErrNotFound, "ancestor grant %q", parentID)
		}
		if err := validateGrantAtIgnoringUses(parent, at); err != nil {
			return fmt.Errorf("ancestor grant %q: %w", parentID, err)
		}
	}
	return nil
}

func validateGrantAtIgnoringUses(grant model.CapabilityGrant, at time.Time) error {
	copy := grant
	copy.MaxUses = 0
	return validateGrantAt(copy, at)
}

// Authorize finds the lexicographically first suitable grant and consumes it.
func (r *Registry) Authorize(request UseRequest) (Authorization, error) {
	if request.GrantID != "" {
		return r.UseGrant(request)
	}
	r.mu.RLock()
	ids := make([]string, 0, len(r.grants))
	for id, grant := range r.grants {
		if request.SubjectID == "" || grant.SubjectID == request.SubjectID {
			ids = append(ids, id)
		}
	}
	r.mu.RUnlock()
	sort.Strings(ids)
	var failures []error
	for _, id := range ids {
		attempt := request
		attempt.GrantID = id
		result, err := r.UseGrant(attempt)
		if err == nil {
			return result, nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return Authorization{}, ErrNotAuthorized
	}
	return Authorization{}, errors.Join(append([]error{ErrNotAuthorized}, failures...)...)
}

// ListGrants returns copies sorted by ID.
func (r *Registry) ListGrants() []model.CapabilityGrant {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.CapabilityGrant, 0, len(r.grants))
	for _, grant := range r.grants {
		out = append(out, cloneGrant(grant))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
