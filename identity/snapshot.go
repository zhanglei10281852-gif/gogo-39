package identity

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"agentguard/model"
)

// ExportSnapshot captures a deep copy while holding one read lock.
func (r *Registry) ExportSnapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snapshot := Snapshot{Version: snapshotVersion, ExportedAt: r.now()}
	for _, identity := range r.identities {
		snapshot.Identities = append(snapshot.Identities, cloneIdentity(identity))
	}
	for _, session := range r.sessions {
		snapshot.Sessions = append(snapshot.Sessions, cloneSession(session))
	}
	for _, grant := range r.grants {
		snapshot.Grants = append(snapshot.Grants, cloneGrant(grant))
	}
	for sessionID, nonces := range r.nonces {
		for nonce := range nonces {
			snapshot.Nonces = append(snapshot.Nonces, NonceRecord{SessionID: sessionID, Nonce: nonce})
		}
	}
	for grantID, parentID := range r.parents {
		snapshot.Parents = append(snapshot.Parents, GrantParent{GrantID: grantID, ParentID: parentID})
	}
	sortIdentities(snapshot.Identities)
	sort.Slice(snapshot.Sessions, func(i, j int) bool { return snapshot.Sessions[i].ID < snapshot.Sessions[j].ID })
	sort.Slice(snapshot.Grants, func(i, j int) bool { return snapshot.Grants[i].ID < snapshot.Grants[j].ID })
	sort.Slice(snapshot.Nonces, func(i, j int) bool {
		if snapshot.Nonces[i].SessionID != snapshot.Nonces[j].SessionID {
			return snapshot.Nonces[i].SessionID < snapshot.Nonces[j].SessionID
		}
		return snapshot.Nonces[i].Nonce < snapshot.Nonces[j].Nonce
	})

	sort.Slice(snapshot.Parents, func(i, j int) bool { return snapshot.Parents[i].GrantID < snapshot.Parents[j].GrantID })
	return snapshot
}

// ImportSnapshot validates into temporary maps and commits all state atomically.
func (r *Registry) ImportSnapshot(snapshot Snapshot) error {
	if snapshot.Version != snapshotVersion {
		return wrap(ErrSnapshotVersion, "version %d", snapshot.Version)
	}
	identities := make(map[string]model.Identity, len(snapshot.Identities))
	for _, raw := range snapshot.Identities {
		identity := normalizeIdentity(raw)
		if err := requireIdentityAuthenticated(identity); err != nil {
			return fmt.Errorf("snapshot identity %q: %w", identity.ID, err)
		}
		if _, duplicate := identities[identity.ID]; duplicate {
			return wrap(ErrInvalid, "duplicate identity %q", identity.ID)
		}
		identities[identity.ID] = cloneIdentity(identity)
	}
	sessions := make(map[string]model.Session, len(snapshot.Sessions))
	for _, raw := range snapshot.Sessions {
		session := cloneSession(raw)
		if err := validateSessionStructure(session); err != nil {
			return fmt.Errorf("snapshot session %q: %w", session.ID, err)
		}
		if _, ok := identities[session.IdentityID]; !ok {
			return wrap(ErrInvalid, "session %q references missing identity", session.ID)
		}
		if _, duplicate := sessions[session.ID]; duplicate {
			return wrap(ErrInvalid, "duplicate session %q", session.ID)
		}
		sessions[session.ID] = session
	}
	for _, session := range sessions {
		if session.ParentSessionID == "" {
			continue
		}
		parent, ok := sessions[session.ParentSessionID]
		if !ok || parent.IdentityID != session.IdentityID {
			return wrap(ErrInvalid, "session %q has invalid parent", session.ID)
		}
		if hasSessionCycle(session.ID, sessions) {
			return wrap(ErrInvalid, "session parent cycle at %q", session.ID)
		}
	}
	grants := make(map[string]model.CapabilityGrant, len(snapshot.Grants))
	for _, raw := range snapshot.Grants {
		grant := normalizeGrant(raw)
		if err := validateGrantStructure(grant); err != nil {
			return fmt.Errorf("snapshot grant %q: %w", grant.ID, err)
		}
		if _, ok := identities[grant.SubjectID]; !ok {
			return wrap(ErrInvalid, "grant %q references missing identity", grant.ID)
		}
		if grant.SessionID != "" {
			session, ok := sessions[grant.SessionID]
			if !ok || session.IdentityID != grant.SubjectID {
				return wrap(ErrInvalid, "grant %q has invalid session", grant.ID)
			}
		}
		if _, duplicate := grants[grant.ID]; duplicate {
			return wrap(ErrInvalid, "duplicate grant %q", grant.ID)
		}
		grants[grant.ID] = grant
	}

	nonces := make(map[string]map[string]struct{}, len(sessions))
	for id := range sessions {
		nonces[id] = make(map[string]struct{})
	}
	for _, record := range snapshot.Nonces {
		if _, ok := sessions[record.SessionID]; !ok || strings.TrimSpace(record.Nonce) == "" {
			return wrap(ErrInvalid, "invalid nonce record for session %q", record.SessionID)
		}
		if _, duplicate := nonces[record.SessionID][record.Nonce]; duplicate {
			return wrap(ErrInvalid, "duplicate nonce for session %q", record.SessionID)
		}
		nonces[record.SessionID][record.Nonce] = struct{}{}
	}
	parents := make(map[string]string, len(snapshot.Parents))
	for _, relation := range snapshot.Parents {
		child, childOK := grants[relation.GrantID]
		parent, parentOK := grants[relation.ParentID]
		if !childOK || !parentOK || relation.GrantID == relation.ParentID {
			return wrap(ErrInvalid, "invalid grant parent relation for %q", relation.GrantID)
		}
		if _, duplicate := parents[relation.GrantID]; duplicate {
			return wrap(ErrInvalid, "duplicate parent for grant %q", relation.GrantID)
		}
		if err := validateDelegationStructure(parent, child); err != nil {
			return fmt.Errorf("grant relation %q: %w", relation.GrantID, err)
		}
		parents[relation.GrantID] = relation.ParentID
	}
	for id := range parents {
		if hasGrantCycle(id, parents) {
			return wrap(ErrInvalid, "grant delegation cycle at %q", id)
		}
	}
	r.mu.Lock()
	r.identities = identities
	r.sessions = sessions
	r.grants = grants
	r.nonces = nonces
	r.parents = parents
	r.mu.Unlock()
	return nil
}

func validateSessionStructure(session model.Session) error {
	if strings.TrimSpace(session.ID) == "" || strings.TrimSpace(session.IdentityID) == "" {
		return wrap(ErrInvalid, "session ID and identity ID are required")
	}
	if session.CreatedAt.IsZero() || session.ExpiresAt.IsZero() || !session.ExpiresAt.After(session.CreatedAt) {
		return wrap(ErrInvalid, "invalid session time window")
	}
	if session.LastSeenAt.Before(session.CreatedAt) || session.LastSeenAt.After(session.ExpiresAt) {
		return wrap(ErrInvalid, "last-seen is outside session window")
	}
	return nil
}

func validateGrantStructure(grant model.CapabilityGrant) error {
	if strings.TrimSpace(grant.ID) == "" || strings.TrimSpace(grant.SubjectID) == "" || len(grant.Capabilities) == 0 {
		return wrap(ErrInvalid, "grant ID, subject, and capabilities are required")
	}
	if grant.IssuedAt.IsZero() || grant.NotBefore.IsZero() || grant.ExpiresAt.IsZero() {
		return wrap(ErrInvalid, "grant times are required")
	}
	if grant.NotBefore.Before(grant.IssuedAt) || !grant.ExpiresAt.After(grant.NotBefore) {
		return wrap(ErrInvalid, "invalid grant time window")
	}
	if grant.MaxUses > 0 && grant.Uses > grant.MaxUses {
		return wrap(ErrInvalid, "grant use count exceeds limit")
	}
	if err := validateScopes(grant.ResourceScopes, "resource"); err != nil {
		return err
	}
	return validateScopes(grant.ToolScopes, "tool")
}

func validateDelegationStructure(parent, child model.CapabilityGrant) error {
	for _, capability := range child.Capabilities {
		if !parent.HasCapability(capability) {
			return wrap(ErrNotAuthorized, "capability exceeds parent")
		}
	}
	if !scopeSetContained(parent.ResourceScopes, child.ResourceScopes) ||
		!scopeSetContained(parent.ToolScopes, child.ToolScopes) {
		return wrap(ErrNotAuthorized, "scope exceeds parent")
	}
	if child.NotBefore.Before(parent.NotBefore) || child.ExpiresAt.After(parent.ExpiresAt) {
		return wrap(ErrNotAuthorized, "time window exceeds parent")
	}
	for key, value := range parent.Constraints {
		if child.Constraints[key] != value {
			return wrap(ErrNotAuthorized, "constraint %q is not inherited", key)
		}
	}
	return nil
}

func hasSessionCycle(start string, sessions map[string]model.Session) bool {
	seen := make(map[string]struct{})
	for current := start; current != ""; current = sessions[current].ParentSessionID {
		if _, exists := seen[current]; exists {
			return true
		}
		seen[current] = struct{}{}
		if _, exists := sessions[current]; !exists {
			return false
		}
	}
	return false
}

func hasGrantCycle(start string, parents map[string]string) bool {
	seen := make(map[string]struct{})
	for current := start; current != ""; current = parents[current] {
		if _, exists := seen[current]; exists {
			return true
		}
		seen[current] = struct{}{}
	}
	return false
}

// ReplaceFromSnapshot is an alias emphasizing replacement semantics.
func (r *Registry) ReplaceFromSnapshot(snapshot Snapshot) error {
	return r.ImportSnapshot(snapshot)
}

// SnapshotVersion returns the supported portable format version.
func SnapshotVersion() int { return snapshotVersion }

// SnapshotAt changes only the descriptive export timestamp.
func SnapshotAt(snapshot Snapshot, at time.Time) Snapshot {
	snapshot.ExportedAt = at.UTC()
	return snapshot
}
