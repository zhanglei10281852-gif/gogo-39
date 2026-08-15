package identity

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"agentguard/model"
)

// RegisterIdentity validates and stores an identity. Re-registering identical
// normalized data is idempotent; changing an existing ID is rejected.
func (r *Registry) RegisterIdentity(identity model.Identity) (model.Identity, error) {
	identity = normalizeIdentity(identity)
	if err := identity.Validate(); err != nil {
		return model.Identity{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !identity.Authenticated {
		return model.Identity{}, ErrUnauthenticated
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.identities[identity.ID]; ok {
		if reflect.DeepEqual(existing, identity) {
			return cloneIdentity(existing), nil
		}
		return model.Identity{}, wrap(ErrAlreadyExists, "identity %q", identity.ID)
	}
	r.identities[identity.ID] = cloneIdentity(identity)
	return cloneIdentity(identity), nil
}

// Register is a terse compatibility helper.
func (r *Registry) Register(identity model.Identity) error {
	_, err := r.RegisterIdentity(identity)
	return err
}

// GetIdentity retrieves an immutable copy.
func (r *Registry) GetIdentity(id string) (model.Identity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	identity, ok := r.identities[strings.TrimSpace(id)]
	if !ok {
		return model.Identity{}, wrap(ErrNotFound, "identity %q", id)
	}
	return cloneIdentity(identity), nil
}

// Identity returns an identity and a presence flag.
func (r *Registry) Identity(id string) (model.Identity, bool) {
	identity, err := r.GetIdentity(id)
	return identity, err == nil
}

// VerifyIdentity compares security-relevant fields with the registered record.
func (r *Registry) VerifyIdentity(candidate model.Identity) error {
	candidate = normalizeIdentity(candidate)
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	registered, err := r.GetIdentity(candidate.ID)
	if err != nil {
		return err
	}
	if !candidate.Authenticated || !registered.Authenticated {
		return ErrUnauthenticated
	}
	if !reflect.DeepEqual(registered, candidate) {
		return wrap(ErrUnauthenticated, "identity %q does not match registered claims", candidate.ID)
	}
	return nil
}

// Authenticate checks registration, authentication, and minimum assurance.
func (r *Registry) Authenticate(id string, minimumAssurance int) (model.Identity, error) {
	if minimumAssurance < 0 || minimumAssurance > 4 {
		return model.Identity{}, wrap(ErrInvalid, "assurance %d is outside 0..4", minimumAssurance)
	}
	identity, err := r.GetIdentity(id)
	if err != nil {
		return model.Identity{}, err
	}
	if !identity.Authenticated {
		return model.Identity{}, ErrUnauthenticated
	}
	if identity.AssuranceLevel < minimumAssurance {
		return model.Identity{}, wrap(ErrUnauthenticated,
			"identity %q assurance %d is below %d", id, identity.AssuranceLevel, minimumAssurance)
	}
	return identity, nil
}

// RemoveIdentity removes an identity only when no session or grant refers to it.
func (r *Registry) RemoveIdentity(id string) error {
	id = strings.TrimSpace(id)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.identities[id]; !ok {
		return wrap(ErrNotFound, "identity %q", id)
	}
	for _, session := range r.sessions {
		if session.IdentityID == id {
			return wrap(ErrInvalid, "identity %q still owns session %q", id, session.ID)
		}
	}
	for _, grant := range r.grants {
		if grant.SubjectID == id {
			return wrap(ErrInvalid, "identity %q still owns grant %q", id, grant.ID)
		}
	}
	delete(r.identities, id)
	return nil
}

// ListIdentities returns copies sorted by ID.
func (r *Registry) ListIdentities() []model.Identity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.Identity, 0, len(r.identities))
	for _, identity := range r.identities {
		out = append(out, cloneIdentity(identity))
	}
	sortIdentities(out)
	return out
}

func sortIdentities(values []model.Identity) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j].ID < values[j-1].ID; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func sameStringSet(left, right []string) bool {
	return reflect.DeepEqual(model.SortedUnique(left), model.SortedUnique(right))
}

func requireIdentityAuthenticated(identity model.Identity) error {
	if err := identity.Validate(); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	if !identity.Authenticated {
		return ErrUnauthenticated
	}
	return nil
}
