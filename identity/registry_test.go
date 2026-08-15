package identity

import (
	"errors"
	"sync"
	"testing"
	"time"

	"agentguard/model"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func newTestRegistry(t *testing.T) (*Registry, *testClock, model.Identity) {
	t.Helper()
	clock := &testClock{now: time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)}
	registry := NewRegistry(WithClock(clock.Now))
	principal := model.Identity{
		ID: "agent-7", Kind: "agent", Issuer: "tests", Authenticated: true,
		AssuranceLevel: 3, Roles: []string{"writer", "writer"}, Groups: []string{"engineering"},
		Attributes: map[string]string{"tenant": "acme", "region": "eu-west"},
	}
	registered, err := registry.RegisterIdentity(principal)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return registry, clock, registered
}

func TestIdentityRegistrationCopiesAndVerifies(t *testing.T) {
	registry, _, registered := newTestRegistry(t)
	if len(registered.Roles) != 1 {
		t.Fatalf("roles were not normalized: %#v", registered.Roles)
	}
	registered.Attributes["tenant"] = "mutated"
	stored, err := registry.Authenticate("agent-7", 3)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Attributes["tenant"] != "acme" {
		t.Fatal("registry leaked mutable identity state")
	}
	if _, err := registry.Authenticate("agent-7", 4); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected assurance failure, got %v", err)
	}
	if err := registry.VerifyIdentity(stored); err != nil {
		t.Fatalf("verify registered claims: %v", err)
	}
	stored.Issuer = "attacker"
	if err := registry.VerifyIdentity(stored); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("modified claims should fail: %v", err)
	}
}

func TestDeterministicIDUsesFraming(t *testing.T) {
	first := DeterministicID("x", "ab", "c")
	if first != DeterministicID("x", "ab", "c") {
		t.Fatal("same inputs produced different IDs")
	}
	if first == DeterministicID("x", "a", "bc") {
		t.Fatal("unframed concatenations collided")
	}
	if len(first) != 34 || first[:2] != "x_" {
		t.Fatalf("unexpected ID form %q", first)
	}
}

func TestSessionSequenceNonceRenewAndRevoke(t *testing.T) {
	registry, clock, _ := newTestRegistry(t)
	session, err := registry.CreateSession("agent-7", 10*time.Minute, map[string]string{"device": "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if !session.CreatedAt.Equal(clock.Now()) || session.Sequence != 0 {
		t.Fatalf("unexpected new session: %#v", session)
	}
	advanced, err := registry.AdvanceSession(session.ID, 1, "n-1")
	if err != nil || advanced.Sequence != 1 {
		t.Fatalf("advance: %#v, %v", advanced, err)
	}
	if _, err := registry.AdvanceSession(session.ID, 1, "n-2"); !errors.Is(err, ErrReplay) {
		t.Fatalf("old sequence was not replay: %v", err)
	}
	if _, err := registry.AdvanceSession(session.ID, 2, "n-1"); !errors.Is(err, ErrReplay) {
		t.Fatalf("reused nonce was not replay: %v", err)
	}
	before := advanced.ExpiresAt
	renewed, err := registry.RenewSession(session.ID, 5*time.Minute)
	if err != nil || !renewed.ExpiresAt.Equal(before.Add(5*time.Minute)) {
		t.Fatalf("renew: %#v, %v", renewed, err)
	}
	if err := registry.RevokeSession(session.ID, "test complete"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ValidateSession(session.ID); !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected revoked, got %v", err)
	}
}

func TestSessionExpiryUsesInjectedClock(t *testing.T) {
	registry, clock, _ := newTestRegistry(t)
	session, err := registry.CreateSession("agent-7", time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	if _, err := registry.ValidateSession(session.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("boundary should be expired: %v", err)
	}
}
