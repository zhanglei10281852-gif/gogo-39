package identity

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGlobMatching(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"projects/*/readme.md", "projects/a/readme.md", true},
		{"projects/*/readme.md", "projects/a/docs/readme.md", false},
		{"projects/**", "projects/a/docs/readme.md", true},
		{"tool.?rite", "tool.write", true},
		{"tool.?rite", "tool./rite", false},
		{"C:/work/**", `C:\work\a\b`, true},
	}
	for _, test := range tests {
		if got := GlobMatch(test.pattern, test.value); got != test.want {
			t.Errorf("GlobMatch(%q, %q) = %v, want %v", test.pattern, test.value, got, test.want)
		}
	}
}

func issueBoundGrant(t *testing.T, registry *Registry, sessionID string, maxUses uint64) string {
	t.Helper()
	grant, err := registry.IssueGrant(GrantRequest{
		SubjectID: "agent-7", SessionID: sessionID,
		Capabilities:   []string{"file.read", "file.write"},
		ResourceScopes: []string{"repos/acme/**"}, ToolScopes: []string{"fs.*"},
		Constraints: map[string]string{
			"assurance_min": "2", "role": "writer", "identity.attribute.tenant": "acme",
			"session.tag.device": "ci", "context.environment": "test|staging",
		},
		TTL: 30 * time.Minute, MaxUses: maxUses, Delegable: true,
	})
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}
	return grant.ID
}

func TestGrantUseScopesConstraintsAndLimit(t *testing.T) {
	registry, _, _ := newTestRegistry(t)
	session, err := registry.CreateSession("agent-7", time.Hour, map[string]string{"device": "ci"})
	if err != nil {
		t.Fatal(err)
	}
	grantID := issueBoundGrant(t, registry, session.ID, 2)
	base := UseRequest{
		GrantID: grantID, SubjectID: "agent-7", SessionID: session.ID,
		Capability: "file.write", Resource: "repos/acme/api/main.go", Tool: "fs.write",
		Context: map[string]string{"environment": "test"},
	}
	first, err := registry.UseGrant(base)
	if err != nil || first.Uses != 1 {
		t.Fatalf("first use: %#v, %v", first, err)
	}
	bad := base
	bad.Resource = "repos/other/secret"
	if _, err := registry.UseGrant(bad); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("out-of-scope resource was accepted: %v", err)
	}
	bad = base
	bad.Context = map[string]string{"environment": "production"}
	if _, err := registry.UseGrant(bad); !errors.Is(err, ErrConstraint) {
		t.Fatalf("constraint mismatch was accepted: %v", err)
	}
	second, err := registry.UseGrant(base)
	if err != nil || second.Uses != 2 {
		t.Fatalf("second use: %#v, %v", second, err)
	}
	if _, err := registry.UseGrant(base); !errors.Is(err, ErrUseLimit) {
		t.Fatalf("exhausted grant was accepted: %v", err)
	}
}

func TestDelegationNarrowsAndRevocationCascades(t *testing.T) {
	registry, clock, _ := newTestRegistry(t)
	session, err := registry.CreateSession("agent-7", time.Hour, map[string]string{"device": "ci"})
	if err != nil {
		t.Fatal(err)
	}
	parentID := issueBoundGrant(t, registry, session.ID, 10)
	child, err := registry.DelegateGrant(parentID, DelegationRequest{
		SubjectID: "agent-7", SessionID: session.ID, Capabilities: []string{"file.read"},
		ResourceScopes: []string{"repos/acme/docs/**"}, ToolScopes: []string{"fs.read"},
		Constraints: map[string]string{
			"assurance_min": "2", "role": "writer", "identity.attribute.tenant": "acme",
			"session.tag.device": "ci", "context.environment": "test|staging",
		},
		ExpiresAt: clock.Now().Add(20 * time.Minute), MaxUses: 3,
	})
	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	_, err = registry.DelegateGrant(parentID, DelegationRequest{
		SubjectID: "agent-7", Capabilities: []string{"admin"},
		ExpiresAt: clock.Now().Add(time.Minute), MaxUses: 1,
	})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("expanded delegation should fail: %v", err)
	}
	if err := registry.RevokeGrant(parentID); err != nil {
		t.Fatal(err)
	}
	stored, err := registry.GetGrant(child.ID)
	if err != nil || !stored.Revoked {
		t.Fatalf("child was not cascade revoked: %#v, %v", stored, err)
	}
}

func TestConcurrentGrantConsumptionIsAtomic(t *testing.T) {
	registry, _, _ := newTestRegistry(t)
	session, err := registry.CreateSession("agent-7", time.Hour, map[string]string{"device": "ci"})
	if err != nil {
		t.Fatal(err)
	}
	grantID := issueBoundGrant(t, registry, session.ID, 25)
	request := UseRequest{
		GrantID: grantID, SubjectID: "agent-7", SessionID: session.ID,
		Capability: "file.read", Resource: "repos/acme/a", Tool: "fs.read",
		Context: map[string]string{"environment": "test"},
	}
	var successes atomic.Int64
	var wait sync.WaitGroup
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := registry.UseGrant(request); err == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 25 {
		t.Fatalf("got %d successful uses, want 25", successes.Load())
	}
	grant, err := registry.GetGrant(grantID)
	if err != nil || grant.Uses != 25 {
		t.Fatalf("stored uses = %d, err = %v", grant.Uses, err)
	}
}
