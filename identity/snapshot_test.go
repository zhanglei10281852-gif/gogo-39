package identity

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"agentguard/model"
)

func TestSnapshotRoundTripPreservesReplayState(t *testing.T) {
	registry, clock, _ := newTestRegistry(t)
	session, err := registry.CreateSession("agent-7", time.Hour, map[string]string{"device": "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AdvanceSession(session.ID, 1, "used-once"); err != nil {
		t.Fatal(err)
	}
	grantID := issueBoundGrant(t, registry, session.ID, 3)
	request := UseRequest{
		GrantID: grantID, SubjectID: "agent-7", SessionID: session.ID,
		Capability: "file.read", Resource: "repos/acme/readme", Tool: "fs.read",
		Context: map[string]string{"environment": "test"},
	}
	if _, err := registry.UseGrant(request); err != nil {
		t.Fatal(err)
	}
	firstJSON, err := registry.MarshalSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := registry.MarshalSnapshot()
	if err != nil || !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("fixed-clock exports are not deterministic: %v", err)
	}
	copyRegistry := NewRegistry(WithClock(clock.Now))
	if err := copyRegistry.UnmarshalSnapshot(firstJSON); err != nil {
		t.Fatalf("import: %v", err)
	}
	copied, err := copyRegistry.GetGrant(grantID)
	if err != nil || copied.Uses != 1 {
		t.Fatalf("grant state not preserved: %#v, %v", copied, err)
	}
	if _, err := copyRegistry.AdvanceSession(session.ID, 2, "used-once"); !errors.Is(err, ErrReplay) {
		t.Fatalf("nonce replay state was not preserved: %v", err)
	}
}

func TestInvalidSnapshotDoesNotPartiallyReplaceRegistry(t *testing.T) {
	registry, _, _ := newTestRegistry(t)
	snapshot := registry.ExportSnapshot()
	snapshot.Sessions = append(snapshot.Sessions, snapshotSessionWithMissingIdentity())
	if err := registry.ImportSnapshot(snapshot); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected invalid snapshot, got %v", err)
	}
	if _, err := registry.GetIdentity("agent-7"); err != nil {
		t.Fatalf("failed import modified registry: %v", err)
	}
}

func snapshotSessionWithMissingIdentity() model.Session {
	created := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	return model.Session{
		ID: "orphan", IdentityID: "missing", CreatedAt: created,
		LastSeenAt: created, ExpiresAt: created.Add(time.Hour), Nonce: "n",
	}
}

func TestSnapshotRejectsDelegationCycle(t *testing.T) {
	registry, clock, _ := newTestRegistry(t)
	first := model.CapabilityGrant{
		ID: "g1", SubjectID: "agent-7", Capabilities: []string{"read"},
		IssuedAt: clock.Now(), NotBefore: clock.Now(), ExpiresAt: clock.Now().Add(time.Hour),
		Delegable: true,
	}
	second := first
	second.ID = "g2"
	snapshot := registry.ExportSnapshot()
	snapshot.Grants = []model.CapabilityGrant{first, second}
	snapshot.Parents = []GrantParent{{GrantID: "g1", ParentID: "g2"}, {GrantID: "g2", ParentID: "g1"}}
	if err := registry.ImportSnapshot(snapshot); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cycle should fail: %v", err)
	}
}

func TestSnapshotJSONRejectsUnknownAndTrailingData(t *testing.T) {
	registry, _, _ := newTestRegistry(t)
	if err := registry.UnmarshalSnapshot([]byte(`{"version":1,"exported_at":"2030-01-01T00:00:00Z","identities":[],"sessions":[],"grants":[],"unknown":true}`)); err == nil {
		t.Fatal("unknown snapshot field was accepted")
	}
	data, err := registry.MarshalSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(` {}`)...)
	if err := registry.UnmarshalSnapshot(data); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}
