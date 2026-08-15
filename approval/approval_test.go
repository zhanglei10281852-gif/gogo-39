package approval

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agentguard/model"
)

var testBase = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func testRequest(id string) Request {
	return Request{
		ID: id, RequestID: "evaluation-" + id, CallID: "call-" + id,
		SubjectID: "subject", PolicyID: "policy-v1", Reason: "dangerous operation",
		CreatedAt: testBase, ExpiresAt: testBase.Add(time.Hour),
		Constraints: map[string]string{"destination": "prod", "ticket": "SEC-123"},
		Requirements: Requirements{
			Quorum: 2, RequireTwoPerson: true, Roles: []string{"security"},
			Groups: []string{"operations"}, MinAssurance: 2,
		},
	}
}

func approver(id string) model.Identity {
	return model.Identity{
		ID: id, Kind: "human", Authenticated: true,
		Roles: []string{"security"}, Groups: []string{"operations"}, AssuranceLevel: 3,
	}
}

func newMemoryService(t *testing.T) *Service {
	t.Helper()
	service, err := New(NewMemoryRepository())
	if err != nil {
		t.Fatal(err)
	}
	return service
}
func TestTwoPersonWorkflowPersistsAndConsumesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "approvals.json")
	service, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(testRequest("approval-1"))
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != string(StatusPending) || len(created.Signature) != 64 {
		t.Fatalf("unexpected creation: %+v", created)
	}
	first, err := service.Approve("approval-1", approver("alice"), "reviewed", testBase.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != string(StatusPending) {
		t.Fatalf("one vote reached quorum: %s", first.Status)
	}
	second, err := service.Approve("approval-1", approver("bob"), "independent review", testBase.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != string(StatusApproved) || second.ApproverID != "alice,bob" {
		t.Fatalf("unexpected approval: %+v", second)
	}

	reloaded, err := OpenFile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	loaded, err := reloaded.Get("approval-1", testBase.Add(3*time.Minute))
	if err != nil || loaded.Signature != second.Signature {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	constraints := map[string]string{"ticket": "SEC-123", "destination": "prod"}
	consumed, err := reloaded.Consume("approval-1", "subject", "call-approval-1", constraints, testBase.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != string(StatusConsumed) || consumed.Signature == second.Signature {
		t.Fatalf("unexpected consumed projection: %+v", consumed)
	}
	if _, err := reloaded.Consume("approval-1", "subject", "call-approval-1", constraints, testBase.Add(5*time.Minute)); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("second consumption error = %v", err)
	}
}
func TestApproverAuthorizationAndSelfApproval(t *testing.T) {
	tests := []struct {
		name  string
		actor model.Identity
		want  error
	}{
		{"self", approver("subject"), ErrSelfApproval},
		{"unauthenticated", model.Identity{ID: "a", Kind: "human", Roles: []string{"security"}, Groups: []string{"operations"}, AssuranceLevel: 3}, ErrUnauthorized},
		{"role", model.Identity{ID: "a", Kind: "human", Authenticated: true, Groups: []string{"operations"}, AssuranceLevel: 3}, ErrUnauthorized},
		{"group", model.Identity{ID: "a", Kind: "human", Authenticated: true, Roles: []string{"security"}, AssuranceLevel: 3}, ErrUnauthorized},
		{"assurance", model.Identity{ID: "a", Kind: "human", Authenticated: true, Roles: []string{"security"}, Groups: []string{"operations"}, AssuranceLevel: 1}, ErrUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newMemoryService(t)
			if _, err := service.Create(testRequest("auth-" + test.name)); err != nil {
				t.Fatal(err)
			}
			_, err := service.Approve("auth-"+test.name, test.actor, "", testBase.Add(time.Minute))
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestDuplicateVoteAndConstraintBinding(t *testing.T) {
	service := newMemoryService(t)
	duplicate := testRequest("duplicate")
	if _, err := service.Create(duplicate); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve("duplicate", approver("alice"), "", testBase.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve("duplicate", approver("alice"), "", testBase.Add(2*time.Minute)); !errors.Is(err, ErrDuplicateVote) {
		t.Fatalf("duplicate vote error: %v", err)
	}

	request := testRequest("binding")
	request.Requirements.Quorum = 1
	request.Requirements.RequireTwoPerson = false
	if _, err := service.Create(request); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve("binding", approver("alice"), "", testBase.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Consume("binding", "subject", "call-binding", map[string]string{"destination": "prod"}, testBase.Add(3*time.Minute)); !errors.Is(err, ErrConstraint) {
		t.Fatalf("partial constraints accepted: %v", err)
	}
	if _, err := service.Consume("binding", "other", "call-binding", request.Constraints, testBase.Add(3*time.Minute)); err == nil {
		t.Fatal("mismatched subject accepted")
	}
}
func TestRejectionCancellationAndExpirationAreTerminal(t *testing.T) {
	service := newMemoryService(t)
	for _, id := range []string{"reject", "cancel", "expire"} {
		if _, err := service.Create(testRequest(id)); err != nil {
			t.Fatal(err)
		}
	}
	rejected, err := service.Reject("reject", approver("alice"), "unsafe", testBase.Add(time.Minute))
	if err != nil || rejected.Status != string(StatusRejected) {
		t.Fatalf("rejected=%+v err=%v", rejected, err)
	}
	if _, err := service.Approve("reject", approver("bob"), "", testBase.Add(2*time.Minute)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("terminal rejection accepted vote: %v", err)
	}
	cancelled, err := service.Cancel("cancel", "subject", testBase.Add(time.Minute))
	if err != nil || cancelled.Status != string(StatusCancelled) {
		t.Fatalf("cancelled=%+v err=%v", cancelled, err)
	}
	if _, err := service.Cancel("expire", "intruder", testBase.Add(time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unauthorized cancellation error: %v", err)
	}
	expired, err := service.Get("expire", testBase.Add(time.Hour))
	if err != nil || expired.Status != string(StatusExpired) {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
	if _, err := service.Approve("expire", approver("alice"), "", testBase.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired vote error: %v", err)
	}
}

func TestConcurrentConsumptionHasSingleWinner(t *testing.T) {
	service := newMemoryService(t)
	request := testRequest("race")
	request.Requirements.Quorum = 1
	request.Requirements.RequireTwoPerson = false
	if _, err := service.Create(request); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve("race", approver("alice"), "", testBase.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	const callers = 32
	var wait sync.WaitGroup
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := service.Consume("race", "subject", "call-race", request.Constraints, testBase.Add(2*time.Minute))
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	already := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAlreadyConsumed):
			already++
		default:
			t.Fatalf("unexpected consume result: %v", err)
		}
	}
	if successes != 1 || already != callers-1 {
		t.Fatalf("successes=%d already=%d", successes, already)
	}
}
func TestStrictRepositoryRejectsUnknownDuplicateAndTamperedData(t *testing.T) {
	makeFile := func(t *testing.T) (string, []byte) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "approvals.json")
		service, err := OpenFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Create(testRequest("strict")); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return path, data
	}
	t.Run("unknown", func(t *testing.T) {
		path, data := makeFile(t)
		data = []byte(strings.Replace(string(data), "\"version\": 1,", "\"version\": 1, \"unknown\": true,", 1))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(path); err == nil {
			t.Fatal("unknown field was accepted")
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		path, data := makeFile(t)
		data = []byte(strings.Replace(string(data), "\"version\": 1,", "\"version\": 1, \"version\": 1,", 1))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate field error = %v", err)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		path, data := makeFile(t)
		data = []byte(strings.Replace(string(data), "dangerous operation", "silently changed", 1))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(path); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("tamper error = %v", err)
		}
	})
}
func TestQueryStatisticsAndDeterministicSignature(t *testing.T) {
	service := newMemoryService(t)
	first := testRequest("b")
	first.Requirements.Roles = []string{"security", "audit", "security"}
	first.Requirements.Groups = []string{"operations", "blue"}
	first.Constraints = map[string]string{"z": "last", "a": "first"}
	second := testRequest("a")
	second.SubjectID = "other"
	second.ExpiresAt = testBase.Add(48 * time.Hour)
	if _, err := service.Create(first); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(second); err != nil {
		t.Fatal(err)
	}
	listed, err := service.List(Filter{Status: StatusPending}, testBase)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].ID != "a" || listed[1].ID != "b" {
		t.Fatalf("list is not stable: %+v", listed)
	}
	stats, err := service.StatisticsWithin(testBase, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 || stats.ByStatus[StatusPending] != 2 || stats.PendingDue != 1 {
		t.Fatalf("unexpected statistics: %+v", stats)
	}
	record, err := service.Inspect("b", testBase)
	if err != nil {
		t.Fatal(err)
	}
	if record.Signature != Signature(record) {
		t.Fatal("exported signature calculation differs")
	}
	copy := cloneRecord(record)
	copy.Request.Constraints = map[string]string{"a": "first", "z": "last"}
	if Signature(copy) != record.Signature {
		t.Fatal("map insertion order changed signature")
	}
}

func TestSweepExpiredAndApprovalFilter(t *testing.T) {
	service := newMemoryService(t)
	for _, id := range []string{"one", "two"} {
		request := testRequest(id)
		request.ExpiresAt = testBase.Add(time.Duration(len(id)) * time.Minute)
		if _, err := service.Create(request); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Approve("one", approver("alice"), "", testBase.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	byAlice, err := service.List(Filter{ApproverID: "alice"}, testBase.Add(time.Minute))
	if err != nil || len(byAlice) != 1 || byAlice[0].ID != "one" {
		t.Fatalf("approver query=%+v err=%v", byAlice, err)
	}
	expired, err := service.SweepExpired(testBase.Add(4 * time.Minute))
	if err != nil || len(expired) != 2 {
		t.Fatalf("sweep=%+v err=%v", expired, err)
	}
	stats, err := service.Statistics(testBase.Add(4 * time.Minute))
	if err != nil || stats.ByStatus[StatusExpired] != 2 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
}
func TestApprovedExpirationPreservesApprovalEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	service, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("approved-expiry")
	request.Requirements.Quorum = 1
	request.Requirements.RequireTwoPerson = false
	if _, err := service.Create(request); err != nil {
		t.Fatal(err)
	}
	approvalTime := testBase.Add(time.Minute)
	if _, err := service.Approve(request.ID, approver("alice"), "", approvalTime); err != nil {
		t.Fatal(err)
	}
	projected, err := service.Get(request.ID, testBase.Add(24*time.Hour))
	if err != nil || projected.Status != string(StatusExpired) {
		t.Fatalf("expired=%+v err=%v", projected, err)
	}
	if !projected.DecidedAt.Equal(request.ExpiresAt) {
		t.Fatalf("model expiration time=%v want %v", projected.DecidedAt, request.ExpiresAt)
	}
	record, err := service.Inspect(request.ID, testBase.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !record.DecidedAt.Equal(approvalTime) || !record.ExpiredAt.Equal(request.ExpiresAt) {
		t.Fatalf("approval evidence was lost: %+v", record)
	}
	if _, err := OpenFile(path); err != nil {
		t.Fatalf("strict reload of expired approval: %v", err)
	}
}

type failingRepository struct {
	saveErr error
}

func (r *failingRepository) Load() ([]Record, error) { return []Record{}, nil }
func (r *failingRepository) Save([]Record) error     { return r.saveErr }

func TestPersistenceFailureDoesNotPublishTransition(t *testing.T) {
	repository := &failingRepository{saveErr: errors.New("disk unavailable")}
	service, err := New(repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(testRequest("rollback")); err == nil || !strings.Contains(err.Error(), "disk unavailable") {
		t.Fatalf("creation error=%v", err)
	}
	if _, err := service.Get("rollback", testBase); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed creation became visible: %v", err)
	}
}
