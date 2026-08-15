package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"agentguard/model"
)

// Repository persists complete snapshots. Implementations must replace a
// snapshot atomically or return an error without exposing a partial snapshot.
type Repository interface {
	Load() ([]Record, error)
	Save([]Record) error
}

// Service serializes transitions and persists every successful mutation.
type Service struct {
	mu      sync.RWMutex
	repo    Repository
	records map[string]Record
}

// New loads and verifies all repository records before exposing the service.
func New(repo Repository) (*Service, error) {
	if repo == nil {
		return nil, errors.New("approval repository is required")
	}
	records, err := repo.Load()
	if err != nil {
		return nil, fmt.Errorf("load approvals: %w", err)
	}
	indexed := make(map[string]Record, len(records))
	for index, record := range records {
		if err := validateRecord(record); err != nil {
			return nil, fmt.Errorf("load approval record %d: %w", index, err)
		}
		if _, exists := indexed[record.Request.ID]; exists {
			return nil, fmt.Errorf("load approvals: duplicate id %q", record.Request.ID)
		}
		indexed[record.Request.ID] = cloneRecord(record)
	}
	return &Service{repo: repo, records: indexed}, nil
}

// Create starts a pending workflow and returns its model-level projection.
func (s *Service) Create(request Request) (model.Approval, error) {
	request.normalize()
	if err := request.validate(); err != nil {
		return model.Approval{}, err
	}
	record := Record{Request: request, Status: StatusPending}
	record.Signature = signRecord(record)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[request.ID]; exists {
		return model.Approval{}, fmt.Errorf("%w: %s", ErrAlreadyExists, request.ID)
	}
	if err := s.commit(record); err != nil {
		return model.Approval{}, err
	}
	return project(record), nil
}

// Approve records one authorized affirmative vote. The state remains pending
// until the configured number of distinct approvers has voted affirmatively.
func (s *Service) Approve(id string, actor model.Identity, reason string, at time.Time) (model.Approval, error) {
	return s.vote(id, actor, true, reason, at)
}

// Reject records an authorized negative vote and immediately rejects the request.
func (s *Service) Reject(id string, actor model.Identity, reason string, at time.Time) (model.Approval, error) {
	return s.vote(id, actor, false, reason, at)
}

func (s *Service) vote(id string, actor model.Identity, approved bool, reason string, at time.Time) (model.Approval, error) {
	at = canonicalTime(at)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[id]
	if !exists {
		return model.Approval{}, ErrNotFound
	}
	record = cloneRecord(record)
	if changed := expireIfDue(&record, at); changed {
		if err := s.commit(record); err != nil {
			return model.Approval{}, err
		}
		return project(record), ErrExpired
	}
	if record.Status != StatusPending {
		return model.Approval{}, stateError(record.Status, "vote")
	}
	if at.IsZero() || at.Before(record.Request.CreatedAt) {
		return model.Approval{}, errors.New("vote time precedes request creation")
	}
	if err := authorize(record.Request, actor); err != nil {
		return model.Approval{}, err
	}
	for _, existing := range record.Votes {
		if existing.ApproverID == actor.ID {
			return model.Approval{}, fmt.Errorf("%w: %s", ErrDuplicateVote, actor.ID)
		}
	}
	record.Votes = append(record.Votes, Vote{
		ApproverID: actor.ID,
		Approved:   approved,
		Reason:     strings.TrimSpace(reason),
		DecidedAt:  at,
		Roles:      model.SortedUnique(actor.Roles),
		Groups:     model.SortedUnique(actor.Groups),
		Assurance:  actor.AssuranceLevel,
	})
	if !approved {
		record.Status = StatusRejected
		record.DecidedAt = at
	} else if affirmativeVotes(record.Votes) >= record.Request.Requirements.Quorum {
		record.Status = StatusApproved
		record.DecidedAt = at
	}
	record.Signature = signRecord(record)
	if err := s.commit(record); err != nil {
		return model.Approval{}, err
	}
	return project(record), nil
}

// Cancel cancels a pending request. Only its subject can cancel it.
func (s *Service) Cancel(id, actorID string, at time.Time) (model.Approval, error) {
	return s.cancel(id, strings.TrimSpace(actorID), false, at)
}

// CancelAs permits the subject or an authenticated approval-admin to cancel.
func (s *Service) CancelAs(id string, actor model.Identity, at time.Time) (model.Approval, error) {
	if err := actor.Validate(); err != nil || !actor.Authenticated {
		return model.Approval{}, fmt.Errorf("cancel actor: %w", ErrUnauthorized)
	}
	return s.cancel(id, actor.ID, actor.HasRole("approval-admin"), at)
}

func (s *Service) cancel(id, actorID string, administrator bool, at time.Time) (model.Approval, error) {
	at = canonicalTime(at)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[id]
	if !exists {
		return model.Approval{}, ErrNotFound
	}
	record = cloneRecord(record)
	if expireIfDue(&record, at) {
		if err := s.commit(record); err != nil {
			return model.Approval{}, err
		}
		return project(record), ErrExpired
	}
	if record.Status != StatusPending {
		return model.Approval{}, stateError(record.Status, "cancel")
	}
	if actorID == "" || (actorID != record.Request.SubjectID && !administrator) {
		return model.Approval{}, fmt.Errorf("%w: only subject or approval-admin may cancel", ErrUnauthorized)
	}
	if at.IsZero() || at.Before(record.Request.CreatedAt) {
		return model.Approval{}, errors.New("cancellation time precedes request creation")
	}
	record.Status = StatusCancelled
	record.DecidedAt = at
	record.CancelledBy = actorID
	record.Signature = signRecord(record)
	if err := s.commit(record); err != nil {
		return model.Approval{}, err
	}
	return project(record), nil
}

// Consume validates exact scope and constraints, then irreversibly spends one
// approved request. Concurrent callers cannot both succeed.
func (s *Service) Consume(id, subjectID, callID string, constraints map[string]string, at time.Time) (model.Approval, error) {
	at = canonicalTime(at)
	if err := validateConstraints(constraints); err != nil {
		return model.Approval{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[id]
	if !exists {
		return model.Approval{}, ErrNotFound
	}
	record = cloneRecord(record)
	if record.Status == StatusConsumed {
		return model.Approval{}, ErrAlreadyConsumed
	}
	if expireIfDue(&record, at) {
		if err := s.commit(record); err != nil {
			return model.Approval{}, err
		}
		return project(record), ErrExpired
	}
	if record.Status != StatusApproved {
		return model.Approval{}, stateError(record.Status, "consume")
	}
	if subjectID != record.Request.SubjectID || callID != record.Request.CallID {
		return model.Approval{}, errors.New("approval scope does not match consumption")
	}
	if !equalConstraints(record.Request.Constraints, constraints) {
		return model.Approval{}, ErrConstraint
	}
	if at.IsZero() || at.Before(record.DecidedAt) {
		return model.Approval{}, errors.New("consumption time precedes approval")
	}
	record.Status = StatusConsumed
	record.ConsumedAt = at
	record.Signature = signRecord(record)
	if err := s.commit(record); err != nil {
		return model.Approval{}, err
	}
	return project(record), nil
}

// Expire advances a due pending or approved request to expired.
func (s *Service) Expire(id string, at time.Time) (model.Approval, error) {
	at = canonicalTime(at)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[id]
	if !exists {
		return model.Approval{}, ErrNotFound
	}
	record = cloneRecord(record)
	if !expireIfDue(&record, at) {
		if record.Status == StatusExpired {
			return project(record), nil
		}
		return model.Approval{}, stateError(record.Status, "expire")
	}
	if err := s.commit(record); err != nil {
		return model.Approval{}, err
	}
	return project(record), nil
}

func authorize(request Request, actor model.Identity) error {
	if err := actor.Validate(); err != nil {
		return fmt.Errorf("%w: invalid identity: %v", ErrUnauthorized, err)
	}
	if !actor.Authenticated {
		return fmt.Errorf("%w: unauthenticated actor", ErrUnauthorized)
	}
	if actor.ID == request.SubjectID && !request.Requirements.AllowSelfApproval {
		return ErrSelfApproval
	}
	if actor.AssuranceLevel < request.Requirements.MinAssurance {
		return fmt.Errorf("%w: assurance %d is below %d", ErrUnauthorized, actor.AssuranceLevel, request.Requirements.MinAssurance)
	}
	roles := model.SortedUnique(actor.Roles)
	groups := model.SortedUnique(actor.Groups)
	if len(request.Requirements.Roles) > 0 && !hasAny(roles, request.Requirements.Roles) {
		return fmt.Errorf("%w: required approver role is missing", ErrUnauthorized)
	}
	if len(request.Requirements.Groups) > 0 && !hasAny(groups, request.Requirements.Groups) {
		return fmt.Errorf("%w: required approver group is missing", ErrUnauthorized)
	}
	return nil
}

func expireIfDue(record *Record, at time.Time) bool {
	if at.IsZero() || at.Before(record.Request.ExpiresAt) {
		return false
	}
	if record.Status != StatusPending && record.Status != StatusApproved {
		return false
	}
	record.Status = StatusExpired
	record.ExpiredAt = record.Request.ExpiresAt
	record.Signature = signRecord(*record)
	return true
}

func affirmativeVotes(votes []Vote) int {
	count := 0
	for _, vote := range votes {
		if vote.Approved {
			count++
		}
	}
	return count
}

func stateError(status Status, operation string) error {
	if status == StatusConsumed && operation == "consume" {
		return ErrAlreadyConsumed
	}
	if status == StatusExpired {
		return ErrExpired
	}
	return fmt.Errorf("%w: cannot %s %s request", ErrInvalidState, operation, status)
}
func (s *Service) commit(candidate Record) error {
	next := make([]Record, 0, len(s.records)+1)
	replaced := false
	for id, current := range s.records {
		if id == candidate.Request.ID {
			next = append(next, cloneRecord(candidate))
			replaced = true
		} else {
			next = append(next, cloneRecord(current))
		}
	}
	if !replaced {
		next = append(next, cloneRecord(candidate))
	}
	sort.Slice(next, func(i, j int) bool { return next[i].Request.ID < next[j].Request.ID })
	if err := s.repo.Save(next); err != nil {
		return fmt.Errorf("save approvals: %w", err)
	}
	s.records[candidate.Request.ID] = cloneRecord(candidate)
	return nil
}

type signedRecord struct {
	Request     Request   `json:"request"`
	Status      Status    `json:"status"`
	Votes       []Vote    `json:"votes,omitempty"`
	DecidedAt   time.Time `json:"decided_at,omitempty"`
	CancelledBy string    `json:"cancelled_by,omitempty"`
	ExpiredAt   time.Time `json:"expired_at,omitempty"`
	ConsumedAt  time.Time `json:"consumed_at,omitempty"`
}

// Signature returns the deterministic SHA-256 digest of all canonical workflow
// fields. Map keys are sorted by encoding/json; lists are normalized at input.
func Signature(record Record) string {
	return signRecord(record)
}

func signRecord(record Record) string {
	payload := signedRecord{
		Request: record.Request, Status: record.Status, Votes: record.Votes,
		DecidedAt: record.DecidedAt, CancelledBy: record.CancelledBy,
		ExpiredAt: record.ExpiredAt, ConsumedAt: record.ConsumedAt,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("approval canonical encoding failed: %v", err))
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func project(record Record) model.Approval {
	approvers := make([]string, 0, len(record.Votes))
	reasons := make([]string, 0, len(record.Votes)+1)
	if record.Request.Reason != "" {
		reasons = append(reasons, record.Request.Reason)
	}
	for _, vote := range record.Votes {
		approvers = append(approvers, vote.ApproverID)
		if vote.Reason != "" {
			reasons = append(reasons, vote.ApproverID+": "+vote.Reason)
		}
	}
	approvers = model.SortedUnique(approvers)
	decidedAt := record.DecidedAt
	switch record.Status {
	case StatusExpired:
		decidedAt = record.ExpiredAt
	case StatusConsumed:
		decidedAt = record.ConsumedAt
	}
	return model.Approval{
		ID:          record.Request.ID,
		RequestID:   record.Request.RequestID,
		CallID:      record.Request.CallID,
		SubjectID:   record.Request.SubjectID,
		ApproverID:  strings.Join(approvers, ","),
		Status:      string(record.Status),
		Reason:      strings.Join(reasons, "; "),
		CreatedAt:   record.Request.CreatedAt,
		DecidedAt:   decidedAt,
		ExpiresAt:   record.Request.ExpiresAt,
		PolicyID:    record.Request.PolicyID,
		Constraints: cloneMap(record.Request.Constraints),
		Signature:   record.Signature,
	}
}
