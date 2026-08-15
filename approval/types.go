package approval

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"agentguard/model"
)

// Status is a durable state in the approval workflow.
type Status string

const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusRejected  Status = "rejected"
	StatusCancelled Status = "cancelled"
	StatusExpired   Status = "expired"
	StatusConsumed  Status = "consumed"
)

var (
	ErrNotFound        = errors.New("approval request not found")
	ErrAlreadyExists   = errors.New("approval request already exists")
	ErrInvalidState    = errors.New("invalid approval state transition")
	ErrUnauthorized    = errors.New("actor is not authorized to approve")
	ErrSelfApproval    = errors.New("self-approval is prohibited")
	ErrDuplicateVote   = errors.New("approver has already voted")
	ErrExpired         = errors.New("approval request is expired")
	ErrConstraint      = errors.New("approval constraints do not match")
	ErrAlreadyConsumed = errors.New("approval has already been consumed")
)

// Requirements controls who may vote and how many independent votes are needed.
// Roles and Groups are both enforced when both are non-empty.
type Requirements struct {
	Quorum            int      `json:"quorum"`
	RequireTwoPerson  bool     `json:"require_two_person,omitempty"`
	AllowSelfApproval bool     `json:"allow_self_approval,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	MinAssurance      int      `json:"min_assurance,omitempty"`
}

// Request describes a new approval workflow. CreatedAt must be supplied so
// creation and signatures are replayable rather than dependent on wall time.
type Request struct {
	ID           string            `json:"id"`
	RequestID    string            `json:"request_id"`
	CallID       string            `json:"call_id"`
	SubjectID    string            `json:"subject_id"`
	PolicyID     string            `json:"policy_id"`
	Reason       string            `json:"reason"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	Constraints  map[string]string `json:"constraints,omitempty"`
	Requirements Requirements      `json:"requirements"`
}

// Vote is immutable evidence of one authorized actor's decision.
type Vote struct {
	ApproverID string    `json:"approver_id"`
	Approved   bool      `json:"approved"`
	Reason     string    `json:"reason,omitempty"`
	DecidedAt  time.Time `json:"decided_at"`
	Roles      []string  `json:"roles,omitempty"`
	Groups     []string  `json:"groups,omitempty"`
	Assurance  int       `json:"assurance"`
}

// Record is the complete durable representation of a workflow.
type Record struct {
	Request     Request   `json:"request"`
	Status      Status    `json:"status"`
	Votes       []Vote    `json:"votes,omitempty"`
	DecidedAt   time.Time `json:"decided_at,omitempty"`
	CancelledBy string    `json:"cancelled_by,omitempty"`
	ExpiredAt   time.Time `json:"expired_at,omitempty"`
	ConsumedAt  time.Time `json:"consumed_at,omitempty"`
	Signature   string    `json:"signature"`
}

// Filter selects records for List. Zero fields do not filter.
type Filter struct {
	Status      Status
	SubjectID   string
	PolicyID    string
	ApproverID  string
	CreatedFrom time.Time
	CreatedTo   time.Time
}

// Stats summarizes the repository at a caller-provided instant.
type Stats struct {
	Total       int            `json:"total"`
	ByStatus    map[Status]int `json:"by_status"`
	PendingDue  int            `json:"pending_due"`
	ApprovedDue int            `json:"approved_due"`
	Votes       int            `json:"votes"`
}

func (s Status) valid() bool {
	switch s {
	case StatusPending, StatusApproved, StatusRejected, StatusCancelled, StatusExpired, StatusConsumed:
		return true
	default:
		return false
	}
}

func (s Status) terminal() bool {
	return s == StatusRejected || s == StatusCancelled || s == StatusExpired || s == StatusConsumed
}

func (r *Requirements) normalize() {
	r.Roles = model.SortedUnique(r.Roles)
	r.Groups = model.SortedUnique(r.Groups)
	if r.Quorum == 0 {
		r.Quorum = 1
	}
	if r.RequireTwoPerson && r.Quorum < 2 {
		r.Quorum = 2
	}
}

func (r Requirements) validate() error {
	if r.Quorum < 1 {
		return errors.New("approval quorum must be at least one")
	}
	if r.RequireTwoPerson && r.Quorum < 2 {
		return errors.New("two-person approval requires quorum of at least two")
	}
	if r.MinAssurance < 0 || r.MinAssurance > 4 {
		return errors.New("minimum assurance must be between zero and four")
	}
	if err := validateNames("role", r.Roles); err != nil {
		return err
	}
	return validateNames("group", r.Groups)
}

func (r *Request) normalize() {
	r.ID = strings.TrimSpace(r.ID)
	r.RequestID = strings.TrimSpace(r.RequestID)
	r.CallID = strings.TrimSpace(r.CallID)
	r.SubjectID = strings.TrimSpace(r.SubjectID)
	r.PolicyID = strings.TrimSpace(r.PolicyID)
	r.Reason = strings.TrimSpace(r.Reason)
	r.CreatedAt = canonicalTime(r.CreatedAt)
	r.ExpiresAt = canonicalTime(r.ExpiresAt)
	r.Constraints = cloneMap(r.Constraints)
	r.Requirements.normalize()
}

func (r Request) validate() error {
	for name, value := range map[string]string{
		"id": r.ID, "request_id": r.RequestID, "call_id": r.CallID,
		"subject_id": r.SubjectID, "policy_id": r.PolicyID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("approval %s is required", name)
		}
	}
	if r.CreatedAt.IsZero() || r.ExpiresAt.IsZero() {
		return errors.New("approval created_at and expires_at are required")
	}
	if !r.ExpiresAt.After(r.CreatedAt) {
		return errors.New("approval expires_at must follow created_at")
	}
	if err := validateConstraints(r.Constraints); err != nil {
		return err
	}
	return r.Requirements.validate()
}
func validateNames(kind string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("approval %s must be non-empty and trimmed", kind)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("duplicate approval %s %q", kind, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateConstraints(values map[string]string) error {
	for key, value := range values {
		if key == "" || strings.TrimSpace(key) != key {
			return fmt.Errorf("%w: keys must be non-empty and trimmed", ErrConstraint)
		}
		if strings.TrimSpace(value) != value {
			return fmt.Errorf("%w: value for %q must be trimmed", ErrConstraint, key)
		}
		if len(key) > 128 || len(value) > 4096 {
			return fmt.Errorf("%w: %q exceeds size limit", ErrConstraint, key)
		}
	}
	return nil
}

func canonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Round(0)
}

func cloneMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func cloneRecord(source Record) Record {
	result := source
	result.Request.Constraints = cloneMap(source.Request.Constraints)
	result.Request.Requirements.Roles = append([]string(nil), source.Request.Requirements.Roles...)
	result.Request.Requirements.Groups = append([]string(nil), source.Request.Requirements.Groups...)
	result.Votes = make([]Vote, len(source.Votes))
	for index, vote := range source.Votes {
		result.Votes[index] = vote
		result.Votes[index].Roles = append([]string(nil), vote.Roles...)
		result.Votes[index].Groups = append([]string(nil), vote.Groups...)
	}
	return result
}

func hasAny(actual, required []string) bool {
	for _, candidate := range actual {
		index := sort.SearchStrings(required, candidate)
		if index < len(required) && required[index] == candidate {
			return true
		}
	}
	return false
}

func equalConstraints(required, actual map[string]string) bool {
	if len(required) != len(actual) {
		return false
	}
	for key, value := range required {
		if actual[key] != value {
			return false
		}
	}
	return true
}
