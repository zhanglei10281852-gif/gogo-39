package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Decision is the final disposition of a tool call.
type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
	DecisionApprove Decision = "require_approval"
)

// Risk is an ordered risk classification.
type Risk string

const (
	RiskNone     Risk = "none"
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

func (r Risk) Rank() int {
	switch r {
	case RiskNone:
		return 0
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	default:
		return -1
	}
}

func ParseRisk(value string) (Risk, error) {
	r := Risk(strings.ToLower(strings.TrimSpace(value)))
	if r.Rank() < 0 {
		return "", fmt.Errorf("invalid risk %q", value)
	}
	return r, nil
}

// Identity describes an authenticated principal. Attributes are policy inputs.
type Identity struct {
	ID             string            `json:"id"`
	Kind           string            `json:"kind"`
	Issuer         string            `json:"issuer"`
	Roles          []string          `json:"roles,omitempty"`
	Groups         []string          `json:"groups,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	Authenticated  bool              `json:"authenticated"`
	AssuranceLevel int               `json:"assurance_level"`
}

func (i Identity) Validate() error {
	if strings.TrimSpace(i.ID) == "" {
		return errors.New("identity id is required")
	}
	if strings.TrimSpace(i.Kind) == "" {
		return errors.New("identity kind is required")
	}
	if i.AssuranceLevel < 0 || i.AssuranceLevel > 4 {
		return errors.New("identity assurance_level must be between 0 and 4")
	}
	return nil
}

func (i Identity) HasRole(role string) bool {
	for _, candidate := range i.Roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func (i Identity) HasGroup(group string) bool {
	for _, candidate := range i.Groups {
		if candidate == group {
			return true
		}
	}
	return false
}

// Session binds requests to an identity and records security state.
type Session struct {
	ID              string            `json:"id"`
	IdentityID      string            `json:"identity_id"`
	CreatedAt       time.Time         `json:"created_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	LastSeenAt      time.Time         `json:"last_seen_at"`
	Sequence        uint64            `json:"sequence"`
	Nonce           string            `json:"nonce"`
	ParentSessionID string            `json:"parent_session_id,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	Revoked         bool              `json:"revoked"`
	RevocationNote  string            `json:"revocation_note,omitempty"`
}

func (s Session) Validate(now time.Time) error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("session id is required")
	}
	if strings.TrimSpace(s.IdentityID) == "" {
		return errors.New("session identity_id is required")
	}
	if s.CreatedAt.IsZero() || s.ExpiresAt.IsZero() {
		return errors.New("session created_at and expires_at are required")
	}
	if !s.ExpiresAt.After(s.CreatedAt) {
		return errors.New("session expires_at must follow created_at")
	}
	if s.Revoked {
		return errors.New("session is revoked")
	}
	if !now.Before(s.ExpiresAt) {
		return errors.New("session is expired")
	}
	if now.Before(s.CreatedAt) {
		return errors.New("session is not active yet")
	}
	return nil
}

// CapabilityGrant authorizes a bounded set of operations.
type CapabilityGrant struct {
	ID             string            `json:"id"`
	SubjectID      string            `json:"subject_id"`
	SessionID      string            `json:"session_id,omitempty"`
	Capabilities   []string          `json:"capabilities"`
	ResourceScopes []string          `json:"resource_scopes,omitempty"`
	ToolScopes     []string          `json:"tool_scopes,omitempty"`
	Constraints    map[string]string `json:"constraints,omitempty"`
	IssuedAt       time.Time         `json:"issued_at"`
	NotBefore      time.Time         `json:"not_before"`
	ExpiresAt      time.Time         `json:"expires_at"`
	MaxUses        uint64            `json:"max_uses,omitempty"`
	Uses           uint64            `json:"uses,omitempty"`
	Delegable      bool              `json:"delegable"`
	Revoked        bool              `json:"revoked"`
}

func (g CapabilityGrant) Validate(now time.Time) error {
	if g.ID == "" || g.SubjectID == "" {
		return errors.New("grant id and subject_id are required")
	}
	if len(g.Capabilities) == 0 {
		return errors.New("grant must contain capabilities")
	}
	if g.Revoked {
		return errors.New("grant is revoked")
	}
	if !g.NotBefore.IsZero() && now.Before(g.NotBefore) {
		return errors.New("grant is not active yet")
	}
	if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
		return errors.New("grant is expired")
	}
	if g.MaxUses > 0 && g.Uses >= g.MaxUses {
		return errors.New("grant use limit exhausted")
	}
	return nil
}

func (g CapabilityGrant) HasCapability(capability string) bool {
	for _, candidate := range g.Capabilities {
		if candidate == capability || candidate == "*" {
			return true
		}
	}
	return false
}

// ToolCall is the normalized operation evaluated by AgentGuard.
type ToolCall struct {
	ID          string          `json:"id"`
	Tool        string          `json:"tool"`
	Operation   string          `json:"operation"`
	Capability  string          `json:"capability"`
	Resource    string          `json:"resource,omitempty"`
	Destination string          `json:"destination,omitempty"`
	Arguments   json.RawMessage `json:"arguments"`
	Content     string          `json:"content,omitempty"`
	Labels      []string        `json:"labels,omitempty"`
}

func (c ToolCall) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("tool call id is required")
	}
	if strings.TrimSpace(c.Tool) == "" {
		return errors.New("tool is required")
	}
	if strings.TrimSpace(c.Operation) == "" {
		return errors.New("operation is required")
	}
	if strings.TrimSpace(c.Capability) == "" {
		return errors.New("capability is required")
	}
	if len(c.Arguments) == 0 {
		c.Arguments = json.RawMessage("{}")
	}
	var object map[string]any
	if err := json.Unmarshal(c.Arguments, &object); err != nil {
		return fmt.Errorf("arguments must be a JSON object: %w", err)
	}
	return nil
}

// EvaluationRequest contains all deterministic inputs. EvaluatedAt is explicit.
type EvaluationRequest struct {
	RequestID   string            `json:"request_id"`
	EvaluatedAt time.Time         `json:"evaluated_at"`
	Identity    Identity          `json:"identity"`
	Session     Session           `json:"session"`
	Grants      []CapabilityGrant `json:"grants,omitempty"`
	Call        ToolCall          `json:"call"`
	Approvals   []Approval        `json:"approvals,omitempty"`
	Context     map[string]string `json:"context,omitempty"`
	Prompt      string            `json:"prompt,omitempty"`
}

func (r EvaluationRequest) Validate() error {
	if r.RequestID == "" {
		return errors.New("request_id is required")
	}
	if r.EvaluatedAt.IsZero() {
		return errors.New("evaluated_at is required for deterministic evaluation")
	}
	if err := r.Identity.Validate(); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if r.Session.IdentityID != r.Identity.ID {
		return errors.New("session identity does not match request identity")
	}
	if err := r.Session.Validate(r.EvaluatedAt); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	if err := r.Call.Validate(); err != nil {
		return fmt.Errorf("call: %w", err)
	}
	return nil
}

// Finding is stable evidence contributing to a decision.
type Finding struct {
	Code       string            `json:"code"`
	Category   string            `json:"category"`
	Risk       Risk              `json:"risk"`
	Message    string            `json:"message"`
	RuleID     string            `json:"rule_id,omitempty"`
	Location   string            `json:"location,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// DecisionResult is complete, sorted, and replayable.
type DecisionResult struct {
	RequestID       string    `json:"request_id"`
	PolicyID        string    `json:"policy_id"`
	PolicyVersion   string    `json:"policy_version"`
	Decision        Decision  `json:"decision"`
	Risk            Risk      `json:"risk"`
	Reasons         []string  `json:"reasons"`
	MatchedRules    []string  `json:"matched_rules,omitempty"`
	Findings        []Finding `json:"findings,omitempty"`
	GrantIDs        []string  `json:"grant_ids,omitempty"`
	ApprovalID      string    `json:"approval_id,omitempty"`
	Fingerprint     string    `json:"fingerprint"`
	EvaluatedAt     time.Time `json:"evaluated_at"`
	EvaluationNanos int64     `json:"evaluation_nanos,omitempty"`
}

func (r *DecisionResult) Normalize() {
	sort.Strings(r.Reasons)
	sort.Strings(r.MatchedRules)
	sort.Strings(r.GrantIDs)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Code != r.Findings[j].Code {
			return r.Findings[i].Code < r.Findings[j].Code
		}
		if r.Findings[i].Location != r.Findings[j].Location {
			return r.Findings[i].Location < r.Findings[j].Location
		}
		return r.Findings[i].Message < r.Findings[j].Message
	})
}

// Approval captures a human or service authorization for one action.
type Approval struct {
	ID          string            `json:"id"`
	RequestID   string            `json:"request_id"`
	CallID      string            `json:"call_id"`
	SubjectID   string            `json:"subject_id"`
	ApproverID  string            `json:"approver_id"`
	Status      string            `json:"status"`
	Reason      string            `json:"reason"`
	CreatedAt   time.Time         `json:"created_at"`
	DecidedAt   time.Time         `json:"decided_at,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at"`
	PolicyID    string            `json:"policy_id"`
	Constraints map[string]string `json:"constraints,omitempty"`
	Signature   string            `json:"signature,omitempty"`
}

func (a Approval) ValidFor(r EvaluationRequest, policyID string) error {
	if a.Status != "approved" {
		return fmt.Errorf("approval status is %q", a.Status)
	}
	if a.RequestID != r.RequestID || a.CallID != r.Call.ID || a.SubjectID != r.Identity.ID {
		return errors.New("approval scope does not match request")
	}
	if a.PolicyID != policyID {
		return errors.New("approval policy does not match")
	}
	if !r.EvaluatedAt.Before(a.ExpiresAt) {
		return errors.New("approval is expired")
	}
	if a.DecidedAt.After(r.EvaluatedAt) {
		return errors.New("approval was decided after evaluation time")
	}
	return nil
}

// AuditEvent is chained by Hash and PreviousHash.
type AuditEvent struct {
	Sequence     uint64          `json:"sequence"`
	Timestamp    time.Time       `json:"timestamp"`
	Type         string          `json:"type"`
	RequestID    string          `json:"request_id,omitempty"`
	SessionID    string          `json:"session_id,omitempty"`
	ActorID      string          `json:"actor_id,omitempty"`
	PolicyID     string          `json:"policy_id,omitempty"`
	Payload      json.RawMessage `json:"payload"`
	PreviousHash string          `json:"previous_hash"`
	Hash         string          `json:"hash"`
}

func SortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
