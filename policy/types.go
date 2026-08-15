// Package policy implements deterministic policy parsing, validation, and evaluation.
package policy

import (
	"context"
	"time"

	"agentguard/model"
)

// Effect is the outcome contributed by a rule or policy default.
type Effect string

const (
	EffectAllow           Effect = "allow"
	EffectDeny            Effect = "deny"
	EffectRequireApproval Effect = "require_approval"
)

// Policy is a complete, versioned set of deterministic rules.
type Policy struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	Description   string `json:"description,omitempty"`
	DefaultEffect Effect `json:"default_effect"`
	Rules         []Rule `json:"rules"`
}

// Rule contributes an effect when its condition matches.
type Rule struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	Priority    int       `json:"priority,omitempty"`
	Effect      Effect    `json:"effect"`
	Reason      string    `json:"reason,omitempty"`
	Condition   Condition `json:"condition"`
}

// Condition is a strict recursive predicate. Populated fields are ANDed.
// All requires every child, Any requires at least one child, and Not negates one child.
type Condition struct {
	Tool        *StringCondition           `json:"tool,omitempty"`
	Operation   *StringCondition           `json:"operation,omitempty"`
	Resource    *StringCondition           `json:"resource,omitempty"`
	Destination *StringCondition           `json:"destination,omitempty"`
	Identity    *IdentityCondition         `json:"identity,omitempty"`
	Session     *SessionCondition          `json:"session,omitempty"`
	Capability  *CapabilityCondition       `json:"capability,omitempty"`
	Risk        *RiskCondition             `json:"risk,omitempty"`
	Time        *TimeCondition             `json:"time,omitempty"`
	Finding     *FindingCondition          `json:"finding,omitempty"`
	Context     map[string]StringCondition `json:"context,omitempty"`
	All         []Condition                `json:"all,omitempty"`
	Any         []Condition                `json:"any,omitempty"`
	Not         *Condition                 `json:"not,omitempty"`
}

// StringCondition matches a string. Positive alternatives are ORed; exclusions
// are then applied. Patterns use path.Match syntax.
type StringCondition struct {
	Equals     *string  `json:"equals,omitempty"`
	OneOf      []string `json:"one_of,omitempty"`
	NotOneOf   []string `json:"not_one_of,omitempty"`
	Prefixes   []string `json:"prefixes,omitempty"`
	Suffixes   []string `json:"suffixes,omitempty"`
	Patterns   []string `json:"patterns,omitempty"`
	IgnoreCase bool     `json:"ignore_case,omitempty"`
	Present    *bool    `json:"present,omitempty"`
}

// SetCondition matches roles, groups, labels, or other string sets.
type SetCondition struct {
	Any  []string `json:"any,omitempty"`
	All  []string `json:"all,omitempty"`
	None []string `json:"none,omitempty"`
}

// IdentityCondition matches authenticated principal properties.
type IdentityCondition struct {
	ID                *StringCondition           `json:"id,omitempty"`
	Kind              *StringCondition           `json:"kind,omitempty"`
	Issuer            *StringCondition           `json:"issuer,omitempty"`
	Authenticated     *bool                      `json:"authenticated,omitempty"`
	MinAssuranceLevel *int                       `json:"min_assurance_level,omitempty"`
	MaxAssuranceLevel *int                       `json:"max_assurance_level,omitempty"`
	Roles             *SetCondition              `json:"roles,omitempty"`
	Groups            *SetCondition              `json:"groups,omitempty"`
	Attributes        map[string]StringCondition `json:"attributes,omitempty"`
}

// SessionCondition matches request session security state and metadata.
type SessionCondition struct {
	ID                  *StringCondition           `json:"id,omitempty"`
	ParentSessionID     *StringCondition           `json:"parent_session_id,omitempty"`
	Nonce               *StringCondition           `json:"nonce,omitempty"`
	Revoked             *bool                      `json:"revoked,omitempty"`
	MinSequence         *uint64                    `json:"min_sequence,omitempty"`
	MaxSequence         *uint64                    `json:"max_sequence,omitempty"`
	MinAgeSeconds       *int64                     `json:"min_age_seconds,omitempty"`
	MaxAgeSeconds       *int64                     `json:"max_age_seconds,omitempty"`
	MinRemainingSeconds *int64                     `json:"min_remaining_seconds,omitempty"`
	MaxRemainingSeconds *int64                     `json:"max_remaining_seconds,omitempty"`
	Tags                map[string]StringCondition `json:"tags,omitempty"`
}

// CapabilityCondition matches the requested capability and usable grants.
type CapabilityCondition struct {
	Name           *StringCondition           `json:"name,omitempty"`
	RequireGrant   bool                       `json:"require_grant,omitempty"`
	GrantIDs       *SetCondition              `json:"grant_ids,omitempty"`
	MinValidGrants *int                       `json:"min_valid_grants,omitempty"`
	Delegable      *bool                      `json:"delegable,omitempty"`
	Constraints    map[string]StringCondition `json:"constraints,omitempty"`
}

// RiskCondition matches the highest supplied finding risk and finding counts.
type RiskCondition struct {
	Minimum     model.Risk `json:"minimum,omitempty"`
	Maximum     model.Risk `json:"maximum,omitempty"`
	Exact       model.Risk `json:"exact,omitempty"`
	MinFindings *int       `json:"min_findings,omitempty"`
	MaxFindings *int       `json:"max_findings,omitempty"`
}

// TimeCondition matches the explicit EvaluationRequest.EvaluatedAt timestamp.
type TimeCondition struct {
	NotBefore        *time.Time `json:"not_before,omitempty"`
	Before           *time.Time `json:"before,omitempty"`
	Weekdays         []string   `json:"weekdays,omitempty"`
	DailyStart       string     `json:"daily_start,omitempty"`
	DailyEnd         string     `json:"daily_end,omitempty"`
	UTCOffsetMinutes int        `json:"utc_offset_minutes,omitempty"`
}

// FindingCondition matches supplied findings. At least MinCount matching
// findings must exist; MinCount defaults to one.
type FindingCondition struct {
	Codes      *SetCondition              `json:"codes,omitempty"`
	Categories *SetCondition              `json:"categories,omitempty"`
	Risks      []model.Risk               `json:"risks,omitempty"`
	RuleIDs    *SetCondition              `json:"rule_ids,omitempty"`
	Location   *StringCondition           `json:"location,omitempty"`
	Attributes map[string]StringCondition `json:"attributes,omitempty"`
	MinCount   *int                       `json:"min_count,omitempty"`
	MaxCount   *int                       `json:"max_count,omitempty"`
}

// FindingProvider supplies local findings without coupling policy to classify.
type FindingProvider interface {
	Findings(context.Context, model.EvaluationRequest) ([]model.Finding, error)
}

// FindingProviderFunc adapts a function to FindingProvider.
type FindingProviderFunc func(context.Context, model.EvaluationRequest) ([]model.Finding, error)

func (f FindingProviderFunc) Findings(ctx context.Context, req model.EvaluationRequest) ([]model.Finding, error) {
	return f(ctx, req)
}

// Evaluator evaluates one validated policy. Provider is optional.
type Evaluator struct {
	Policy   Policy
	Provider FindingProvider
}
