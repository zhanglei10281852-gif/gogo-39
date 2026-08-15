// Package report aggregates and renders AgentGuard decision results.
package report

import (
	"time"

	"agentguard/model"
)

// Report is a deterministic, structured summary of decision results.
type Report struct {
	Total             int              `json:"total"`
	TimeRange         TimeRange        `json:"time_range"`
	Evaluation        DurationSummary  `json:"evaluation"`
	Decisions         []CountRatio     `json:"decisions"`
	Risks             []CountRatio     `json:"risks"`
	Policies          []PolicySummary  `json:"policies,omitempty"`
	Rules             []RuleSummary    `json:"rules,omitempty"`
	FindingCategories []FindingSummary `json:"finding_categories,omitempty"`
	FindingCodes      []FindingSummary `json:"finding_codes,omitempty"`
	Results           []ResultSummary  `json:"results,omitempty"`
}

// TimeRange describes the inclusive range of non-zero evaluation times.
type TimeRange struct {
	Start time.Time `json:"start,omitempty"`
	End   time.Time `json:"end,omitempty"`
}

// DurationSummary contains aggregate evaluation timing in nanoseconds.
type DurationSummary struct {
	TotalNanos int64   `json:"total_nanos"`
	MinNanos   int64   `json:"min_nanos"`
	MaxNanos   int64   `json:"max_nanos"`
	MeanNanos  float64 `json:"mean_nanos"`
	Measured   int     `json:"measured"`
}

// CountRatio is a named count and its fraction of all results.
type CountRatio struct {
	Name    string  `json:"name"`
	Count   int     `json:"count"`
	Ratio   float64 `json:"ratio"`
	Percent float64 `json:"percent"`
}

// PolicySummary counts results for one policy identity and version.
type PolicySummary struct {
	PolicyID      string  `json:"policy_id"`
	PolicyVersion string  `json:"policy_version"`
	Count         int     `json:"count"`
	Ratio         float64 `json:"ratio"`
	Percent       float64 `json:"percent"`
}

// RuleSummary counts distinct result matches for a rule.
type RuleSummary struct {
	RuleID         string  `json:"rule_id"`
	MatchedResults int     `json:"matched_results"`
	MatchRatio     float64 `json:"match_ratio"`
	MatchPercent   float64 `json:"match_percent"`
	FindingCount   int     `json:"finding_count"`
	HighestRisk    string  `json:"highest_risk"`
}

// FindingSummary counts finding occurrences and affected results.
type FindingSummary struct {
	Name            string  `json:"name"`
	Occurrences     int     `json:"occurrences"`
	AffectedResults int     `json:"affected_results"`
	AffectedRatio   float64 `json:"affected_ratio"`
	AffectedPercent float64 `json:"affected_percent"`
	HighestRisk     string  `json:"highest_risk"`
}

// ResultSummary preserves reportable detail without mutating source results.
type ResultSummary struct {
	RequestID       string          `json:"request_id"`
	PolicyID        string          `json:"policy_id"`
	PolicyVersion   string          `json:"policy_version"`
	Decision        model.Decision  `json:"decision"`
	Risk            model.Risk      `json:"risk"`
	Reasons         []string        `json:"reasons,omitempty"`
	MatchedRules    []string        `json:"matched_rules,omitempty"`
	Findings        []FindingDetail `json:"findings,omitempty"`
	GrantIDs        []string        `json:"grant_ids,omitempty"`
	ApprovalID      string          `json:"approval_id,omitempty"`
	Fingerprint     string          `json:"fingerprint"`
	EvaluatedAt     time.Time       `json:"evaluated_at"`
	EvaluationNanos int64           `json:"evaluation_nanos,omitempty"`
}

// FindingDetail is a deterministic copy of a model finding.
type FindingDetail struct {
	Code       string      `json:"code"`
	Category   string      `json:"category"`
	Risk       model.Risk  `json:"risk"`
	Message    string      `json:"message"`
	RuleID     string      `json:"rule_id,omitempty"`
	Location   string      `json:"location,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
}

// Attribute represents one sorted finding attribute.
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
