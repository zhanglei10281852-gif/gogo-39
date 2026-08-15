package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"agentguard/model"
	"agentguard/strictjson"
)

// Decode reads exactly one strict JSON policy and validates it.
func Decode(reader io.Reader) (Policy, error) {
	var policy Policy
	if err := strictjson.Decode(reader, &policy); err != nil {
		return Policy{}, err
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, fmt.Errorf("validate policy: %w", err)
	}
	return policy, nil
}

// Parse decodes and validates a strict JSON policy.
func Parse(data []byte) (Policy, error) {
	var policy Policy
	if err := strictjson.DecodeBytes(data, &policy); err != nil {
		return Policy{}, err
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, fmt.Errorf("validate policy: %w", err)
	}
	return policy, nil
}

// Load decodes and validates a strict JSON policy file.
func Load(path string) (Policy, error) {
	var policy Policy
	if err := strictjson.DecodeFile(path, &policy); err != nil {
		return Policy{}, err
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, fmt.Errorf("validate policy: %w", err)
	}
	return policy, nil
}

// Evaluate validates all inputs and returns a deterministic decision.
func Evaluate(policy Policy, request model.EvaluationRequest, findings []model.Finding) (model.DecisionResult, error) {
	if err := policy.Validate(); err != nil {
		return model.DecisionResult{}, fmt.Errorf("policy: %w", err)
	}
	if err := request.Validate(); err != nil {
		return model.DecisionResult{}, fmt.Errorf("request: %w", err)
	}
	if err := validateFindings(findings); err != nil {
		return model.DecisionResult{}, err
	}

	findings = cloneFindings(findings)
	risk := highestRisk(findings)
	grants := usableGrants(request)
	input := matchInput{request: request, findings: findings, grants: grants, risk: risk}

	matched := make([]Rule, 0, len(policy.Rules))
	for _, rule := range policy.Rules {
		if rule.Condition.matches(input) {
			matched = append(matched, rule)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Priority != matched[j].Priority {
			return matched[i].Priority > matched[j].Priority
		}
		return matched[i].ID < matched[j].ID
	})

	effect := policy.DefaultEffect
	if len(matched) > 0 {
		effect = selectEffect(matched)
	}
	result := model.DecisionResult{
		RequestID: request.RequestID, PolicyID: policy.ID, PolicyVersion: policy.Version,
		Risk: risk, Findings: findings, EvaluatedAt: request.EvaluatedAt,
	}
	for _, grant := range grants {
		result.GrantIDs = append(result.GrantIDs, grant.ID)
	}
	if len(matched) == 0 {
		result.Reasons = append(result.Reasons, "policy default: "+string(effect))
	} else {
		for _, rule := range matched {
			result.MatchedRules = append(result.MatchedRules, rule.ID)
			if rule.Reason != "" {
				result.Reasons = append(result.Reasons, rule.Reason)
			} else {
				result.Reasons = append(result.Reasons, "matched rule "+rule.ID+": "+string(rule.Effect))
			}
		}
	}

	switch effect {
	case EffectDeny:
		result.Decision = model.DecisionDeny
	case EffectAllow:
		result.Decision = model.DecisionAllow
	case EffectRequireApproval:
		approval := effectiveApproval(request, policy.ID, risk)
		if approval == nil {
			result.Decision = model.DecisionApprove
			result.Reasons = append(result.Reasons, "valid approval required")
		} else {
			result.Decision = model.DecisionAllow
			result.ApprovalID = approval.ID
			result.Reasons = append(result.Reasons, "approval "+approval.ID+" accepted")
		}
	default:
		return model.DecisionResult{}, errors.New("internal error: unsupported effect")
	}
	result.Normalize()
	fingerprint, err := resultFingerprint(policy, request, result)
	if err != nil {
		return model.DecisionResult{}, err
	}
	result.Fingerprint = fingerprint
	return result, nil
}

// Evaluate obtains findings from the optional provider and evaluates the request.
func (e Evaluator) Evaluate(ctx context.Context, request model.EvaluationRequest) (model.DecisionResult, error) {
	var findings []model.Finding
	if e.Provider != nil {
		var err error
		findings, err = e.Provider.Findings(ctx, request)
		if err != nil {
			return model.DecisionResult{}, fmt.Errorf("provide findings: %w", err)
		}
	}
	return Evaluate(e.Policy, request, findings)
}

func selectEffect(rules []Rule) Effect {
	selected := EffectAllow
	for _, rule := range rules {
		if rule.Effect == EffectDeny {
			return EffectDeny
		}
		if rule.Effect == EffectRequireApproval {
			selected = EffectRequireApproval
		}
	}
	return selected
}

func validateFindings(findings []model.Finding) error {
	for i, finding := range findings {
		if strings.TrimSpace(finding.Code) == "" {
			return fmt.Errorf("findings[%d]: code is required", i)
		}
		if strings.TrimSpace(finding.Category) == "" {
			return fmt.Errorf("findings[%d]: category is required", i)
		}
		if finding.Risk.Rank() < 0 {
			return fmt.Errorf("findings[%d]: invalid risk %q", i, finding.Risk)
		}
	}
	return nil
}

func highestRisk(findings []model.Finding) model.Risk {
	risk := model.RiskNone
	for _, finding := range findings {
		if finding.Risk.Rank() > risk.Rank() {
			risk = finding.Risk
		}
	}
	return risk
}

func effectiveApproval(request model.EvaluationRequest, policyID string, risk model.Risk) *model.Approval {
	valid := make([]model.Approval, 0, len(request.Approvals))
	for _, approval := range request.Approvals {
		if approval.ValidFor(request, policyID) != nil {
			continue
		}
		if strings.TrimSpace(approval.ID) == "" || strings.TrimSpace(approval.ApproverID) == "" {
			continue
		}
		if approval.DecidedAt.IsZero() || approval.CreatedAt.IsZero() {
			continue
		}
		if approval.CreatedAt.After(approval.DecidedAt) || approval.DecidedAt.After(request.EvaluatedAt) {
			continue
		}
		if !approval.ExpiresAt.After(approval.DecidedAt) {
			continue
		}
		if !approvalConstraintsMatch(approval.Constraints, request, risk) {
			continue
		}
		valid = append(valid, approval)
	}
	if len(valid) == 0 {
		return nil
	}
	sort.Slice(valid, func(i, j int) bool {
		if !valid[i].DecidedAt.Equal(valid[j].DecidedAt) {
			return valid[i].DecidedAt.Before(valid[j].DecidedAt)
		}
		return valid[i].ID < valid[j].ID
	})
	return &valid[0]
}

func approvalConstraintsMatch(constraints map[string]string, request model.EvaluationRequest, risk model.Risk) bool {
	for key, expected := range constraints {
		var actual string
		switch {
		case key == "tool":
			actual = request.Call.Tool
		case key == "operation":
			actual = request.Call.Operation
		case key == "resource":
			actual = request.Call.Resource
		case key == "destination":
			actual = request.Call.Destination
		case key == "capability":
			actual = request.Call.Capability
		case key == "risk":
			actual = string(risk)
		case key == "identity.kind":
			actual = request.Identity.Kind
		case strings.HasPrefix(key, "context."):
			var ok bool
			actual, ok = request.Context[strings.TrimPrefix(key, "context.")]
			if !ok {
				return false
			}
		case strings.HasPrefix(key, "identity.attribute."):
			var ok bool
			actual, ok = request.Identity.Attributes[strings.TrimPrefix(key, "identity.attribute.")]
			if !ok {
				return false
			}
		default:
			return false
		}
		if actual != expected {
			return false
		}
	}
	return true
}

// Hash returns the SHA-256 hash of the canonical normalized policy.
func (p Policy) Hash() (string, error) { return PolicyHash(p) }

// PolicyHash validates and hashes a normalized policy representation.
func PolicyHash(policy Policy) (string, error) {
	if err := policy.Validate(); err != nil {
		return "", fmt.Errorf("policy: %w", err)
	}
	normalized, err := normalizedPolicy(policy)
	if err != nil {
		return "", err
	}
	return hashCanonical(normalized)
}

// Fingerprint recomputes the stable fingerprint for a result. EvaluationNanos
// and an existing Fingerprint value are intentionally excluded.
func Fingerprint(policy Policy, request model.EvaluationRequest, result model.DecisionResult) (string, error) {
	return resultFingerprint(policy, request, result)
}

func resultFingerprint(policy Policy, request model.EvaluationRequest, result model.DecisionResult) (string, error) {
	policyHash, err := PolicyHash(policy)
	if err != nil {
		return "", err
	}
	normalizeRequest(&request)
	copyResult := result
	// The result is also passed by value, but Normalize sorts slices in place.
	// Detach them first so Fingerprint never mutates caller-owned storage.
	copyResult.Reasons = append([]string(nil), result.Reasons...)
	copyResult.MatchedRules = append([]string(nil), result.MatchedRules...)
	copyResult.GrantIDs = append([]string(nil), result.GrantIDs...)
	copyResult.Findings = cloneFindings(result.Findings)
	copyResult.Fingerprint = ""
	copyResult.EvaluationNanos = 0
	copyResult.Normalize()
	payload := struct {
		PolicyHash string                  `json:"policy_hash"`
		Request    model.EvaluationRequest `json:"request"`
		Result     model.DecisionResult    `json:"result"`
	}{policyHash, request, copyResult}
	return hashCanonical(payload)
}

func hashCanonical(value any) (string, error) {
	data, err := strictjson.MarshalCanonical(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func cloneFindings(findings []model.Finding) []model.Finding {
	out := append([]model.Finding(nil), findings...)
	for i := range out {
		if out[i].Attributes != nil {
			attributes := make(map[string]string, len(out[i].Attributes))
			for key, value := range out[i].Attributes {
				attributes[key] = value
			}
			out[i].Attributes = attributes
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		if out[i].Location != out[j].Location {
			return out[i].Location < out[j].Location
		}
		if out[i].Message != out[j].Message {
			return out[i].Message < out[j].Message
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
