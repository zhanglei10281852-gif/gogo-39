package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"agentguard/model"
)

func pointer[T any](value T) *T { return &value }

func testRequest() model.EvaluationRequest {
	now := time.Date(2026, 8, 17, 10, 30, 0, 0, time.UTC) // Monday.
	return model.EvaluationRequest{
		RequestID: "req-1", EvaluatedAt: now,
		Identity: model.Identity{
			ID: "user-1", Kind: "human", Issuer: "local", Authenticated: true,
			AssuranceLevel: 3, Roles: []string{"developer", "operator"},
			Groups: []string{"engineering"}, Attributes: map[string]string{"region": "eu"},
		},
		Session: model.Session{
			ID: "session-1", IdentityID: "user-1", CreatedAt: now.Add(-time.Hour),
			ExpiresAt: now.Add(time.Hour), LastSeenAt: now, Sequence: 7,
			Nonce: "nonce", Tags: map[string]string{"device": "managed"},
		},
		Call: model.ToolCall{
			ID: "call-1", Tool: "shell.exec", Operation: "write", Capability: "filesystem.write",
			Resource: "/prod/config", Destination: "host.internal", Arguments: []byte(`{"force":false}`),
		},
		Context: map[string]string{"environment": "production"},
	}
}

func emptyPolicy(effect Effect) Policy {
	return Policy{ID: "policy-1", Version: "1", DefaultEffect: effect, Rules: []Rule{}}
}

func TestParseStrictAndValidation(t *testing.T) {
	valid := `{
		"id":"p","version":"1","default_effect":"deny","rules":[{
			"id":"allow-read","effect":"allow","condition":{
				"tool":{"one_of":["fs"]},"operation":{"equals":"read"}
			}
		}]
	}`
	policy, err := Parse([]byte(valid))
	if err != nil {
		t.Fatalf("Parse(valid): %v", err)
	}
	if policy.Rules[0].ID != "allow-read" {
		t.Fatalf("unexpected policy: %#v", policy)
	}

	cases := []struct{ name, input, want string }{
		{"unknown policy field", `{"id":"p","version":"1","default_effect":"deny","rules":[],"extra":1}`, "unknown field"},
		{"unknown condition field", `{"id":"p","version":"1","default_effect":"deny","rules":[{"id":"r","effect":"deny","condition":{"tools":[]}}]}`, "unknown field"},
		{"trailing JSON", valid + ` {}`, "trailing value"},
		{"missing rules", `{"id":"p","version":"1","default_effect":"deny"}`, "rules is required"},
		{"empty condition", `{"id":"p","version":"1","default_effect":"deny","rules":[{"id":"r","effect":"deny","condition":{}}]}`, "must contain"},
		{"duplicate rule", `{"id":"p","version":"1","default_effect":"deny","rules":[{"id":"r","effect":"deny","condition":{"tool":{"equals":"a"}}},{"id":"r","effect":"allow","condition":{"tool":{"equals":"b"}}}]}`, "duplicate rule"},
		{"bad pattern", `{"id":"p","version":"1","default_effect":"deny","rules":[{"id":"r","effect":"deny","condition":{"tool":{"patterns":["["]}}}]}`, "syntax error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.input))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateConditionBounds(t *testing.T) {
	policy := emptyPolicy(EffectAllow)
	policy.Rules = []Rule{{
		ID: "bad", Effect: EffectDeny,
		Condition: Condition{Identity: &IdentityCondition{
			MinAssuranceLevel: pointer(4), MaxAssuranceLevel: pointer(2),
		}},
	}}
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Validate() = %v, want assurance bounds error", err)
	}

	policy.Rules[0].Condition = Condition{Time: &TimeCondition{DailyStart: "09:00"}}
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "supplied together") {
		t.Fatalf("Validate() = %v, want paired daily times", err)
	}

	negative := int64(-1)
	policy.Rules[0].Condition = Condition{Session: &SessionCondition{MinAgeSeconds: &negative}}
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("Validate() = %v, want duration bounds", err)
	}
}

func TestAllConditionFamiliesAndUsableGrant(t *testing.T) {
	request := testRequest()
	request.Grants = []model.CapabilityGrant{{
		ID: "grant-1", SubjectID: request.Identity.ID, SessionID: request.Session.ID,
		Capabilities: []string{"filesystem.write"}, ToolScopes: []string{"shell.*"},
		ResourceScopes: []string{"/prod/*"}, Constraints: map[string]string{"environment": "production"},
		IssuedAt: request.EvaluatedAt.Add(-time.Hour), NotBefore: request.EvaluatedAt.Add(-time.Minute),
		ExpiresAt: request.EvaluatedAt.Add(time.Hour), Delegable: false,
	}}
	finding := model.Finding{
		Code: "SECRET", Category: "sensitive_data", Risk: model.RiskHigh,
		Location: "arguments.token", Attributes: map[string]string{"confidence": "high"},
	}
	condition := Condition{
		Tool:        &StringCondition{Patterns: []string{"shell.*"}},
		Operation:   &StringCondition{OneOf: []string{"write", "delete"}},
		Resource:    &StringCondition{Prefixes: []string{"/prod/"}},
		Destination: &StringCondition{Suffixes: []string{".internal"}},
		Identity: &IdentityCondition{
			ID: &StringCondition{Equals: pointer("user-1")}, Authenticated: pointer(true),
			MinAssuranceLevel: pointer(2), Roles: &SetCondition{All: []string{"developer", "operator"}},
			Groups:     &SetCondition{Any: []string{"engineering"}},
			Attributes: map[string]StringCondition{"region": {OneOf: []string{"eu", "us"}}},
		},
		Session: &SessionCondition{
			MinSequence: pointer(uint64(5)), MinAgeSeconds: pointer(int64(300)),
			MinRemainingSeconds: pointer(int64(300)),
			Tags:                map[string]StringCondition{"device": {Equals: pointer("managed")}},
		},
		Capability: &CapabilityCondition{
			Name: &StringCondition{Equals: pointer("filesystem.write")}, RequireGrant: true,
			GrantIDs: &SetCondition{Any: []string{"grant-1"}}, MinValidGrants: pointer(1),
			Constraints: map[string]StringCondition{"environment": {Equals: pointer("production")}},
		},
		Risk: &RiskCondition{Minimum: model.RiskMedium, Maximum: model.RiskCritical, MinFindings: pointer(1)},
		Time: &TimeCondition{Weekdays: []string{"mon"}, DailyStart: "09:00", DailyEnd: "17:00"},
		Finding: &FindingCondition{
			Codes: &SetCondition{Any: []string{"SECRET"}}, Categories: &SetCondition{Any: []string{"sensitive_data"}},
			Risks: []model.Risk{model.RiskHigh}, Location: &StringCondition{Prefixes: []string{"arguments."}},
			Attributes: map[string]StringCondition{"confidence": {Equals: pointer("high")}},
		},
		Context: map[string]StringCondition{"environment": {Equals: pointer("production")}},
		All:     []Condition{{Not: &Condition{Tool: &StringCondition{Equals: pointer("browser")}}}},
	}
	policy := emptyPolicy(EffectAllow)
	policy.Rules = []Rule{{ID: "deny-sensitive-prod-write", Priority: 100, Effect: EffectDeny, Condition: condition}}
	result, err := Evaluate(policy, request, []model.Finding{finding})
	if err != nil {
		t.Fatalf("Evaluate(): %v", err)
	}
	if result.Decision != model.DecisionDeny {
		t.Fatalf("decision = %q, want deny", result.Decision)
	}
	if result.Risk != model.RiskHigh {
		t.Fatalf("risk = %q, want high", result.Risk)
	}
	if len(result.GrantIDs) != 1 || result.GrantIDs[0] != "grant-1" {
		t.Fatalf("grant IDs = %v", result.GrantIDs)
	}

	request.Grants[0].ResourceScopes = []string{"/staging/*"}
	result, err = Evaluate(policy, request, []model.Finding{finding})
	if err != nil {
		t.Fatalf("Evaluate(scope mismatch): %v", err)
	}
	if result.Decision != model.DecisionAllow {
		t.Fatalf("scope mismatch decision = %q, want default allow", result.Decision)
	}
}

func validApproval(request model.EvaluationRequest) model.Approval {
	return model.Approval{
		ID: "approval-1", RequestID: request.RequestID, CallID: request.Call.ID,
		SubjectID: request.Identity.ID, ApproverID: "security-1", Status: "approved",
		Reason: "change approved", CreatedAt: request.EvaluatedAt.Add(-10 * time.Minute),
		DecidedAt: request.EvaluatedAt.Add(-5 * time.Minute), ExpiresAt: request.EvaluatedAt.Add(time.Hour),
		PolicyID: "policy-1", Constraints: map[string]string{
			"tool": "shell.exec", "operation": "write", "context.environment": "production",
		},
	}
}

func TestRequireApprovalAndDenyPrecedence(t *testing.T) {
	request := testRequest()
	policy := emptyPolicy(EffectRequireApproval)

	result, err := Evaluate(policy, request, nil)
	if err != nil {
		t.Fatalf("Evaluate(no approval): %v", err)
	}
	if result.Decision != model.DecisionApprove {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}

	request.Approvals = []model.Approval{validApproval(request)}
	result, err = Evaluate(policy, request, nil)
	if err != nil {
		t.Fatalf("Evaluate(valid approval): %v", err)
	}
	if result.Decision != model.DecisionAllow || result.ApprovalID != "approval-1" {
		t.Fatalf("approved result = %#v", result)
	}

	request.Approvals[0].Constraints["destination"] = "wrong.example"
	result, err = Evaluate(policy, request, nil)
	if err != nil {
		t.Fatalf("Evaluate(bad constraint): %v", err)
	}
	if result.Decision != model.DecisionApprove {
		t.Fatalf("constraint mismatch decision = %q", result.Decision)
	}

	request.Approvals = []model.Approval{validApproval(request)}
	policy.Rules = []Rule{
		{ID: "approval", Priority: 100, Effect: EffectRequireApproval, Condition: Condition{Tool: &StringCondition{Equals: pointer("shell.exec")}}},
		{ID: "deny", Priority: -100, Effect: EffectDeny, Condition: Condition{Operation: &StringCondition{Equals: pointer("write")}}},
		{ID: "allow", Priority: 1000, Effect: EffectAllow, Condition: Condition{Identity: &IdentityCondition{Roles: &SetCondition{Any: []string{"developer"}}}}},
	}
	result, err = Evaluate(policy, request, nil)
	if err != nil {
		t.Fatalf("Evaluate(deny precedence): %v", err)
	}
	if result.Decision != model.DecisionDeny {
		t.Fatalf("decision = %q, deny must dominate", result.Decision)
	}
	if result.ApprovalID != "" {
		t.Fatalf("deny must not consume approval: %q", result.ApprovalID)
	}
}

func TestExpiredAndFutureApprovalsAreIneffective(t *testing.T) {
	request := testRequest()
	policy := emptyPolicy(EffectRequireApproval)
	approval := validApproval(request)
	approval.ExpiresAt = request.EvaluatedAt
	request.Approvals = []model.Approval{approval}
	result, err := Evaluate(policy, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.DecisionApprove {
		t.Fatalf("expired approval decision = %q", result.Decision)
	}

	approval = validApproval(request)
	approval.DecidedAt = request.EvaluatedAt.Add(time.Minute)
	approval.ExpiresAt = request.EvaluatedAt.Add(time.Hour)
	request.Approvals = []model.Approval{approval}
	result, err = Evaluate(policy, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.DecisionApprove {
		t.Fatalf("future approval decision = %q", result.Decision)
	}
}

func TestStablePolicyHashAndFingerprint(t *testing.T) {
	first := emptyPolicy(EffectAllow)
	first.Rules = []Rule{
		{ID: "b", Effect: EffectDeny, Condition: Condition{Tool: &StringCondition{OneOf: []string{"b", "a"}}}},
		{ID: "a", Effect: EffectAllow, Condition: Condition{Any: []Condition{
			{Operation: &StringCondition{Equals: pointer("read")}},
			{Operation: &StringCondition{Equals: pointer("write")}},
		}}},
	}
	second := emptyPolicy(EffectAllow)
	second.Rules = []Rule{
		{ID: "a", Effect: EffectAllow, Condition: Condition{Any: []Condition{
			{Operation: &StringCondition{Equals: pointer("write")}},
			{Operation: &StringCondition{Equals: pointer("read")}},
		}}},
		{ID: "b", Effect: EffectDeny, Condition: Condition{Tool: &StringCondition{OneOf: []string{"a", "b"}}}},
	}

	hash1, err := first.Hash()
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := PolicyHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Fatalf("semantic policy hashes differ:\n%s\n%s", hash1, hash2)
	}
	if len(hash1) != 64 {
		t.Fatalf("hash length = %d", len(hash1))
	}

	request1 := testRequest()
	request1.Identity.Roles = []string{"operator", "developer"}
	request1.Call.Arguments = []byte(`{ "force" : false }`)
	request2 := testRequest()
	findings1 := []model.Finding{
		{Code: "B", Category: "test", Risk: model.RiskLow, Message: "second"},
		{Code: "A", Category: "test", Risk: model.RiskMedium, Message: "first"},
	}
	findings2 := []model.Finding{findings1[1], findings1[0]}
	result1, err := Evaluate(first, request1, findings1)
	if err != nil {
		t.Fatal(err)
	}
	result2, err := Evaluate(second, request2, findings2)
	if err != nil {
		t.Fatal(err)
	}
	if result1.Fingerprint != result2.Fingerprint {
		t.Fatalf("stable fingerprints differ:\n%s\n%s", result1.Fingerprint, result2.Fingerprint)
	}
	result1.EvaluationNanos = 999
	recomputed, err := Fingerprint(first, request1, result1)
	if err != nil {
		t.Fatal(err)
	}
	if recomputed != result1.Fingerprint {
		t.Fatalf("recomputed fingerprint = %s, want %s", recomputed, result1.Fingerprint)
	}
}

func TestFindingProviderAndDefaultEffects(t *testing.T) {
	request := testRequest()
	called := false
	provider := FindingProviderFunc(func(ctx context.Context, got model.EvaluationRequest) ([]model.Finding, error) {
		called = true
		if got.RequestID != request.RequestID {
			t.Fatalf("provider request = %q", got.RequestID)
		}
		return []model.Finding{{Code: "INJECTION", Category: "prompt", Risk: model.RiskCritical}}, nil
	})
	policy := emptyPolicy(EffectAllow)
	policy.Rules = []Rule{{
		ID: "critical-deny", Effect: EffectDeny,
		Condition: Condition{Risk: &RiskCondition{Minimum: model.RiskHigh}},
	}}
	result, err := (Evaluator{Policy: policy, Provider: provider}).Evaluate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("provider was not called")
	}
	if result.Decision != model.DecisionDeny || result.Risk != model.RiskCritical {
		t.Fatalf("provider result = %#v", result)
	}

	providerErr := errors.New("scanner unavailable")
	_, err = (Evaluator{Policy: policy, Provider: FindingProviderFunc(
		func(context.Context, model.EvaluationRequest) ([]model.Finding, error) { return nil, providerErr },
	)}).Evaluate(context.Background(), request)
	if !errors.Is(err, providerErr) {
		t.Fatalf("provider error = %v", err)
	}

	for _, effect := range []Effect{EffectAllow, EffectDeny, EffectRequireApproval} {
		result, err := Evaluate(emptyPolicy(effect), request, nil)
		if err != nil {
			t.Fatalf("default %s: %v", effect, err)
		}
		if model.Decision(effect) != result.Decision {
			t.Fatalf("default %s produced %s", effect, result.Decision)
		}
	}
}

func TestFindingAbsenceAndCombinators(t *testing.T) {
	request := testRequest()
	zero := 0
	policy := emptyPolicy(EffectAllow)
	policy.Rules = []Rule{{
		ID: "deny-when-no-secret", Effect: EffectDeny,
		Condition: Condition{
			Finding: &FindingCondition{Codes: &SetCondition{Any: []string{"SECRET"}}, MaxCount: &zero},
			Any: []Condition{
				{Tool: &StringCondition{Equals: pointer("shell.exec")}},
				{Tool: &StringCondition{Equals: pointer("browser")}},
			},
		},
	}}
	result, err := Evaluate(policy, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.DecisionDeny {
		t.Fatalf("absence rule decision = %q", result.Decision)
	}
	result, err = Evaluate(policy, request, []model.Finding{{Code: "SECRET", Category: "data", Risk: model.RiskHigh}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.DecisionAllow {
		t.Fatalf("present finding decision = %q", result.Decision)
	}
}

func TestFingerprintDoesNotMutateInputs(t *testing.T) {
	policy := emptyPolicy(EffectAllow)
	request := testRequest()
	request.Identity.Roles = []string{"z-role", "a-role"}
	request.Call.Labels = []string{"z-label", "a-label"}
	request.Grants = []model.CapabilityGrant{
		{ID: "z-grant", Capabilities: []string{"z", "a"}},
		{ID: "a-grant", Capabilities: []string{"b", "a"}},
	}
	request.Approvals = []model.Approval{{ID: "z-approval"}, {ID: "a-approval"}}
	result := model.DecisionResult{
		RequestID: request.RequestID, PolicyID: policy.ID, PolicyVersion: policy.Version,
		Decision: model.DecisionAllow, Risk: model.RiskNone, EvaluatedAt: request.EvaluatedAt,
		Reasons: []string{"z-reason", "a-reason"}, MatchedRules: []string{"z-rule", "a-rule"},
		GrantIDs: []string{"z-grant", "a-grant"},
		Findings: []model.Finding{
			{Code: "Z", Category: "test", Risk: model.RiskLow},
			{Code: "A", Category: "test", Risk: model.RiskLow},
		},
	}

	if _, err := Fingerprint(policy, request, result); err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if request.Identity.Roles[0] != "z-role" || request.Call.Labels[0] != "z-label" {
		t.Fatalf("request slices mutated: roles=%v labels=%v", request.Identity.Roles, request.Call.Labels)
	}
	if request.Grants[0].ID != "z-grant" || request.Approvals[0].ID != "z-approval" {
		t.Fatalf("request collections mutated: grants=%v approvals=%v", request.Grants, request.Approvals)
	}
	if result.Reasons[0] != "z-reason" || result.MatchedRules[0] != "z-rule" || result.GrantIDs[0] != "z-grant" {
		t.Fatalf("result slices mutated: %#v", result)
	}
	if result.Findings[0].Code != "Z" {
		t.Fatalf("result findings mutated: %v", result.Findings)
	}
}
