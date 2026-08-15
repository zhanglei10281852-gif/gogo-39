package report

import (
	"reflect"
	"testing"
	"time"

	"agentguard/model"
)

func sampleResults() []model.DecisionResult {
	base := time.Date(2025, 2, 3, 4, 5, 6, 0, time.FixedZone("test", 3600))
	return []model.DecisionResult{
		{
			RequestID: "request-b", PolicyID: "policy-z", PolicyVersion: "2",
			Decision: model.DecisionApprove, Risk: model.RiskHigh,
			Reasons:      []string{"second", "first", "first"},
			MatchedRules: []string{"rule-b", "rule-a", "rule-a"},
			Findings: []model.Finding{
				{Code: "EX-1", Category: "exfiltration", Risk: model.RiskHigh, Message: "first", RuleID: "rule-a", Attributes: map[string]string{"z": "last", "a": "first"}},
				{Code: "EX-1", Category: "exfiltration", Risk: model.RiskLow, Message: "duplicate category", RuleID: "rule-a"},
			},
			Fingerprint: "fp-b", EvaluatedAt: base.Add(2 * time.Hour), EvaluationNanos: 100,
		},
		{
			RequestID: "request-a", PolicyID: "policy-a", PolicyVersion: "1",
			Decision: model.DecisionDeny, Risk: model.RiskCritical,
			Findings:    []model.Finding{{Code: "EX-1", Category: "exfiltration", Risk: model.RiskCritical, Message: "critical", RuleID: "rule-b"}},
			Fingerprint: "fp-a", EvaluatedAt: base, EvaluationNanos: 300,
		},
		{
			RequestID: "request-c", PolicyID: "policy-a", PolicyVersion: "1",
			Decision: model.DecisionAllow, Risk: model.RiskNone,
			Fingerprint: "fp-c", EvaluatedAt: base.Add(time.Hour),
		},
	}
}

func TestBuildAggregatesAndSorts(t *testing.T) {
	results := sampleResults()
	originalRules := append([]string(nil), results[0].MatchedRules...)
	got := Build(results)

	if got.Total != 3 {
		t.Fatalf("Total = %d, want 3", got.Total)
	}
	if !got.TimeRange.Start.Equal(results[1].EvaluatedAt) || !got.TimeRange.End.Equal(results[0].EvaluatedAt) {
		t.Fatalf("unexpected range: %#v", got.TimeRange)
	}
	if got.Evaluation.Measured != 2 || got.Evaluation.TotalNanos != 400 || got.Evaluation.MinNanos != 100 || got.Evaluation.MaxNanos != 300 || got.Evaluation.MeanNanos != 200 {
		t.Fatalf("unexpected evaluation summary: %#v", got.Evaluation)
	}
	if !reflect.DeepEqual(results[0].MatchedRules, originalRules) {
		t.Fatalf("Build mutated source rules: %v", results[0].MatchedRules)
	}
	for _, value := range got.Decisions {
		if value.Count != 1 || value.Ratio != 1.0/3.0 {
			t.Errorf("decision %#v", value)
		}
	}
	if ids := []string{got.Results[0].RequestID, got.Results[1].RequestID, got.Results[2].RequestID}; !reflect.DeepEqual(ids, []string{"request-a", "request-c", "request-b"}) {
		t.Fatalf("result order = %v", ids)
	}
}
func TestBuildAggregatesRulesAndFindings(t *testing.T) {
	got := Build(sampleResults())
	if len(got.Rules) != 2 {
		t.Fatalf("rules = %#v", got.Rules)
	}
	ratioOne := 1.0 / 3.0
	ratioTwo := 2.0 / 3.0
	wantRules := []RuleSummary{
		{RuleID: "rule-a", MatchedResults: 1, MatchRatio: ratioOne, MatchPercent: ratioOne * 100, FindingCount: 2, HighestRisk: "high"},
		{RuleID: "rule-b", MatchedResults: 2, MatchRatio: ratioTwo, MatchPercent: ratioTwo * 100, FindingCount: 1, HighestRisk: "critical"},
	}
	if !reflect.DeepEqual(got.Rules, wantRules) {
		t.Fatalf("rules = %#v, want %#v", got.Rules, wantRules)
	}
	wantFinding := FindingSummary{
		Name: "exfiltration", Occurrences: 3, AffectedResults: 2,
		AffectedRatio: ratioTwo, AffectedPercent: ratioTwo * 100, HighestRisk: "critical",
	}
	if len(got.FindingCategories) != 1 || !reflect.DeepEqual(got.FindingCategories[0], wantFinding) {
		t.Fatalf("categories = %#v", got.FindingCategories)
	}
	wantFinding.Name = "EX-1"
	if len(got.FindingCodes) != 1 || !reflect.DeepEqual(got.FindingCodes[0], wantFinding) {
		t.Fatalf("codes = %#v", got.FindingCodes)
	}
	if got.Policies[0].PolicyID != "policy-a" || got.Policies[0].Count != 2 || got.Policies[1].PolicyID != "policy-z" {
		t.Fatalf("policies not sorted/counting correctly: %#v", got.Policies)
	}
	attributes := got.Results[2].Findings[1].Attributes
	if !reflect.DeepEqual(attributes, []Attribute{{Name: "a", Value: "first"}, {Name: "z", Value: "last"}}) {
		t.Fatalf("attributes not sorted: %#v", attributes)
	}
}

func TestBuildEmptyIncludesKnownDecisionAndRiskBuckets(t *testing.T) {
	got := Build(nil)
	if got.Total != 0 || len(got.Decisions) != 3 || len(got.Risks) != 5 {
		t.Fatalf("unexpected empty report: %#v", got)
	}
	for _, value := range append(got.Decisions, got.Risks...) {
		if value.Count != 0 || value.Ratio != 0 || value.Percent != 0 {
			t.Errorf("nonzero empty bucket: %#v", value)
		}
	}
}
