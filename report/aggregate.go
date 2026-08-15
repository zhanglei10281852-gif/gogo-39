package report

import (
	"sort"
	"strings"
	"time"

	"agentguard/model"
)

type policyKey struct {
	id      string
	version string
}

type ruleAccumulator struct {
	results  int
	findings int
	risk     model.Risk
}

type findingAccumulator struct {
	occurrences int
	affected    int
	risk        model.Risk
}

var standardDecisions = []model.Decision{
	model.DecisionAllow,
	model.DecisionApprove,
	model.DecisionDeny,
}

var standardRisks = []model.Risk{
	model.RiskNone,
	model.RiskLow,
	model.RiskMedium,
	model.RiskHigh,
	model.RiskCritical,
}

// Build returns a deterministic report and never mutates results.
func Build(results []model.DecisionResult) Report {
	report := Report{Total: len(results)}
	decisionCounts := make(map[string]int)
	riskCounts := make(map[string]int)
	policyCounts := make(map[policyKey]int)
	rules := make(map[string]*ruleAccumulator)
	categories := make(map[string]*findingAccumulator)
	codes := make(map[string]*findingAccumulator)

	for i := range results {
		result := results[i]
		decisionCounts[string(result.Decision)]++
		riskCounts[string(result.Risk)]++
		policyCounts[policyKey{result.PolicyID, result.PolicyVersion}]++
		accumulateTime(&report, result)
		accumulateRules(rules, result)
		accumulateFindings(categories, codes, result)
		report.Results = append(report.Results, summarizeResult(result))
	}

	finalizeEvaluation(&report)
	report.Decisions = makeCountRatios(decisionCounts, decisionNames(decisionCounts), report.Total)
	report.Risks = makeCountRatios(riskCounts, riskNames(riskCounts), report.Total)
	report.Policies = makePolicies(policyCounts, report.Total)
	report.Rules = makeRules(rules, report.Total)
	report.FindingCategories = makeFindings(categories, report.Total)
	report.FindingCodes = makeFindings(codes, report.Total)
	sortResults(report.Results)
	return report
}
func accumulateTime(report *Report, result model.DecisionResult) {
	if !result.EvaluatedAt.IsZero() {
		at := result.EvaluatedAt.UTC()
		if report.TimeRange.Start.IsZero() || at.Before(report.TimeRange.Start) {
			report.TimeRange.Start = at
		}
		if report.TimeRange.End.IsZero() || at.After(report.TimeRange.End) {
			report.TimeRange.End = at
		}
	}
	if result.EvaluationNanos <= 0 {
		return
	}
	evaluation := &report.Evaluation
	evaluation.TotalNanos += result.EvaluationNanos
	evaluation.Measured++
	if evaluation.MinNanos == 0 || result.EvaluationNanos < evaluation.MinNanos {
		evaluation.MinNanos = result.EvaluationNanos
	}
	if result.EvaluationNanos > evaluation.MaxNanos {
		evaluation.MaxNanos = result.EvaluationNanos
	}
}

func finalizeEvaluation(report *Report) {
	if report.Evaluation.Measured > 0 {
		report.Evaluation.MeanNanos = float64(report.Evaluation.TotalNanos) /
			float64(report.Evaluation.Measured)
	}
}

func accumulateRules(rules map[string]*ruleAccumulator, result model.DecisionResult) {
	seen := make(map[string]struct{})
	for _, ruleID := range result.MatchedRules {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID != "" {
			seen[ruleID] = struct{}{}
		}
	}
	for _, finding := range result.Findings {
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID == "" {
			continue
		}
		seen[ruleID] = struct{}{}
		acc := ensureRule(rules, ruleID)
		acc.findings++
		acc.risk = higherRisk(acc.risk, finding.Risk)
	}
	for ruleID := range seen {
		ensureRule(rules, ruleID).results++
	}
}

func ensureRule(rules map[string]*ruleAccumulator, ruleID string) *ruleAccumulator {
	acc := rules[ruleID]
	if acc == nil {
		acc = &ruleAccumulator{risk: model.RiskNone}
		rules[ruleID] = acc
	}
	return acc
}

func accumulateFindings(categories, codes map[string]*findingAccumulator, result model.DecisionResult) {
	seenCategories := make(map[string]model.Risk)
	seenCodes := make(map[string]model.Risk)
	for _, finding := range result.Findings {
		category := strings.TrimSpace(finding.Category)
		code := strings.TrimSpace(finding.Code)
		categoryAcc := ensureFinding(categories, category)
		categoryAcc.occurrences++
		categoryAcc.risk = higherRisk(categoryAcc.risk, finding.Risk)
		codeAcc := ensureFinding(codes, code)
		codeAcc.occurrences++
		codeAcc.risk = higherRisk(codeAcc.risk, finding.Risk)
		seenCategories[category] = higherRisk(seenCategories[category], finding.Risk)
		seenCodes[code] = higherRisk(seenCodes[code], finding.Risk)
	}
	for category := range seenCategories {
		categories[category].affected++
	}
	for code := range seenCodes {
		codes[code].affected++
	}
}

func ensureFinding(values map[string]*findingAccumulator, name string) *findingAccumulator {
	acc := values[name]
	if acc == nil {
		acc = &findingAccumulator{risk: model.RiskNone}
		values[name] = acc
	}
	return acc
}
func decisionNames(counts map[string]int) []string {
	names := make([]string, 0, len(counts)+len(standardDecisions))
	seen := make(map[string]struct{})
	for _, decision := range standardDecisions {
		name := string(decision)
		names = append(names, name)
		seen[name] = struct{}{}
	}
	var extra []string
	for name := range counts {
		if _, ok := seen[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	return append(names, extra...)
}

func riskNames(counts map[string]int) []string {
	names := make([]string, 0, len(counts)+len(standardRisks))
	seen := make(map[string]struct{})
	for _, risk := range standardRisks {
		name := string(risk)
		names = append(names, name)
		seen[name] = struct{}{}
	}
	var extra []string
	for name := range counts {
		if _, ok := seen[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	return append(names, extra...)
}

func makeCountRatios(counts map[string]int, names []string, total int) []CountRatio {
	out := make([]CountRatio, 0, len(names))
	for _, name := range names {
		ratio := fraction(counts[name], total)
		out = append(out, CountRatio{
			Name: name, Count: counts[name], Ratio: ratio, Percent: ratio * 100,
		})
	}
	return out
}

func makePolicies(counts map[policyKey]int, total int) []PolicySummary {
	out := make([]PolicySummary, 0, len(counts))
	for key, count := range counts {
		ratio := fraction(count, total)
		out = append(out, PolicySummary{
			PolicyID: key.id, PolicyVersion: key.version, Count: count,
			Ratio: ratio, Percent: ratio * 100,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PolicyID != out[j].PolicyID {
			return out[i].PolicyID < out[j].PolicyID
		}
		return out[i].PolicyVersion < out[j].PolicyVersion
	})
	return out
}

func makeRules(values map[string]*ruleAccumulator, total int) []RuleSummary {
	out := make([]RuleSummary, 0, len(values))
	for id, value := range values {
		ratio := fraction(value.results, total)
		out = append(out, RuleSummary{
			RuleID: id, MatchedResults: value.results, MatchRatio: ratio,
			MatchPercent: ratio * 100, FindingCount: value.findings,
			HighestRisk: string(value.risk),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func makeFindings(values map[string]*findingAccumulator, total int) []FindingSummary {
	out := make([]FindingSummary, 0, len(values))
	for name, value := range values {
		ratio := fraction(value.affected, total)
		out = append(out, FindingSummary{
			Name: name, Occurrences: value.occurrences, AffectedResults: value.affected,
			AffectedRatio: ratio, AffectedPercent: ratio * 100,
			HighestRisk: string(value.risk),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func fraction(count, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(count) / float64(total)
}
func higherRisk(left, right model.Risk) model.Risk {
	if left == "" {
		left = model.RiskNone
	}
	if right.Rank() > left.Rank() {
		return right
	}
	return left
}

func summarizeResult(result model.DecisionResult) ResultSummary {
	summary := ResultSummary{
		RequestID: result.RequestID, PolicyID: result.PolicyID,
		PolicyVersion: result.PolicyVersion, Decision: result.Decision,
		Risk: result.Risk, Reasons: sortedUniqueCopy(result.Reasons),
		MatchedRules: sortedUniqueCopy(result.MatchedRules),
		GrantIDs:     sortedUniqueCopy(result.GrantIDs), ApprovalID: result.ApprovalID,
		Fingerprint: result.Fingerprint, EvaluationNanos: result.EvaluationNanos,
	}
	if !result.EvaluatedAt.IsZero() {
		summary.EvaluatedAt = result.EvaluatedAt.UTC()
	}
	for _, finding := range result.Findings {
		detail := FindingDetail{
			Code: finding.Code, Category: finding.Category, Risk: finding.Risk,
			Message: finding.Message, RuleID: finding.RuleID, Location: finding.Location,
		}
		for name, value := range finding.Attributes {
			detail.Attributes = append(detail.Attributes, Attribute{Name: name, Value: value})
		}
		sort.Slice(detail.Attributes, func(i, j int) bool {
			if detail.Attributes[i].Name != detail.Attributes[j].Name {
				return detail.Attributes[i].Name < detail.Attributes[j].Name
			}
			return detail.Attributes[i].Value < detail.Attributes[j].Value
		})
		summary.Findings = append(summary.Findings, detail)
	}
	sort.SliceStable(summary.Findings, func(i, j int) bool {
		left, right := summary.Findings[i], summary.Findings[j]
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.Category != right.Category {
			return left.Category < right.Category
		}
		if left.Location != right.Location {
			return left.Location < right.Location
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		if left.Message != right.Message {
			return left.Message < right.Message
		}
		return left.Risk < right.Risk
	})
	return summary
}

func sortedUniqueCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	copyOfValues := append([]string(nil), values...)
	return model.SortedUnique(copyOfValues)
}

func sortResults(results []ResultSummary) {
	sort.SliceStable(results, func(i, j int) bool {
		left, right := results[i], results[j]
		if !left.EvaluatedAt.Equal(right.EvaluatedAt) {
			if left.EvaluatedAt.IsZero() {
				return false
			}
			if right.EvaluatedAt.IsZero() {
				return true
			}
			return left.EvaluatedAt.Before(right.EvaluatedAt)
		}
		if left.RequestID != right.RequestID {
			return left.RequestID < right.RequestID
		}
		if left.PolicyID != right.PolicyID {
			return left.PolicyID < right.PolicyID
		}
		if left.PolicyVersion != right.PolicyVersion {
			return left.PolicyVersion < right.PolicyVersion
		}
		return left.Fingerprint < right.Fingerprint
	})
}

// Duration returns the inclusive span between the earliest and latest result.
func (r Report) Duration() time.Duration {
	if r.TimeRange.Start.IsZero() || r.TimeRange.End.IsZero() {
		return 0
	}
	return r.TimeRange.End.Sub(r.TimeRange.Start)
}
