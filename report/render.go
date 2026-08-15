package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"
)

// MarshalJSON returns deterministic, indented JSON with HTML-sensitive bytes escaped.
func MarshalJSON(report Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: marshal JSON: %w", err)
	}
	return append(data, '\n'), nil
}

// WriteJSON writes a structured report as JSON.
func WriteJSON(w io.Writer, report Report) error {
	if w == nil {
		return fmt.Errorf("report: nil JSON writer")
	}
	data, err := MarshalJSON(report)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("report: write JSON: %w", err)
	}
	return nil
}

// RenderText returns a compact human-readable representation.
func RenderText(report Report) string {
	var out strings.Builder
	fmt.Fprintf(&out, "AgentGuard Decision Report\n")
	fmt.Fprintf(&out, "Results: %d\n", report.Total)
	fmt.Fprintf(&out, "Time range: %s — %s\n", formatTime(report.TimeRange.Start), formatTime(report.TimeRange.End))
	fmt.Fprintf(&out, "Evaluation: measured=%d total=%s min=%s max=%s mean=%s\n",
		report.Evaluation.Measured, formatNanos(report.Evaluation.TotalNanos),
		formatNanos(report.Evaluation.MinNanos), formatNanos(report.Evaluation.MaxNanos),
		formatNanosFloat(report.Evaluation.MeanNanos))

	writeCountRatioText(&out, "Decisions", report.Decisions)
	writeCountRatioText(&out, "Risks", report.Risks)
	writePolicyText(&out, report.Policies)
	writeRuleText(&out, report.Rules)
	writeFindingText(&out, "Finding categories", report.FindingCategories)
	writeFindingText(&out, "Finding codes", report.FindingCodes)
	writeResultText(&out, report.Results)
	return out.String()
}

// WriteText writes the human-readable representation.
func WriteText(w io.Writer, report Report) error {
	if w == nil {
		return fmt.Errorf("report: nil text writer")
	}
	if _, err := io.WriteString(w, RenderText(report)); err != nil {
		return fmt.Errorf("report: write text: %w", err)
	}
	return nil
}
func writeCountRatioText(out *strings.Builder, title string, values []CountRatio) {
	fmt.Fprintf(out, "\n%s:\n", title)
	for _, value := range values {
		fmt.Fprintf(out, "  %-18s %6d %7.2f%%\n", textValue(value.Name), value.Count, value.Percent)
	}
}

func writePolicyText(out *strings.Builder, values []PolicySummary) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintln(out, "\nPolicies:")
	for _, value := range values {
		fmt.Fprintf(out, "  %s@%s: %d (%.2f%%)\n", textValue(value.PolicyID),
			textValue(value.PolicyVersion), value.Count, value.Percent)
	}
}

func writeRuleText(out *strings.Builder, values []RuleSummary) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintln(out, "\nRules:")
	for _, value := range values {
		fmt.Fprintf(out, "  %s: results=%d (%.2f%%), findings=%d, highest-risk=%s\n",
			textValue(value.RuleID), value.MatchedResults, value.MatchPercent,
			value.FindingCount, textValue(value.HighestRisk))
	}
}

func writeFindingText(out *strings.Builder, title string, values []FindingSummary) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s:\n", title)
	for _, value := range values {
		fmt.Fprintf(out, "  %s: occurrences=%d, affected=%d (%.2f%%), highest-risk=%s\n",
			textValue(value.Name), value.Occurrences, value.AffectedResults,
			value.AffectedPercent, textValue(value.HighestRisk))
	}
}

func writeResultText(out *strings.Builder, results []ResultSummary) {
	if len(results) == 0 {
		return
	}
	fmt.Fprintln(out, "\nResults:")
	for _, result := range results {
		fmt.Fprintf(out, "  [%s] %s decision=%s risk=%s policy=%s@%s\n",
			formatTime(result.EvaluatedAt), textValue(result.RequestID), result.Decision,
			result.Risk, textValue(result.PolicyID), textValue(result.PolicyVersion))
		for _, reason := range result.Reasons {
			fmt.Fprintf(out, "    reason: %s\n", textValue(reason))
		}
		for _, finding := range result.Findings {
			fmt.Fprintf(out, "    finding %s/%s [%s]: %s", textValue(finding.Category),
				textValue(finding.Code), finding.Risk, textValue(finding.Message))
			if finding.Location != "" {
				fmt.Fprintf(out, " at %s", textValue(finding.Location))
			}
			if finding.RuleID != "" {
				fmt.Fprintf(out, " rule=%s", textValue(finding.RuleID))
			}
			fmt.Fprintln(out)
		}
	}
}

func textValue(value string) string {
	quoted := strconv.QuoteToGraphic(value)
	if len(quoted) >= 2 {
		return quoted[1 : len(quoted)-1]
	}
	return value
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "n/a"
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func formatNanos(value int64) string {
	if value <= 0 {
		return "0s"
	}
	return time.Duration(value).String()
}

func formatNanosFloat(value float64) string {
	if value <= 0 {
		return "0s"
	}
	return time.Duration(value).String()
}

var htmlFunctions = template.FuncMap{
	"time":       formatTime,
	"nanos":      formatNanos,
	"nanosFloat": formatNanosFloat,
	"percent":    func(value float64) string { return fmt.Sprintf("%.2f%%", value) },
	"join":       func(values []string) string { return strings.Join(values, ", ") },
	"riskClass": func(value any) string {
		switch fmt.Sprint(value) {
		case "critical":
			return "risk-critical"
		case "high":
			return "risk-high"
		case "medium":
			return "risk-medium"
		case "low":
			return "risk-low"
		default:
			return "risk-none"
		}
	},
	"decisionClass": func(value any) string {
		switch fmt.Sprint(value) {
		case "allow":
			return "decision-allow"
		case "deny":
			return "decision-deny"
		default:
			return "decision-approval"
		}
	},
}

var reportHTMLTemplate = template.Must(template.New("agentguard-report").Funcs(htmlFunctions).Parse(reportHTMLSource))

// RenderHTML renders a complete HTML document. html/template contextually
// escapes every value originating in the report.
func RenderHTML(report Report) (string, error) {
	var out bytes.Buffer
	if err := reportHTMLTemplate.Execute(&out, report); err != nil {
		return "", fmt.Errorf("report: render HTML: %w", err)
	}
	return out.String(), nil
}

// WriteHTML writes a complete, safely escaped HTML report.
func WriteHTML(w io.Writer, report Report) error {
	if w == nil {
		return fmt.Errorf("report: nil HTML writer")
	}
	if err := reportHTMLTemplate.Execute(w, report); err != nil {
		return fmt.Errorf("report: write HTML: %w", err)
	}
	return nil
}

const reportHTMLSource = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGuard Decision Report</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { margin: 2rem auto; max-width: 1100px; padding: 0 1rem; line-height: 1.45; }
h1, h2 { line-height: 1.15; }
.summary { display: grid; grid-template-columns: repeat(auto-fit,minmax(13rem,1fr)); gap: .75rem; }
.card { border: 1px solid #8886; border-radius: .5rem; padding: .75rem; }
table { border-collapse: collapse; width: 100%; margin: .75rem 0 1.5rem; }
th, td { border-bottom: 1px solid #8885; padding: .45rem; text-align: left; vertical-align: top; }
th { font-weight: 650; }
.number { text-align: right; font-variant-numeric: tabular-nums; }
.badge { border-radius: 1rem; display: inline-block; padding: .12rem .5rem; font-weight: 650; }
.risk-critical,.decision-deny { background: #b42318; color: white; }
.risk-high { background: #dc6803; color: white; }
.risk-medium,.decision-approval { background: #fdb022; color: #222; }
.risk-low { background: #1570ef; color: white; }
.risk-none,.decision-allow { background: #039855; color: white; }
.result { border: 1px solid #8886; border-radius: .5rem; margin: .75rem 0; padding: .9rem; }
.result h3 { margin-top: 0; }
dt { font-weight: 650; } dd { margin-bottom: .35rem; }
code { overflow-wrap: anywhere; }
</style>
</head>
<body>
<header><h1>AgentGuard Decision Report</h1></header>
<section class="summary" aria-label="Summary">
<div class="card"><strong>Results</strong><br>{{.Total}}</div>
<div class="card"><strong>From</strong><br><time>{{time .TimeRange.Start}}</time></div>
<div class="card"><strong>To</strong><br><time>{{time .TimeRange.End}}</time></div>
<div class="card"><strong>Evaluation</strong><br>{{.Evaluation.Measured}} measured / {{nanos .Evaluation.TotalNanos}}</div>
</section>
<h2>Decisions</h2>
<table><thead><tr><th>Decision</th><th class="number">Count</th><th class="number">Share</th></tr></thead><tbody>
{{range .Decisions}}<tr><td><span class="badge {{decisionClass .Name}}">{{.Name}}</span></td><td class="number">{{.Count}}</td><td class="number">{{percent .Percent}}</td></tr>{{end}}
</tbody></table>
<h2>Risks</h2>
<table><thead><tr><th>Risk</th><th class="number">Count</th><th class="number">Share</th></tr></thead><tbody>
{{range .Risks}}<tr><td><span class="badge {{riskClass .Name}}">{{.Name}}</span></td><td class="number">{{.Count}}</td><td class="number">{{percent .Percent}}</td></tr>{{end}}
</tbody></table>
{{if .Policies}}<h2>Policies</h2>
<table><thead><tr><th>Policy</th><th>Version</th><th class="number">Count</th><th class="number">Share</th></tr></thead><tbody>
{{range .Policies}}<tr><td>{{.PolicyID}}</td><td>{{.PolicyVersion}}</td><td class="number">{{.Count}}</td><td class="number">{{percent .Percent}}</td></tr>{{end}}
</tbody></table>{{end}}
{{if .Rules}}<h2>Rules</h2>
<table><thead><tr><th>Rule</th><th class="number">Matched results</th><th class="number">Findings</th><th>Highest risk</th></tr></thead><tbody>
{{range .Rules}}<tr><td>{{.RuleID}}</td><td class="number">{{.MatchedResults}} ({{percent .MatchPercent}})</td><td class="number">{{.FindingCount}}</td><td><span class="badge {{riskClass .HighestRisk}}">{{.HighestRisk}}</span></td></tr>{{end}}
</tbody></table>{{end}}
{{template "findings" .FindingCategories}}
{{template "codes" .FindingCodes}}
{{if .Results}}<h2>Results</h2>{{range .Results}}
<article class="result">
<h3><code>{{.RequestID}}</code></h3>
<p><span class="badge {{decisionClass .Decision}}">{{.Decision}}</span> <span class="badge {{riskClass .Risk}}">{{.Risk}}</span></p>
<dl><dt>Evaluated</dt><dd><time>{{time .EvaluatedAt}}</time></dd><dt>Policy</dt><dd>{{.PolicyID}} @ {{.PolicyVersion}}</dd><dt>Fingerprint</dt><dd><code>{{.Fingerprint}}</code></dd>
{{if .Reasons}}<dt>Reasons</dt><dd>{{join .Reasons}}</dd>{{end}}{{if .MatchedRules}}<dt>Matched rules</dt><dd>{{join .MatchedRules}}</dd>{{end}}</dl>
{{if .Findings}}<table><thead><tr><th>Category / code</th><th>Risk</th><th>Message</th><th>Rule / location</th><th>Attributes</th></tr></thead><tbody>{{range .Findings}}
<tr><td>{{.Category}} / {{.Code}}</td><td><span class="badge {{riskClass .Risk}}">{{.Risk}}</span></td><td>{{.Message}}</td><td>{{.RuleID}}<br>{{.Location}}</td><td>{{range .Attributes}}<div><strong>{{.Name}}</strong>: {{.Value}}</div>{{end}}</td></tr>
{{end}}</tbody></table>{{end}}
</article>{{end}}{{end}}
</body></html>
{{define "findings"}}{{if .}}<h2>Finding categories</h2><table><thead><tr><th>Category</th><th class="number">Occurrences</th><th class="number">Affected results</th><th>Highest risk</th></tr></thead><tbody>{{range .}}<tr><td>{{.Name}}</td><td class="number">{{.Occurrences}}</td><td class="number">{{.AffectedResults}} ({{percent .AffectedPercent}})</td><td><span class="badge {{riskClass .HighestRisk}}">{{.HighestRisk}}</span></td></tr>{{end}}</tbody></table>{{end}}{{end}}
{{define "codes"}}{{if .}}<h2>Finding codes</h2><table><thead><tr><th>Code</th><th class="number">Occurrences</th><th class="number">Affected results</th><th>Highest risk</th></tr></thead><tbody>{{range .}}<tr><td>{{.Name}}</td><td class="number">{{.Occurrences}}</td><td class="number">{{.AffectedResults}} ({{percent .AffectedPercent}})</td><td><span class="badge {{riskClass .HighestRisk}}">{{.HighestRisk}}</span></td></tr>{{end}}</tbody></table>{{end}}{{end}}`
