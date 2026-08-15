package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"agentguard/model"
)

func hostileReport() Report {
	value := `"><script>alert('x')</script>&`
	result := model.DecisionResult{
		RequestID: value, PolicyID: value, PolicyVersion: "v1",
		Decision: model.DecisionDeny, Risk: model.RiskHigh,
		Reasons: []string{"line one\nline two", value}, MatchedRules: []string{value},
		Findings: []model.Finding{{
			Code: value, Category: value, Risk: model.RiskHigh, Message: value,
			RuleID: value, Location: value,
			Attributes: map[string]string{value: value},
		}},
		Fingerprint: value, EvaluatedAt: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	return Build([]model.DecisionResult{result})
}

func TestRenderHTMLEscapesEveryDynamicContext(t *testing.T) {
	html, err := RenderHTML(hostileReport())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>alert") {
		t.Fatalf("HTML contains executable dynamic markup: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;alert") || !strings.Contains(html, "&amp;") {
		t.Fatalf("HTML lacks expected escapes: %s", html)
	}
	if strings.Count(html, "&lt;script&gt;") < 8 {
		t.Fatalf("not all dynamic fields appear escaped; count=%d", strings.Count(html, "&lt;script&gt;"))
	}
}

func TestMarshalJSONIsDeterministicAndEscapesHTML(t *testing.T) {
	report := hostileReport()
	first, err := MarshalJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("JSON output is not deterministic")
	}
	if bytes.Contains(first, []byte("<script>")) || !bytes.Contains(first, []byte(`\u003cscript\u003e`)) {
		t.Fatalf("JSON did not escape HTML-sensitive content: %s", first)
	}
}

func TestRenderTextQuotesLineBreaks(t *testing.T) {
	text := RenderText(hostileReport())
	if strings.Contains(text, "line one\nline two") {
		t.Fatalf("dynamic newline was emitted literally: %q", text)
	}
	if !strings.Contains(text, `line one\nline two`) {
		t.Fatalf("dynamic newline was not made visible: %q", text)
	}
	if !strings.Contains(text, "AgentGuard Decision Report") || !strings.Contains(text, "Finding codes") {
		t.Fatalf("missing readable sections: %s", text)
	}
}
