package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentguard/model"
	"agentguard/policy"
)

func invoke(args []string, input string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func samplePolicyFile(t *testing.T) (string, []byte) {
	t.Helper()
	code, out, stderr := invoke([]string{"sample-policy"}, "")
	if code != 0 || stderr != "" {
		t.Fatalf("sample-policy: code=%d stderr=%q", code, stderr)
	}
	if _, err := policy.Parse([]byte(out)); err != nil {
		t.Fatalf("sample policy is invalid: %v", err)
	}
	return writeTemp(t, "policy.json", []byte(out)), []byte(out)
}

func requestJSON(t *testing.T) []byte {
	t.Helper()
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	request := model.EvaluationRequest{
		RequestID: "request-1", EvaluatedAt: now,
		Identity: model.Identity{ID: "agent-1", Kind: "service", Issuer: "test", Authenticated: true, AssuranceLevel: 2},
		Session:  model.Session{ID: "session-1", IdentityID: "agent-1", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), LastSeenAt: now, Sequence: 1, Nonce: "nonce"},
		Call:     model.ToolCall{ID: "call-1", Tool: "shell", Operation: "execute", Capability: "shell.execute", Arguments: json.RawMessage(`{"command":"echo ok"}`)},
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSamplePolicyAndValidate(t *testing.T) {
	path, sample := samplePolicyFile(t)
	code, out, stderr := invoke([]string{"validate", "-policy", path}, "")
	if code != 0 || stderr != "" || out != "policy example-agent-policy@1.0.0 is valid\n" {
		t.Fatalf("validate: code=%d stdout=%q stderr=%q", code, out, stderr)
	}

	tests := []struct {
		name string
		data string
		want string
	}{
		{"unknown field", strings.Replace(string(sample), `"id":`, `"unknown": true, "id":`, 1), "unknown field"},
		{"trailing value", string(sample) + `{}`, "trailing value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, out, stderr := invoke([]string{"validate", "-policy", "-"}, test.data)
			if code != 1 || out != "" || !strings.Contains(stderr, test.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, stderr)
			}
		})
	}
}

func TestEvaluateAndExplain(t *testing.T) {
	policyPath, _ := samplePolicyFile(t)
	request := string(requestJSON(t))
	code, out, stderr := invoke([]string{"evaluate", "-policy", policyPath}, request)
	if code != 0 || stderr != "" {
		t.Fatalf("evaluate: code=%d stderr=%q", code, stderr)
	}
	var result model.DecisionResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("result JSON: %v", err)
	}
	if result.Decision != model.DecisionApprove || result.RequestID != "request-1" {
		t.Fatalf("unexpected result: %#v", result)
	}

	args := []string{"explain", "-policy", policyPath}
	code, first, stderr := invoke(args, request)
	code2, second, stderr2 := invoke(args, request)
	if code != 0 || code2 != 0 || stderr != "" || stderr2 != "" || first != second {
		t.Fatalf("explain is not stable: codes=%d/%d stderr=%q/%q", code, code2, stderr, stderr2)
	}
	for _, text := range []string{"Decision: require_approval", "Matched rules: approve-shell", "- shell execution requires approval", "Fingerprint: "} {
		if !strings.Contains(first, text) {
			t.Errorf("explanation missing %q:\n%s", text, first)
		}
	}
}

func TestEvaluateRejectsStrictRequestAndFindings(t *testing.T) {
	policyPath, _ := samplePolicyFile(t)
	request := string(requestJSON(t))
	t.Run("request unknown field", func(t *testing.T) {
		bad := strings.Replace(request, `"request_id":`, `"extra": true, "request_id":`, 1)
		code, out, stderr := invoke([]string{"evaluate", "-policy", policyPath}, bad)
		if code != 1 || out != "" || !strings.Contains(stderr, "unknown field") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out, stderr)
		}
	})
	t.Run("request trailing value", func(t *testing.T) {
		code, out, stderr := invoke([]string{"evaluate", "-policy", policyPath}, request+` null`)
		if code != 1 || out != "" || !strings.Contains(stderr, "trailing value") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out, stderr)
		}
	})
	t.Run("findings unknown field", func(t *testing.T) {
		requestPath := writeTemp(t, "request.json", []byte(request))
		findingsPath := writeTemp(t, "findings.json", []byte(`{"findings":[],"extra":true}`))
		code, out, stderr := invoke([]string{"evaluate", "-policy", policyPath, "-request", requestPath, "-findings", findingsPath}, "")
		if code != 1 || out != "" || !strings.Contains(stderr, "unknown field") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out, stderr)
		}
	})
	t.Run("findings trailing value", func(t *testing.T) {
		requestPath := writeTemp(t, "request.json", []byte(request))
		findingsPath := writeTemp(t, "findings.json", []byte(`{"findings":[]} []`))
		code, out, stderr := invoke([]string{"explain", "-policy", policyPath, "-request", requestPath, "-findings", findingsPath}, "")
		if code != 1 || out != "" || !strings.Contains(stderr, "trailing value") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out, stderr)
		}
	})
}

func reportInput(t *testing.T) []byte {
	t.Helper()
	result := model.DecisionResult{
		RequestID: "report-1", PolicyID: "policy-1", PolicyVersion: "1", Decision: model.DecisionDeny,
		Risk: model.RiskHigh, Reasons: []string{"unsafe <script>alert(1)</script>"},
		Fingerprint: "fingerprint", EvaluatedAt: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	data, err := json.Marshal(struct {
		Results []model.DecisionResult `json:"results"`
	}{[]model.DecisionResult{result}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReportFormatsOutputAndStrictInput(t *testing.T) {
	input := string(reportInput(t))
	for _, format := range []string{"json", "text", "html"} {
		t.Run(format, func(t *testing.T) {
			code, out, stderr := invoke([]string{"report", "-format", format}, input)
			if code != 0 || stderr != "" || out == "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, stderr)
			}
			if format == "html" {
				if strings.Contains(out, "<script>alert") || !strings.Contains(out, "&lt;script&gt;") {
					t.Fatalf("HTML was not safely escaped: %s", out)
				}
			}
		})
	}

	outputPath := filepath.Join(t.TempDir(), "report.txt")
	code, out, stderr := invoke([]string{"report", "-output", outputPath}, input)
	if code != 0 || out != "" || stderr != "" {
		t.Fatalf("file output: code=%d stdout=%q stderr=%q", code, out, stderr)
	}
	written, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Contains(written, []byte("AgentGuard Decision Report")) {
		t.Fatalf("output file: data=%q err=%v", written, err)
	}

	for name, bad := range map[string]string{
		"unknown":  strings.Replace(input, `"results":`, `"unknown": true, "results":`, 1),
		"trailing": input + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			code, out, stderr := invoke([]string{"report"}, bad)
			if code != 1 || out != "" || stderr == "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, stderr)
			}
		})
	}
}

func TestUsageAndErrorStreams(t *testing.T) {
	code, out, stderr := invoke(nil, "")
	if code != 2 || out != "" || !strings.Contains(stderr, "Usage:") {
		t.Fatalf("root usage: code=%d stdout=%q stderr=%q", code, out, stderr)
	}
	code, out, stderr = invoke([]string{"evaluate", "-bad"}, "")
	if code != 2 || out != "" || !strings.Contains(stderr, "flag provided but not defined") {
		t.Fatalf("flag usage: code=%d stdout=%q stderr=%q", code, out, stderr)
	}
	code, out, stderr = invoke([]string{"report", "-format", "xml"}, `{}`)
	if code != 2 || out != "" || !strings.Contains(stderr, "invalid -format") {
		t.Fatalf("format usage: code=%d stdout=%q stderr=%q", code, out, stderr)
	}
	code, out, stderr = invoke([]string{"explain", "-h"}, "")
	if code != 0 || stderr != "" || !strings.Contains(out, "Usage: agentguard explain") {
		t.Fatalf("help: code=%d stdout=%q stderr=%q", code, out, stderr)
	}
}
