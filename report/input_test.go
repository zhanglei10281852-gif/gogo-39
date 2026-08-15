package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"agentguard/model"
)

func validResultJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(sampleResults()[0])
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeResultStrictAndValid(t *testing.T) {
	valid := validResultJSON(t)
	got, err := DecodeResultBytes(valid)
	if err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	if got.RequestID != "request-b" {
		t.Fatalf("request_id = %q", got.RequestID)
	}

	unknown := append(append([]byte(nil), bytes.TrimSuffix(valid, []byte("}"))...), []byte(`,"unexpected":true}`)...)
	if _, err := DecodeResultBytes(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	if _, err := DecodeResultBytes(trailing); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	duplicate := bytes.Replace(valid, []byte(`"request_id":"request-b"`), []byte(`"request_id":"request-b","request_id":"other"`), 1)
	if _, err := DecodeResultBytes(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate key error = %v", err)
	}
}

func TestDecodeResultsEnvelopeAndValidation(t *testing.T) {
	input := Input{Results: sampleResults()}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeResultsBytes(data)
	if err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("decoded %d results", len(got))
	}

	if _, err := DecodeResultsBytes([]byte(`{"results":[],"extra":1}`)); err == nil {
		t.Fatal("unknown envelope field accepted")
	}
	if _, err := DecodeResultsBytes([]byte(`{}`)); err == nil || !strings.Contains(err.Error(), "results is required") {
		t.Fatalf("missing results error = %v", err)
	}
}

func TestDecodeResultsRejectsDuplicateRequests(t *testing.T) {
	result := sampleResults()[0]
	data, err := json.Marshal(Input{Results: []model.DecisionResult{result, result}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResultsBytes(data); err == nil || !strings.Contains(err.Error(), "duplicate request_id") {
		t.Fatalf("duplicate request error = %v", err)
	}
}
