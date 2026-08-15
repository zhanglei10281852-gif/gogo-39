package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"agentguard/model"
	"agentguard/strictjson"
)

// Input is the strict JSON envelope accepted by DecodeResults.
type Input struct {
	Results []model.DecisionResult `json:"results"`
}

// DecodeResult decodes one result, rejecting unknown fields, duplicate keys,
// trailing values, invalid enum values, and missing report identifiers.
func DecodeResult(r io.Reader) (model.DecisionResult, error) {
	data, err := readInput(r)
	if err != nil {
		return model.DecisionResult{}, err
	}
	var result model.DecisionResult
	if err := strictjson.DecodeBytes(data, &result); err != nil {
		return model.DecisionResult{}, err
	}
	if err := ValidateResult(result); err != nil {
		return model.DecisionResult{}, err
	}
	return result, nil
}

// DecodeResultBytes is the byte-slice form of DecodeResult.
func DecodeResultBytes(data []byte) (model.DecisionResult, error) {
	return DecodeResult(bytes.NewReader(data))
}

// DecodeResults decodes an object of the form {"results":[...]}.
func DecodeResults(r io.Reader) ([]model.DecisionResult, error) {
	data, err := readInput(r)
	if err != nil {
		return nil, err
	}
	var input Input
	if err := strictjson.DecodeBytes(data, &input); err != nil {
		return nil, err
	}
	if input.Results == nil {
		return nil, fmt.Errorf("report input: results is required")
	}
	if err := ValidateResults(input.Results); err != nil {
		return nil, err
	}
	return input.Results, nil
}

// DecodeResultsBytes is the byte-slice form of DecodeResults.
func DecodeResultsBytes(data []byte) ([]model.DecisionResult, error) {
	return DecodeResults(bytes.NewReader(data))
}

// DecodeResultsFile reads a strict report input from path.
func DecodeResultsFile(path string) ([]model.DecisionResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("report input: open %s: %w", path, err)
	}
	defer file.Close()
	return DecodeResults(file)
}

// BuildJSON decodes an input envelope and aggregates it.
func BuildJSON(r io.Reader) (Report, error) {
	results, err := DecodeResults(r)
	if err != nil {
		return Report{}, err
	}
	return Build(results), nil
}

// ValidateResults verifies each result and enforces unique request IDs.
func ValidateResults(results []model.DecisionResult) error {
	seen := make(map[string]struct{}, len(results))
	for i, result := range results {
		if err := ValidateResult(result); err != nil {
			return fmt.Errorf("report input: results[%d]: %w", i, err)
		}
		if _, exists := seen[result.RequestID]; exists {
			return fmt.Errorf("report input: duplicate request_id %q", result.RequestID)
		}
		seen[result.RequestID] = struct{}{}
	}
	return nil
}

// ValidateResult validates the fields needed for trustworthy aggregation.
func ValidateResult(result model.DecisionResult) error {
	if strings.TrimSpace(result.RequestID) == "" {
		return fmt.Errorf("request_id is required")
	}
	if strings.TrimSpace(result.PolicyID) == "" {
		return fmt.Errorf("policy_id is required")
	}
	if strings.TrimSpace(result.PolicyVersion) == "" {
		return fmt.Errorf("policy_version is required")
	}
	switch result.Decision {
	case model.DecisionAllow, model.DecisionApprove, model.DecisionDeny:
	default:
		return fmt.Errorf("invalid decision %q", result.Decision)
	}
	if result.Risk.Rank() < 0 {
		return fmt.Errorf("invalid risk %q", result.Risk)
	}
	if result.EvaluatedAt.IsZero() {
		return fmt.Errorf("evaluated_at is required")
	}
	if result.EvaluationNanos < 0 {
		return fmt.Errorf("evaluation_nanos cannot be negative")
	}
	for i, finding := range result.Findings {
		if strings.TrimSpace(finding.Code) == "" {
			return fmt.Errorf("findings[%d].code is required", i)
		}
		if strings.TrimSpace(finding.Category) == "" {
			return fmt.Errorf("findings[%d].category is required", i)
		}
		if finding.Risk.Rank() < 0 {
			return fmt.Errorf("findings[%d]: invalid risk %q", i, finding.Risk)
		}
	}
	return nil
}
func readInput(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("report input: nil reader")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("report input: read JSON: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("report input: empty JSON")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("report input: %w", err)
	}
	return data, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, "$", nil); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing token %v", token)
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, path string, first json.Token) error {
	token := first
	var err error
	if token == nil {
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON at %s: %w", path, err)
		}
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid object at %s: %w", path, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("non-string object key at %s", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, path+"."+key, nil); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, '}', path)
	case '[':
		index := 0
		for decoder.More() {
			if err := consumeJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), nil); err != nil {
				return err
			}
			index++
		}
		return consumeClosingDelimiter(decoder, ']', path)
	default:
		return fmt.Errorf("unexpected delimiter %q at %s", delim, path)
	}
}

func consumeClosingDelimiter(decoder *json.Decoder, expected json.Delim, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("unterminated JSON at %s: %w", path, err)
	}
	if token != expected {
		return fmt.Errorf("expected %q at %s, got %v", expected, path, token)
	}
	return nil
}
