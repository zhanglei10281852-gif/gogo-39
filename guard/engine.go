// Package guard integrates classification, policy evaluation, and audit recording.
package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"agentguard/audit"
	"agentguard/classify"
	"agentguard/model"
	"agentguard/policy"
)

// Engine is an offline deterministic AgentGuard evaluation pipeline.
type Engine struct {
	Policy     policy.Policy
	Classifier *classify.Classifier
	Ledger     *audit.Ledger
}

// New creates an engine with the conservative default classifier.
func New(p policy.Policy) (*Engine, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &Engine{Policy: p, Classifier: classify.MustNewDefault()}, nil
}

// WithClassifier replaces the classifier after validating it is non-nil.
func (e *Engine) WithClassifier(classifier *classify.Classifier) *Engine {
	copy := *e
	copy.Classifier = classifier
	return &copy
}

// WithLedger returns an engine that records successful evaluations.
func (e *Engine) WithLedger(ledger *audit.Ledger) *Engine {
	copy := *e
	copy.Ledger = ledger
	return &copy
}

// Evaluate classifies all egress channels, applies policy, and optionally audits.
func (e *Engine) Evaluate(ctx context.Context, request model.EvaluationRequest) (model.DecisionResult, error) {
	return e.EvaluateWithFindings(ctx, request, nil)
}

// EvaluateWithFindings adds trusted external findings to local classification.
func (e *Engine) EvaluateWithFindings(ctx context.Context, request model.EvaluationRequest, extra []model.Finding) (model.DecisionResult, error) {
	result, _, err := e.evaluate(ctx, request, extra)
	if err != nil {
		return model.DecisionResult{}, err
	}
	if e.Ledger != nil {
		_, err := e.Ledger.Append(ctx, audit.EventInput{
			Timestamp: request.EvaluatedAt,
			Type:      "decision", RequestID: request.RequestID,
			SessionID: request.Session.ID, ActorID: request.Identity.ID,
			PolicyID: e.Policy.ID,
			Payload:  audit.ReplayRecord{Request: request, Result: result},
		})
		if err != nil {
			return model.DecisionResult{}, fmt.Errorf("append audit decision: %w", err)
		}
	}
	return result, nil
}

// EvaluateWithoutAudit is used by replay to avoid mutating the source ledger.
func (e *Engine) EvaluateWithoutAudit(ctx context.Context, request model.EvaluationRequest) (model.DecisionResult, error) {
	result, _, err := e.evaluate(ctx, request, nil)
	return result, err
}

func (e *Engine) evaluate(ctx context.Context, request model.EvaluationRequest, extra []model.Finding) (model.DecisionResult, classify.Report, error) {
	if err := ctx.Err(); err != nil {
		return model.DecisionResult{}, classify.Report{}, err
	}
	if e == nil {
		return model.DecisionResult{}, classify.Report{}, fmt.Errorf("guard engine is nil")
	}
	if e.Classifier == nil {
		return model.DecisionResult{}, classify.Report{}, fmt.Errorf("classifier is required")
	}
	if err := e.Policy.Validate(); err != nil {
		return model.DecisionResult{}, classify.Report{}, fmt.Errorf("policy: %w", err)
	}
	metadata := make(map[string]string, len(request.Context)+2)
	for key, value := range request.Context {
		metadata["context."+key] = value
	}
	if len(request.Call.Arguments) > 0 {
		metadata["tool.arguments"] = string(request.Call.Arguments)
	}
	if len(request.Call.Labels) > 0 {
		labels := append([]string(nil), request.Call.Labels...)
		sort.Strings(labels)
		metadata["tool.labels"] = strings.Join(labels, ",")
	}
	report := e.Classifier.Analyze(classify.Input{
		Content: request.Call.Content, Prompt: request.Prompt,
		Destination: request.Call.Destination, Metadata: metadata,
	})
	findings := append(ModelFindings(report.Findings), extra...)
	result, err := policy.Evaluate(e.Policy, request, findings)
	if err != nil {
		return model.DecisionResult{}, report, err
	}
	return result, report, nil
}

// ModelFindings converts classifier evidence to stable policy evidence.
func ModelFindings(input []classify.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(input))
	for _, finding := range input {
		attributes := make(map[string]string, len(finding.Metadata)+4)
		for key, value := range finding.Metadata {
			attributes[key] = value
		}
		attributes["confidence"] = strconv.FormatFloat(finding.Confidence, 'f', 3, 64)
		attributes["span_start"] = strconv.Itoa(finding.Span.Start)
		attributes["span_end"] = strconv.Itoa(finding.Span.End)
		if finding.Value != "" {
			attributes["value_present"] = "true"
		}
		out = append(out, model.Finding{
			Code: string(finding.Kind), Category: string(finding.Category),
			Risk: severityRisk(finding.Severity), Message: finding.Message,
			Location: finding.Source, Attributes: attributes,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		if out[i].Location != out[j].Location {
			return out[i].Location < out[j].Location
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func severityRisk(severity classify.Severity) model.Risk {
	switch severity {
	case classify.SeverityCritical:
		return model.RiskCritical
	case classify.SeverityHigh:
		return model.RiskHigh
	case classify.SeverityMedium:
		return model.RiskMedium
	case classify.SeverityLow:
		return model.RiskLow
	default:
		return model.RiskNone
	}
}

// Replay verifies and reevaluates all decision events without writing new events.
func (e *Engine) Replay(ctx context.Context, ledger *audit.Ledger) (audit.ReplayReport, error) {
	if ledger == nil {
		return audit.ReplayReport{}, fmt.Errorf("audit ledger is required")
	}
	return ledger.Replay(ctx, "decision", func(ctx context.Context, request model.EvaluationRequest) (model.DecisionResult, error) {
		return e.EvaluateWithoutAudit(ctx, request)
	})
}

// MarshalEvidence provides a canonical portable classification attachment.
func MarshalEvidence(report classify.Report) (json.RawMessage, error) {
	data, err := audit.CanonicalJSON(report)
	if err != nil {
		return nil, fmt.Errorf("canonicalize classification report: %w", err)
	}
	return json.RawMessage(data), nil
}
