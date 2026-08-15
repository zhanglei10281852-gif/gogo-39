// Package config defines AgentGuard's strict runtime JSON configuration.
package config

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"agentguard/classify"
	"agentguard/strictjson"
)

const CurrentVersion = 1

// Config controls local classification and output safety behavior.
type Config struct {
	Version        int                  `json:"version"`
	Classification ClassificationConfig `json:"classification"`
	Limits         LimitsConfig         `json:"limits"`
}

// ClassificationConfig is a JSON-friendly classifier configuration.
type ClassificationConfig struct {
	MinConfidence       float64  `json:"min_confidence"`
	MinSeverity         string   `json:"min_severity"`
	EntropyThreshold    float64  `json:"entropy_threshold"`
	MinEntropyLength    int      `json:"min_entropy_length"`
	MaxEntropyLength    int      `json:"max_entropy_length"`
	TrustedDomains      []string `json:"trusted_domains,omitempty"`
	UntrustedDomains    []string `json:"untrusted_domains,omitempty"`
	AllowedDestinations []string `json:"allowed_destinations,omitempty"`
	AllowValues         []string `json:"allow_values,omitempty"`
	AllowPatterns       []string `json:"allow_patterns,omitempty"`
	SensitiveQueryKeys  []string `json:"sensitive_query_keys,omitempty"`
	BlockSeverity       string   `json:"block_severity"`
	RedactionText       string   `json:"redaction_text"`
	IncludeValues       bool     `json:"include_values"`
	DetectPrivateIPs    bool     `json:"detect_private_ips"`
}

// LimitsConfig bounds untrusted input sizes at application boundaries.
type LimitsConfig struct {
	MaxPolicyBytes  int64 `json:"max_policy_bytes"`
	MaxRequestBytes int64 `json:"max_request_bytes"`
	MaxAuditBytes   int64 `json:"max_audit_bytes"`
}

// Default returns conservative offline defaults.
func Default() Config {
	base := classify.DefaultConfig()
	return Config{
		Version: CurrentVersion,
		Classification: ClassificationConfig{
			MinConfidence:      base.MinConfidence,
			MinSeverity:        base.MinSeverity.String(),
			EntropyThreshold:   base.EntropyThreshold,
			MinEntropyLength:   base.MinEntropyLength,
			MaxEntropyLength:   base.MaxEntropyLength,
			SensitiveQueryKeys: append([]string(nil), base.SensitiveQueryKeys...),
			BlockSeverity:      base.BlockSeverity.String(),
			RedactionText:      base.RedactionText,
			DetectPrivateIPs:   base.DetectPrivateIPs,
		},
		Limits: LimitsConfig{
			MaxPolicyBytes:  4 << 20,
			MaxRequestBytes: 16 << 20,
			MaxAuditBytes:   1 << 30,
		},
	}
}

// Decode rejects unknown fields, trailing values, and invalid settings.
func Decode(reader io.Reader) (Config, error) {
	var value Config
	if err := strictjson.Decode(reader, &value); err != nil {
		return Config{}, err
	}
	if err := value.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return value, nil
}

// Load reads a strict JSON configuration file.
func Load(path string) (Config, error) {
	var value Config
	if err := strictjson.DecodeFile(path, &value); err != nil {
		return Config{}, err
	}
	if err := value.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return value, nil
}

// Validate checks all invariants and compiles classifier expressions.
func (c Config) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Limits.MaxPolicyBytes <= 0 || c.Limits.MaxRequestBytes <= 0 || c.Limits.MaxAuditBytes <= 0 {
		return fmt.Errorf("all input limits must be positive")
	}
	if c.Limits.MaxPolicyBytes > 64<<20 {
		return fmt.Errorf("max_policy_bytes exceeds 64 MiB safety limit")
	}
	if c.Limits.MaxRequestBytes > 256<<20 {
		return fmt.Errorf("max_request_bytes exceeds 256 MiB safety limit")
	}
	if c.Limits.MaxAuditBytes < c.Limits.MaxRequestBytes {
		return fmt.Errorf("max_audit_bytes must not be smaller than max_request_bytes")
	}
	_, err := c.Classifier()
	return err
}

// Classifier validates and constructs the immutable classifier.
func (c Config) Classifier() (*classify.Classifier, error) {
	minimum, err := parseSeverity(c.Classification.MinSeverity)
	if err != nil {
		return nil, fmt.Errorf("min_severity: %w", err)
	}
	block, err := parseSeverity(c.Classification.BlockSeverity)
	if err != nil {
		return nil, fmt.Errorf("block_severity: %w", err)
	}
	settings := classify.Config{
		MinConfidence:       c.Classification.MinConfidence,
		MinSeverity:         minimum,
		EntropyThreshold:    c.Classification.EntropyThreshold,
		MinEntropyLength:    c.Classification.MinEntropyLength,
		MaxEntropyLength:    c.Classification.MaxEntropyLength,
		TrustedDomains:      normalized(c.Classification.TrustedDomains),
		UntrustedDomains:    normalized(c.Classification.UntrustedDomains),
		AllowedDestinations: normalized(c.Classification.AllowedDestinations),
		AllowValues:         append([]string(nil), c.Classification.AllowValues...),
		AllowPatterns:       append([]string(nil), c.Classification.AllowPatterns...),
		SensitiveQueryKeys:  normalized(c.Classification.SensitiveQueryKeys),
		BlockSeverity:       block,
		RedactionText:       c.Classification.RedactionText,
		IncludeValues:       c.Classification.IncludeValues,
		DetectPrivateIPs:    c.Classification.DetectPrivateIPs,
	}
	classifier, err := classify.New(settings)
	if err != nil {
		return nil, fmt.Errorf("classification: %w", err)
	}
	return classifier, nil
}

func parseSeverity(value string) (classify.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "info", "none":
		return classify.SeverityInfo, nil
	case "low":
		return classify.SeverityLow, nil
	case "medium":
		return classify.SeverityMedium, nil
	case "high":
		return classify.SeverityHigh, nil
	case "critical":
		return classify.SeverityCritical, nil
	default:
		return 0, fmt.Errorf("invalid severity %q", value)
	}
}

func normalized(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
