// Package classify detects sensitive egress, destination trust, and prompt injection.
package classify

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Severity is an ordered impact level.
type Severity uint8

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Category identifies a family of security evidence.
type Category string

const (
	CategorySecret      Category = "secret"
	CategoryPII         Category = "pii"
	CategoryFinancial   Category = "financial"
	CategoryNetwork     Category = "network"
	CategoryDestination Category = "destination"
	CategoryInjection   Category = "prompt_injection"
	CategoryObfuscation Category = "obfuscation"
)

// Kind identifies a concrete detector. Values are stable for policy use.
type Kind string

const (
	KindAPIKey              Kind = "api_key"
	KindAccessToken         Kind = "access_token"
	KindPrivateKey          Kind = "private_key"
	KindCloudCredential     Kind = "cloud_credential"
	KindConnectionString    Kind = "connection_string"
	KindJWT                 Kind = "jwt"
	KindHighEntropy         Kind = "high_entropy"
	KindSensitiveQuery      Kind = "sensitive_url_query"
	KindEmail               Kind = "email"
	KindPhone               Kind = "phone"
	KindIPAddress           Kind = "ip_address"
	KindCreditCard          Kind = "credit_card"
	KindSSN                 Kind = "ssn"
	KindIBAN                Kind = "iban"
	KindBankAccount         Kind = "bank_account"
	KindIgnoreInstructions  Kind = "ignore_instructions"
	KindRoleOverride        Kind = "role_override"
	KindDataExfiltration    Kind = "data_exfiltration"
	KindEncodedInstruction  Kind = "encoded_instruction"
	KindToolAbuse           Kind = "tool_abuse"
	KindAuthorityClaim      Kind = "authority_claim"
	KindInstructionBoundary Kind = "instruction_boundary"
	KindSuspiciousLink      Kind = "suspicious_link"
)

// Span is a half-open byte interval in the original input.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

func (s Span) ValidFor(text string) bool {
	return s.Start >= 0 && s.End >= s.Start && s.End <= len(text)
}

// Finding is deterministic evidence emitted by a detector.
type Finding struct {
	Kind       Kind              `json:"kind"`
	Category   Category          `json:"category"`
	Severity   Severity          `json:"severity"`
	Confidence float64           `json:"confidence"`
	Span       Span              `json:"span"`
	Value      string            `json:"value,omitempty"`
	Message    string            `json:"message"`
	Source     string            `json:"source,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// TrustLevel describes confidence in an outbound destination.
type TrustLevel string

const (
	TrustTrusted   TrustLevel = "trusted"
	TrustInternal  TrustLevel = "internal"
	TrustUnknown   TrustLevel = "unknown"
	TrustUntrusted TrustLevel = "untrusted"
	TrustInvalid   TrustLevel = "invalid"
)

// DestinationResult is a normalized destination classification.
type DestinationResult struct {
	Input      string     `json:"input"`
	Normalized string     `json:"normalized,omitempty"`
	Scheme     string     `json:"scheme,omitempty"`
	Host       string     `json:"host,omitempty"`
	Port       string     `json:"port,omitempty"`
	Trust      TrustLevel `json:"trust"`
	Reason     string     `json:"reason"`
	Allowed    bool       `json:"allowed"`
}

// Summary aggregates findings without losing the detailed evidence.
type Summary struct {
	Total          int              `json:"total"`
	ByCategory     map[Category]int `json:"by_category"`
	ByKind         map[Kind]int     `json:"by_kind"`
	BySeverity     map[string]int   `json:"by_severity"`
	Highest        Severity         `json:"highest"`
	SensitiveCount int              `json:"sensitive_count"`
	InjectionCount int              `json:"injection_count"`
	ShouldBlock    bool             `json:"should_block"`
}

// Input contains independent channels analyzed by Classifier.
type Input struct {
	Content     string            `json:"content"`
	Prompt      string            `json:"prompt,omitempty"`
	Destination string            `json:"destination,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Report is the complete, sorted result of analysis.
type Report struct {
	Findings        []Finding         `json:"findings"`
	Destination     DestinationResult `json:"destination"`
	Summary         Summary           `json:"summary"`
	RedactedContent string            `json:"redacted_content,omitempty"`
	RedactedPrompt  string            `json:"redacted_prompt,omitempty"`
}

// Config controls filtering, trust, entropy, and redaction.
type Config struct {
	MinConfidence       float64
	MinSeverity         Severity
	EntropyThreshold    float64
	MinEntropyLength    int
	MaxEntropyLength    int
	TrustedDomains      []string
	UntrustedDomains    []string
	AllowedDestinations []string
	AllowValues         []string
	AllowPatterns       []string
	SensitiveQueryKeys  []string
	BlockSeverity       Severity
	RedactionText       string
	IncludeValues       bool
	DetectPrivateIPs    bool
}

// DefaultConfig returns conservative defaults suitable for outbound content.
func DefaultConfig() Config {
	return Config{
		MinConfidence:      0.55,
		MinSeverity:        SeverityLow,
		EntropyThreshold:   4.15,
		MinEntropyLength:   20,
		MaxEntropyLength:   256,
		SensitiveQueryKeys: []string{"access_token", "api_key", "apikey", "auth", "authorization", "client_secret", "code", "key", "password", "secret", "signature", "sig", "token"},
		BlockSeverity:      SeverityHigh,
		RedactionText:      "[REDACTED]",
		DetectPrivateIPs:   true,
	}
}

// Classifier is immutable after construction and safe for concurrent use.
type Classifier struct {
	config        Config
	allowPatterns []*regexp.Regexp
	allowValues   map[string]struct{}
	queryKeys     map[string]struct{}
}

// New validates and compiles a classifier configuration.
func New(config Config) (*Classifier, error) {
	if config.MinConfidence < 0 || config.MinConfidence > 1 {
		return nil, fmt.Errorf("min confidence must be between 0 and 1")
	}
	if config.MinSeverity > SeverityCritical {
		return nil, fmt.Errorf("invalid minimum severity %d", config.MinSeverity)
	}
	if config.BlockSeverity > SeverityCritical {
		return nil, fmt.Errorf("invalid block severity %d", config.BlockSeverity)
	}
	if config.EntropyThreshold <= 0 {
		config.EntropyThreshold = 4.15
	}
	if config.MinEntropyLength <= 0 {
		config.MinEntropyLength = 20
	}
	if config.MaxEntropyLength < config.MinEntropyLength {
		config.MaxEntropyLength = 256
	}
	if config.RedactionText == "" {
		config.RedactionText = "[REDACTED]"
	}
	if len(config.SensitiveQueryKeys) == 0 {
		config.SensitiveQueryKeys = DefaultConfig().SensitiveQueryKeys
	}
	c := &Classifier{
		config:      config,
		allowValues: make(map[string]struct{}, len(config.AllowValues)),
		queryKeys:   make(map[string]struct{}, len(config.SensitiveQueryKeys)),
	}
	for _, value := range config.AllowValues {
		if value = strings.TrimSpace(value); value != "" {
			c.allowValues[value] = struct{}{}
		}
	}
	for _, key := range config.SensitiveQueryKeys {
		if key = strings.ToLower(strings.TrimSpace(key)); key != "" {
			c.queryKeys[key] = struct{}{}
		}
	}
	for _, expression := range config.AllowPatterns {
		re, err := regexp.Compile(expression)
		if err != nil {
			return nil, fmt.Errorf("invalid allow pattern %q: %w", expression, err)
		}
		c.allowPatterns = append(c.allowPatterns, re)
	}
	return c, nil
}

// MustNewDefault creates a classifier with default configuration.
func MustNewDefault() *Classifier {
	c, err := New(DefaultConfig())
	if err != nil {
		panic(err)
	}
	return c
}

func (c *Classifier) allowed(value string) bool {
	if _, ok := c.allowValues[value]; ok {
		return true
	}
	for _, re := range c.allowPatterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func (c *Classifier) accept(f Finding) bool {
	return f.Confidence >= c.config.MinConfidence && f.Severity >= c.config.MinSeverity && !c.allowed(f.Value)
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Span.Start != b.Span.Start {
			return a.Span.Start < b.Span.Start
		}
		if a.Span.End != b.Span.End {
			return a.Span.End < b.Span.End
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Message < b.Message
	})
}
