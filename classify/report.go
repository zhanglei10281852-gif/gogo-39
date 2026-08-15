package classify

import (
	"sort"
	"strings"
)

// Analyze classifies all input channels and returns sorted findings and redacted text.
func (c *Classifier) Analyze(input Input) Report {
	findings := c.detectEgress(input.Content)
	promptFindings := c.detectInjection(input.Prompt)
	findings = append(findings, promptFindings...)
	findings = append(findings, c.detectMetadata(input.Metadata)...)
	destination := c.ClassifyDestination(input.Destination)
	if input.Destination != "" {
		if finding, ok := c.destinationFinding(destination); ok && c.accept(finding) {
			findings = append(findings, finding)
		}
	}
	findings = deduplicateFindings(findings)
	sortFindings(findings)
	report := Report{
		Findings: findings, Destination: destination,
		RedactedContent: c.Redact(input.Content, findings),
		RedactedPrompt:  c.RedactSource(input.Prompt, findings, "prompt"),
	}
	report.Summary = Summarize(findings, c.config.BlockSeverity)
	if !c.config.IncludeValues {
		clearFindingValues(report.Findings)
	}
	return report
}

func (c *Classifier) detectMetadata(metadata map[string]string) []Finding {
	if len(metadata) == 0 {
		return nil
	}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var findings []Finding
	for _, key := range keys {
		value := metadata[key]
		channelFindings := c.detectEgress(value)
		for i := range channelFindings {
			channelFindings[i].Source = "metadata." + key
		}
		findings = append(findings, channelFindings...)
	}
	return findings
}

func (c *Classifier) destinationFinding(result DestinationResult) (Finding, bool) {
	f := Finding{
		Kind: KindSuspiciousLink, Category: CategoryDestination, Span: Span{0, len(result.Input)},
		Value: result.Input, Message: result.Reason, Source: "destination",
		Metadata: map[string]string{"host": result.Host, "scheme": result.Scheme, "trust": string(result.Trust)},
	}
	switch result.Trust {
	case TrustInvalid, TrustUntrusted:
		f.Severity = SeverityHigh
		f.Confidence = 0.97
	case TrustUnknown:
		f.Severity = SeverityMedium
		f.Confidence = 0.80
	default:
		return Finding{}, false
	}
	return f, true
}

// Redact replaces accepted content findings with the configured marker.
func (c *Classifier) Redact(text string, findings []Finding) string {
	return c.RedactSource(text, findings, "content")
}

// RedactSource redacts only spans belonging to source. Overlapping spans are merged.
func (c *Classifier) RedactSource(text string, findings []Finding, source string) string {
	spans := make([]Span, 0, len(findings))
	for _, finding := range findings {
		if finding.Source != source || !finding.Span.ValidFor(text) || finding.Span.Start == finding.Span.End {
			continue
		}
		spans = append(spans, finding.Span)
	}
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End < spans[j].End
	})
	merged := make([]Span, 0, len(spans))
	for _, span := range spans {
		last := len(merged) - 1
		if last >= 0 && span.Start <= merged[last].End {
			if span.End > merged[last].End {
				merged[last].End = span.End
			}
			continue
		}
		merged = append(merged, span)
	}
	var b strings.Builder
	previous := 0
	for _, span := range merged {
		b.WriteString(text[previous:span.Start])
		b.WriteString(c.config.RedactionText)
		previous = span.End
	}
	b.WriteString(text[previous:])
	return b.String()
}

// Summarize creates stable aggregate counts and a blocking recommendation.
func Summarize(findings []Finding, blockAt Severity) Summary {
	summary := Summary{
		Total: len(findings), ByCategory: make(map[Category]int),
		ByKind: make(map[Kind]int), BySeverity: make(map[string]int), Highest: SeverityInfo,
	}
	for _, finding := range findings {
		summary.ByCategory[finding.Category]++
		summary.ByKind[finding.Kind]++
		summary.BySeverity[finding.Severity.String()]++
		if finding.Severity > summary.Highest {
			summary.Highest = finding.Severity
		}
		if finding.Category == CategoryInjection || finding.Category == CategoryObfuscation {
			summary.InjectionCount++
		} else if finding.Category != CategoryDestination {
			summary.SensitiveCount++
		}
		if finding.Severity >= blockAt {
			summary.ShouldBlock = true
		}
	}
	return summary
}

// FilterFindings returns a copy containing findings at or above severity.
func FilterFindings(findings []Finding, minimum Severity) []Finding {
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Severity >= minimum {
			result = append(result, cloneFinding(finding))
		}
	}
	sortFindings(result)
	return result
}

func cloneFinding(f Finding) Finding {
	if f.Metadata != nil {
		metadata := make(map[string]string, len(f.Metadata))
		for key, value := range f.Metadata {
			metadata[key] = value
		}
		f.Metadata = metadata
	}
	return f
}
