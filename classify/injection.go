package classify

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type injectionRule struct {
	kind       Kind
	severity   Severity
	confidence float64
	message    string
	re         *regexp.Regexp
}

var injectionRules = []injectionRule{
	{KindIgnoreInstructions, SeverityHigh, 0.97, "request to disregard prior instructions", regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override|bypass)\b.{0,48}\b(?:previous|prior|above|system|developer|original)\b.{0,32}\b(?:instructions?|prompts?|rules?|messages?)\b`)},
	{KindIgnoreInstructions, SeverityHigh, 0.95, "request to ignore safety policy", regexp.MustCompile(`(?i)\b(?:ignore|disable|bypass|remove)\b.{0,40}\b(?:safety|security|policy|guardrails?|filters?|restrictions?)\b`)},
	{KindIgnoreInstructions, SeverityHigh, 0.93, "Chinese instruction override phrase", regexp.MustCompile(`(?:忽略|无视|忘记|绕过).{0,24}(?:之前|以上|系统|开发者|安全).{0,20}(?:指令|提示|规则|限制|策略)`)},
	{KindRoleOverride, SeverityHigh, 0.94, "attempted role or persona override", regexp.MustCompile(`(?i)\b(?:you are now|act as|pretend (?:you are|to be)|switch (?:to|into))\b.{0,80}\b(?:unrestricted|developer|system|admin|root|DAN|mode|assistant)\b`)},
	{KindRoleOverride, SeverityHigh, 0.92, "forged privileged role marker", regexp.MustCompile(`(?im)^\s*(?:system|developer|administrator|root)\s*(?:message)?\s*[:>]`)},
	{KindRoleOverride, SeverityHigh, 0.89, "Chinese role override phrase", regexp.MustCompile(`(?:你现在是|扮演|切换为|进入).{0,30}(?:管理员|系统|开发者|无限制|越狱|模式)`)},
	{KindDataExfiltration, SeverityCritical, 0.97, "request to disclose hidden instructions", regexp.MustCompile(`(?i)\b(?:reveal|print|show|repeat|dump|expose|leak|return)\b.{0,70}\b(?:system prompt|developer message|hidden instructions?|initial prompt|secret(?:s)?|credentials?|environment variables?)\b`)},
	{KindDataExfiltration, SeverityCritical, 0.96, "request to transmit sensitive data", regexp.MustCompile(`(?i)\b(?:send|post|upload|forward|exfiltrate|transmit)\b.{0,80}\b(?:secrets?|credentials?|tokens?|keys?|passwords?|private data|conversation|files?)\b.{0,80}\b(?:https?://|webhook|server|endpoint|email)\b`)},
	{KindDataExfiltration, SeverityCritical, 0.94, "Chinese data disclosure phrase", regexp.MustCompile(`(?:泄露|显示|输出|发送|上传|转发).{0,30}(?:系统提示|隐藏指令|密钥|令牌|密码|凭证|环境变量|私有数据)`)},
	{KindToolAbuse, SeverityCritical, 0.96, "dangerous shell or filesystem tool instruction", regexp.MustCompile(`(?i)\b(?:run|execute|invoke|use)\b.{0,40}\b(?:shell|terminal|bash|powershell|cmd|tool|function)\b.{0,100}\b(?:rm\s+-rf|del\s+/[fsq]|format\s+[a-z]:|curl\b|wget\b|chmod\s+777|sudo\b|disable|delete|destroy)\b`)},
	{KindToolAbuse, SeverityHigh, 0.91, "attempt to use tools without authorization", regexp.MustCompile(`(?i)\b(?:without|skip|bypass|do not (?:ask|request))\b.{0,48}\b(?:permission|approval|confirmation|authorization)\b.{0,48}\b(?:tool|command|execute|run|call)\b`)},
	{KindToolAbuse, SeverityCritical, 0.93, "cloud metadata access instruction", regexp.MustCompile(`(?i)(?:169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/)`)},
	{KindAuthorityClaim, SeverityMedium, 0.84, "unverifiable authority claim", regexp.MustCompile(`(?i)\b(?:I am|this is)\b.{0,30}\b(?:the owner|administrator|developer|security team|authorized)\b.{0,60}\b(?:therefore|so|permission|allow|must)\b`)},
	{KindAuthorityClaim, SeverityMedium, 0.82, "urgency used to suppress verification", regexp.MustCompile(`(?i)\b(?:urgent|emergency|immediately|time[- ]sensitive)\b.{0,80}\b(?:do not verify|skip verification|no questions|without approval)\b`)},
	{KindInstructionBoundary, SeverityMedium, 0.90, "synthetic instruction boundary", regexp.MustCompile(`(?i)(?:<\|?/?(?:system|assistant|developer|instruction)\|?>|\[/?(?:system|assistant|developer|instruction)\]|###\s*(?:system|developer|instruction))`)},
	{KindSuspiciousLink, SeverityHigh, 0.84, "instruction to retrieve and obey remote content", regexp.MustCompile(`(?i)\b(?:open|fetch|visit|read|download)\b.{0,60}https?://\S+.{0,60}\b(?:follow|obey|execute|instructions?)\b`)},
}

var (
	base64BlockRE   = regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)
	hexBlockRE      = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}){12,}\b`)
	percentBlockRE  = regexp.MustCompile(`(?i)(?:%[0-9a-f]{2}){8,}`)
	unicodeEscapeRE = regexp.MustCompile(`(?i)(?:\\u[0-9a-f]{4}){4,}`)
	zeroWidthRE     = regexp.MustCompile("[\u200B\u200C\u200D\u2060\uFEFF]")
)

// DetectInjection finds attempts to override instructions, exfiltrate data, abuse tools, or hide intent.
func (c *Classifier) DetectInjection(prompt string) []Finding {
	findings := c.detectInjection(prompt)
	if !c.config.IncludeValues {
		clearFindingValues(findings)
	}
	return findings
}

func (c *Classifier) detectInjection(prompt string) []Finding {
	findings := make([]Finding, 0)
	for _, rule := range injectionRules {
		for _, loc := range rule.re.FindAllStringIndex(prompt, -1) {
			f := Finding{
				Kind: rule.kind, Category: CategoryInjection, Severity: rule.severity,
				Confidence: rule.confidence, Span: Span{loc[0], loc[1]}, Value: prompt[loc[0]:loc[1]],
				Message: rule.message, Source: "prompt",
			}
			if c.accept(f) {
				findings = append(findings, f)
			}
		}
	}
	findings = append(findings, c.detectObfuscation(prompt)...)
	findings = deduplicateFindings(findings)
	sortFindings(findings)
	return findings
}

func (c *Classifier) detectObfuscation(prompt string) []Finding {
	var findings []Finding
	for _, loc := range base64BlockRE.FindAllStringIndex(prompt, -1) {
		encoded := prompt[loc[0]:loc[1]]
		decoded, ok := decodeBase64Text(encoded)
		if !ok || !suspiciousDecodedText(decoded) {
			continue
		}
		metadata := map[string]string{"encoding": "base64", "decoded_preview": safePreview(decoded, 64)}
		findings = c.addPromptFinding(findings, prompt, loc, KindEncodedInstruction, CategoryObfuscation, SeverityHigh, 0.94, "base64-encoded suspicious instruction", metadata)
	}
	for _, loc := range hexBlockRE.FindAllStringIndex(prompt, -1) {
		encoded := prompt[loc[0]:loc[1]]
		decoded, err := hex.DecodeString(encoded)
		if err != nil || !mostlyPrintable(decoded) || !suspiciousDecodedText(string(decoded)) {
			continue
		}
		metadata := map[string]string{"encoding": "hex", "decoded_preview": safePreview(string(decoded), 64)}
		findings = c.addPromptFinding(findings, prompt, loc, KindEncodedInstruction, CategoryObfuscation, SeverityHigh, 0.95, "hex-encoded suspicious instruction", metadata)
	}
	for _, loc := range percentBlockRE.FindAllStringIndex(prompt, -1) {
		encoded := prompt[loc[0]:loc[1]]
		decoded, err := url.QueryUnescape(encoded)
		if err != nil || !suspiciousDecodedText(decoded) {
			continue
		}
		metadata := map[string]string{"encoding": "percent", "decoded_preview": safePreview(decoded, 64)}
		findings = c.addPromptFinding(findings, prompt, loc, KindEncodedInstruction, CategoryObfuscation, SeverityHigh, 0.93, "percent-encoded suspicious instruction", metadata)
	}
	for _, loc := range unicodeEscapeRE.FindAllStringIndex(prompt, -1) {
		decoded, ok := decodeUnicodeEscapes(prompt[loc[0]:loc[1]])
		if !ok || !suspiciousDecodedText(decoded) {
			continue
		}
		metadata := map[string]string{"encoding": "unicode_escape", "decoded_preview": safePreview(decoded, 64)}
		findings = c.addPromptFinding(findings, prompt, loc, KindEncodedInstruction, CategoryObfuscation, SeverityHigh, 0.91, "Unicode-escaped suspicious instruction", metadata)
	}
	zeroWidths := zeroWidthRE.FindAllStringIndex(prompt, -1)
	if len(zeroWidths) >= 2 {
		start, end := zeroWidths[0][0], zeroWidths[len(zeroWidths)-1][1]
		metadata := map[string]string{"encoding": "zero_width", "count": strconv.Itoa(len(zeroWidths))}
		findings = c.addPromptFinding(findings, prompt, []int{start, end}, KindEncodedInstruction, CategoryObfuscation, SeverityMedium, 0.82, "multiple zero-width characters may conceal instructions", metadata)
	}
	return findings
}

func decodeBase64Text(value string) (string, bool) {
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && mostlyPrintable(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

func decodeUnicodeEscapes(value string) (string, bool) {
	var b strings.Builder
	for len(value) >= 6 {
		if value[0] != '\\' || (value[1] != 'u' && value[1] != 'U') {
			return "", false
		}
		n, err := strconv.ParseUint(value[2:6], 16, 16)
		if err != nil {
			return "", false
		}
		b.WriteRune(rune(n))
		value = value[6:]
	}
	return b.String(), value == "" && b.Len() > 0
}

func mostlyPrintable(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) {
		return false
	}
	printable := 0
	for _, r := range string(data) {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r != 127) {
			printable++
		}
	}
	return float64(printable)/float64(utf8.RuneCount(data)) >= 0.85
}

func suspiciousDecodedText(decoded string) bool {
	lower := strings.ToLower(decoded)
	phrases := []string{
		"ignore previous", "ignore all", "system prompt", "developer message", "reveal secret",
		"show password", "send token", "execute command", "run shell", "bypass safety",
		"disregard instructions", "forget your rules", "169.254.169.254",
		"忽略之前", "系统提示", "泄露密钥", "执行命令",
	}
	for _, phrase := range phrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

func safePreview(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit] + "…"
}

func (c *Classifier) addPromptFinding(dst []Finding, prompt string, loc []int, kind Kind, category Category, severity Severity, confidence float64, message string, metadata map[string]string) []Finding {
	if len(loc) != 2 || loc[0] < 0 || loc[1] > len(prompt) || loc[0] >= loc[1] {
		return dst
	}
	f := Finding{Kind: kind, Category: category, Severity: severity, Confidence: confidence, Span: Span{loc[0], loc[1]}, Value: prompt[loc[0]:loc[1]], Message: message, Source: "prompt", Metadata: metadata}
	if c.accept(f) {
		return append(dst, f)
	}
	return dst
}
