package classify

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	emailRE = regexp.MustCompile(`(?i)\b[a-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b`)
	ipv4RE  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6RE  = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b`)
)

var secretRules = []struct {
	kind       Kind
	category   Category
	severity   Severity
	confidence float64
	message    string
	re         *regexp.Regexp
}{
	{KindCloudCredential, CategorySecret, SeverityCritical, 0.99, "AWS access key identifier", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
	{KindCloudCredential, CategorySecret, SeverityCritical, 0.99, "Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{KindAccessToken, CategorySecret, SeverityCritical, 0.99, "GitHub access token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b`)},
	{KindAccessToken, CategorySecret, SeverityCritical, 0.99, "GitLab access token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,255}\b`)},
	{KindAccessToken, CategorySecret, SeverityCritical, 0.99, "Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,200}\b`)},
	{KindAccessToken, CategorySecret, SeverityHigh, 0.94, "Bearer authorization token", regexp.MustCompile(`(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]{12,1000}`)},
	{KindAPIKey, CategorySecret, SeverityHigh, 0.88, "API key assignment", regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret)[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/-]{8,256}["']?`)},
	{KindAccessToken, CategorySecret, SeverityHigh, 0.87, "token assignment", regexp.MustCompile(`(?i)\b(?:access[_-]?token|auth[_-]?token|refresh[_-]?token)[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/=-]{8,1000}["']?`)},
	{KindPrivateKey, CategorySecret, SeverityCritical, 1.0, "PEM private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{KindCloudCredential, CategorySecret, SeverityCritical, 0.98, "AWS secret access key assignment", regexp.MustCompile(`(?i)\baws_secret_access_key[ \t]*[:=][ \t]*["']?[A-Za-z0-9/+=]{32,64}["']?`)},
	{KindCloudCredential, CategorySecret, SeverityCritical, 0.96, "cloud service account private key", regexp.MustCompile(`(?i)"private_key"[ \t]*:[ \t]*"-----BEGIN[^"\\]*(?:\\n[^"\\]*)+`)},
	{KindConnectionString, CategorySecret, SeverityCritical, 0.97, "credential-bearing database connection string", regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s/@:]+:[^\s/@]+@[^\s"'<>]+`)},
	{KindConnectionString, CategorySecret, SeverityHigh, 0.92, "cloud storage connection string", regexp.MustCompile(`(?i)\bDefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[^;\s]+(?:;EndpointSuffix=[^;\s]+)?`)},
}

var (
	jwtRE              = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}\b`)
	ssnRE              = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	phoneRE            = regexp.MustCompile(`(?:\+?\d{1,3}[-. ()]*)?(?:\d{2,4}[-. ()]*){2,4}\d{3,4}`)
	cardCandidateRE    = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	ibanRE             = regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
	bankLabeledRE      = regexp.MustCompile(`(?i)\b(?:account|acct|bank[_ -]?account|银行卡|银行账号)[ \t]*(?:number|no\.?|号码)?[ \t]*[:=：]?[ \t]*\d[\d -]{7,29}\d`)
	entropyCandidateRE = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,256}`)
	urlCandidateRE     = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
)

// DetectEgress finds secrets, personal information, financial identifiers, and network data.
func (c *Classifier) DetectEgress(text string) []Finding {
	findings := c.detectEgress(text)
	if !c.config.IncludeValues {
		clearFindingValues(findings)
	}
	return findings
}

func (c *Classifier) detectEgress(text string) []Finding {
	findings := make([]Finding, 0)
	for _, rule := range secretRules {
		for _, loc := range rule.re.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			f := Finding{Kind: rule.kind, Category: rule.category, Severity: rule.severity, Confidence: rule.confidence, Span: Span{loc[0], loc[1]}, Value: value, Message: rule.message, Source: "content"}
			if c.accept(f) {
				findings = append(findings, f)
			}
		}
	}
	findings = append(findings, c.detectJWTs(text)...)
	findings = append(findings, c.detectPII(text)...)
	findings = append(findings, c.detectFinancial(text)...)
	findings = append(findings, c.detectSensitiveURLs(text)...)
	findings = append(findings, c.detectEntropy(text, findings)...)
	findings = deduplicateFindings(findings)
	sortFindings(findings)
	return findings
}

func (c *Classifier) detectJWTs(text string) []Finding {
	var findings []Finding
	for _, loc := range jwtRE.FindAllStringIndex(text, -1) {
		value := text[loc[0]:loc[1]]
		parts := strings.Split(value, ".")
		confidence := 0.82
		metadata := map[string]string{"segments": strconv.Itoa(len(parts))}
		if len(parts) == 3 && validJWTJSON(parts[0]) && validJWTJSON(parts[1]) {
			confidence = 0.99
			metadata["json"] = "valid"
		}
		f := Finding{Kind: KindJWT, Category: CategorySecret, Severity: SeverityCritical, Confidence: confidence, Span: Span{loc[0], loc[1]}, Value: value, Message: "JSON Web Token", Source: "content", Metadata: metadata}
		if c.accept(f) {
			findings = append(findings, f)
		}
	}
	return findings
}

func validJWTJSON(segment string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}
	var object map[string]any
	return json.Unmarshal(decoded, &object) == nil && len(object) > 0
}

func (c *Classifier) detectPII(text string) []Finding {
	var findings []Finding
	for _, loc := range emailRE.FindAllStringIndex(text, -1) {
		findings = c.addFinding(findings, text, loc, KindEmail, CategoryPII, SeverityMedium, 0.98, "email address", nil)
	}
	for _, loc := range ssnRE.FindAllStringIndex(text, -1) {
		value := text[loc[0]:loc[1]]
		if validSSN(value) {
			findings = c.addFinding(findings, text, loc, KindSSN, CategoryPII, SeverityHigh, 0.98, "US Social Security number", nil)
		}
	}
	for _, loc := range phoneRE.FindAllStringIndex(text, -1) {
		value := text[loc[0]:loc[1]]
		digits := onlyDigits(value)
		if len(digits) < 10 || len(digits) > 15 || allSame(digits) || overlapsAny(loc, findings) {
			continue
		}
		confidence := 0.72
		if strings.HasPrefix(strings.TrimSpace(value), "+") {
			confidence = 0.88
		}
		findings = c.addFinding(findings, text, loc, KindPhone, CategoryPII, SeverityMedium, confidence, "telephone number", map[string]string{"digits": strconv.Itoa(len(digits))})
	}
	for _, re := range []*regexp.Regexp{ipv4RE, ipv6RE} {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			ip := net.ParseIP(value)
			if ip == nil || (!c.config.DetectPrivateIPs && isPrivateIP(ip)) {
				continue
			}
			metadata := map[string]string{"scope": ipScope(ip)}
			findings = c.addFinding(findings, text, loc, KindIPAddress, CategoryNetwork, SeverityLow, 0.96, "IP address", metadata)
		}
	}
	return findings
}

func validSSN(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 3 || parts[0] == "000" || parts[0] == "666" || strings.HasPrefix(parts[0], "9") || parts[1] == "00" || parts[2] == "0000" {
		return false
	}
	return true
}

func (c *Classifier) detectFinancial(text string) []Finding {
	var findings []Finding
	for _, loc := range cardCandidateRE.FindAllStringIndex(text, -1) {
		value := text[loc[0]:loc[1]]
		digits := onlyDigits(value)
		if len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits) && !allSame(digits) {
			metadata := map[string]string{"network": cardNetwork(digits), "last4": digits[len(digits)-4:]}
			findings = c.addFinding(findings, text, loc, KindCreditCard, CategoryFinancial, SeverityCritical, 0.99, "payment card number passing Luhn validation", metadata)
		}
	}
	for _, loc := range ibanRE.FindAllStringIndex(text, -1) {
		value := strings.ReplaceAll(strings.ToUpper(text[loc[0]:loc[1]]), " ", "")
		if validIBAN(value) {
			findings = c.addFinding(findings, text, loc, KindIBAN, CategoryFinancial, SeverityHigh, 0.98, "valid IBAN", map[string]string{"country": value[:2]})
		}
	}
	for _, loc := range bankLabeledRE.FindAllStringIndex(text, -1) {
		value := text[loc[0]:loc[1]]
		digits := onlyDigits(value)
		if len(digits) >= 8 && len(digits) <= 30 {
			findings = c.addFinding(findings, text, loc, KindBankAccount, CategoryFinancial, SeverityHigh, 0.86, "labeled bank account number", map[string]string{"digits": strconv.Itoa(len(digits))})
		}
	}
	return findings
}

func luhnValid(digits string) bool {
	sum := 0
	parity := len(digits) % 2
	for i, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
		n := int(r - '0')
		if i%2 == parity {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return len(digits) > 0 && sum%10 == 0
}

func cardNetwork(digits string) string {
	switch {
	case strings.HasPrefix(digits, "4"):
		return "visa"
	case hasNumericPrefixInRange(digits, 51, 55) || hasNumericPrefixInRange(digits, 2221, 2720):
		return "mastercard"
	case strings.HasPrefix(digits, "34") || strings.HasPrefix(digits, "37"):
		return "amex"
	case strings.HasPrefix(digits, "6011") || strings.HasPrefix(digits, "65"):
		return "discover"
	case strings.HasPrefix(digits, "62"):
		return "unionpay"
	default:
		return "unknown"
	}
}

func hasNumericPrefixInRange(value string, low, high int) bool {
	width := len(strconv.Itoa(low))
	if len(value) < width {
		return false
	}
	n, err := strconv.Atoi(value[:width])
	return err == nil && n >= low && n <= high
}

func validIBAN(value string) bool {
	if len(value) < 15 || len(value) > 34 {
		return false
	}
	rearranged := value[4:] + value[:4]
	remainder := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			remainder = (remainder*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			n := int(r-'A') + 10
			remainder = (remainder*100 + n) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

func (c *Classifier) detectSensitiveURLs(text string) []Finding {
	var findings []Finding
	for _, loc := range urlCandidateRE.FindAllStringIndex(text, -1) {
		raw := strings.TrimRight(text[loc[0]:loc[1]], ".,);]}")
		u, err := url.Parse(raw)
		if err != nil || u.RawQuery == "" {
			continue
		}
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			continue
		}
		for key, entries := range values {
			if _, sensitive := c.queryKeys[strings.ToLower(key)]; !sensitive {
				continue
			}
			for _, value := range entries {
				if value == "" {
					continue
				}
				start := loc[0] + strings.Index(raw, u.RawQuery)
				encoded := url.QueryEscape(value)
				offset := strings.Index(text[start:loc[0]+len(raw)], encoded)
				if offset < 0 {
					offset = strings.Index(text[start:loc[0]+len(raw)], value)
				}
				span := []int{loc[0], loc[0] + len(raw)}
				if offset >= 0 {
					span = []int{start + offset, start + offset + len(encoded)}
				}
				metadata := map[string]string{"parameter": key, "host": strings.ToLower(u.Hostname())}
				findings = c.addFinding(findings, text, span, KindSensitiveQuery, CategorySecret, SeverityHigh, 0.96, "sensitive value in URL query", metadata)
			}
		}
	}
	return findings
}

func (c *Classifier) detectEntropy(text string, existing []Finding) []Finding {
	var findings []Finding
	for _, loc := range entropyCandidateRE.FindAllStringIndex(text, -1) {
		value := text[loc[0]:loc[1]]
		if len(value) < c.config.MinEntropyLength || len(value) > c.config.MaxEntropyLength || overlapsAny(loc, existing) || looksOrdinary(value) {
			continue
		}
		entropy := ShannonEntropy(value)
		if entropy < c.config.EntropyThreshold {
			continue
		}
		confidence := 0.62 + math.Min(0.28, (entropy-c.config.EntropyThreshold)*0.15)
		metadata := map[string]string{"entropy": strconv.FormatFloat(entropy, 'f', 3, 64), "length": strconv.Itoa(len(value))}
		findings = c.addFinding(findings, text, loc, KindHighEntropy, CategorySecret, SeverityHigh, confidence, "high-entropy credential-like value", metadata)
	}
	return findings
}

// ShannonEntropy computes bits of information per byte.
func ShannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[byte]int)
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}
	length := float64(len(value))
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func looksOrdinary(value string) bool {
	if strings.Contains(value, "_") && (strings.HasPrefix(value, "http") || strings.Contains(value, "placeholder")) {
		return true
	}
	letters, digits, symbols := 0, 0, 0
	for _, r := range value {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		default:
			symbols++
		}
	}
	classes := 0
	if letters > 0 {
		classes++
	}
	if digits > 0 {
		classes++
	}
	if symbols > 0 {
		classes++
	}
	return classes < 2
}

func (c *Classifier) addFinding(dst []Finding, text string, loc []int, kind Kind, category Category, severity Severity, confidence float64, message string, metadata map[string]string) []Finding {
	if len(loc) != 2 || loc[0] < 0 || loc[1] > len(text) || loc[0] >= loc[1] {
		return dst
	}
	f := Finding{Kind: kind, Category: category, Severity: severity, Confidence: confidence, Span: Span{loc[0], loc[1]}, Value: text[loc[0]:loc[1]], Message: message, Source: "content", Metadata: metadata}
	if c.accept(f) {
		return append(dst, f)
	}
	return dst
}

func onlyDigits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func allSame(value string) bool {
	if len(value) < 2 {
		return true
	}
	for i := 1; i < len(value); i++ {
		if value[i] != value[0] {
			return false
		}
	}
	return true
}

func overlapsAny(loc []int, findings []Finding) bool {
	for _, f := range findings {
		if loc[0] < f.Span.End && loc[1] > f.Span.Start {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func ipScope(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link_local"
	case ip.IsMulticast():
		return "multicast"
	case ip.IsUnspecified():
		return "unspecified"
	default:
		return "public"
	}
}

func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		key := string(f.Kind) + "\x00" + f.Source + "\x00" + strconv.Itoa(f.Span.Start) + "\x00" + strconv.Itoa(f.Span.End)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func clearFindingValues(findings []Finding) {
	for i := range findings {
		findings[i].Value = ""
	}
}
