package classify

import (
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

// ClassifyDestination normalizes a network or filesystem target and assigns trust.
func (c *Classifier) ClassifyDestination(destination string) DestinationResult {
	input := strings.TrimSpace(destination)
	if input == "" {
		return DestinationResult{Input: destination, Trust: TrustUnknown, Reason: "no destination supplied", Allowed: true}
	}
	if looksLikeWindowsPath(input) {
		return c.classifyFilePath(input)
	}
	parsed, err := parseDestination(input)
	if err != nil {
		return DestinationResult{Input: destination, Trust: TrustInvalid, Reason: "destination cannot be parsed", Allowed: false}
	}
	result := DestinationResult{
		Input: destination, Normalized: parsed.String(), Scheme: strings.ToLower(parsed.Scheme),
		Host: normalizeHost(parsed.Hostname()), Port: parsed.Port(), Trust: TrustUnknown,
	}
	return c.classifyParsedDestination(parsed, result)
}

func parseDestination(input string) (*url.URL, error) {
	candidate := input
	if !strings.Contains(candidate, "://") && !strings.HasPrefix(candidate, "mailto:") && !strings.HasPrefix(candidate, "file:") {
		candidate = "https://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "file" {
		return u, nil
	}
	if u.Hostname() == "" {
		return nil, &url.Error{Op: "parse", URL: input, Err: errMissingHost{}}
	}
	return u, nil
}

type errMissingHost struct{}

func (errMissingHost) Error() string { return "missing host" }

func (c *Classifier) classifyParsedDestination(u *url.URL, result DestinationResult) DestinationResult {
	scheme := strings.ToLower(u.Scheme)
	host := result.Host
	if scheme == "file" {
		return c.classifyFilePath(u.Path)
	}
	if scheme != "https" && scheme != "http" && scheme != "ssh" && scheme != "sftp" && scheme != "mailto" {
		result.Trust = TrustUntrusted
		result.Reason = "scheme is not approved for egress"
		return result
	}
	if host == "169.254.169.254" || host == "metadata.google.internal" {
		result.Trust = TrustUntrusted
		result.Reason = "cloud instance metadata endpoint"
		return result
	}
	if domainMatchesAny(host, c.config.UntrustedDomains) {
		result.Trust = TrustUntrusted
		result.Reason = "host matches untrusted-domain policy"
		return result
	}
	if c.explicitlyAllowed(u, host) {
		result.Trust = TrustTrusted
		result.Reason = "destination matches explicit allowlist"
		result.Allowed = true
		return result
	}
	if domainMatchesAny(host, c.config.TrustedDomains) {
		if scheme == "http" {
			result.Trust = TrustUnknown
			result.Reason = "trusted host uses unencrypted HTTP"
			return result
		}
		result.Trust = TrustTrusted
		result.Reason = "host matches trusted-domain policy"
		result.Allowed = true
		return result
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if isPrivateIP(ip) {
			result.Trust = TrustInternal
			result.Reason = "private or local network address"
			result.Allowed = true
			return result
		}
		result.Trust = TrustUnknown
		result.Reason = "public IP address is not allowlisted"
		return result
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		result.Trust = TrustInternal
		result.Reason = "local hostname"
		result.Allowed = true
		return result
	}
	result.Trust = TrustUnknown
	result.Reason = "host is not present in trust policy"
	return result
}

func (c *Classifier) explicitlyAllowed(u *url.URL, host string) bool {
	for _, entry := range c.config.AllowedDestinations {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "://") {
			allowedURL, err := url.Parse(entry)
			if err == nil && strings.EqualFold(allowedURL.Scheme, u.Scheme) && domainMatch(host, normalizeHost(allowedURL.Hostname())) && portCompatible(u, allowedURL) && pathAllowed(u.Path, allowedURL.Path) {
				return true
			}
			continue
		}
		if domainMatch(host, normalizeHost(entry)) {
			return true
		}
	}
	return false
}

func portCompatible(actual, allowed *url.URL) bool {
	if allowed.Port() == "" {
		return true
	}
	return actual.Port() == allowed.Port()
}

func pathAllowed(actual, allowed string) bool {
	if allowed == "" || allowed == "/" {
		return true
	}
	cleanActual := strings.TrimSuffix(actual, "/")
	cleanAllowed := strings.TrimSuffix(allowed, "/")
	return cleanActual == cleanAllowed || strings.HasPrefix(cleanActual, cleanAllowed+"/")
}

func domainMatchesAny(host string, domains []string) bool {
	for _, domain := range domains {
		if domainMatch(host, normalizeHost(domain)) {
			return true
		}
	}
	return false
}

func domainMatch(host, domain string) bool {
	host = normalizeHost(host)
	domain = strings.TrimPrefix(normalizeHost(domain), "*.")
	if host == "" || domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return strings.Trim(host, "[]")
}

func looksLikeWindowsPath(value string) bool {
	return len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/')
}

func (c *Classifier) classifyFilePath(path string) DestinationResult {
	clean := filepath.Clean(path)
	result := DestinationResult{Input: path, Normalized: clean, Scheme: "file", Trust: TrustInternal, Allowed: true, Reason: "local filesystem destination"}
	lower := strings.ToLower(clean)
	for _, sensitive := range []string{".ssh", ".aws", ".kube", "windows\\system32", "/etc/", "/proc/", "/sys/"} {
		if strings.Contains(lower, sensitive) {
			result.Trust = TrustUntrusted
			result.Allowed = false
			result.Reason = "sensitive filesystem destination"
			break
		}
	}
	return result
}

// TrustedDomainList returns a normalized, sorted copy of configured trust entries.
func (c *Classifier) TrustedDomainList() []string {
	values := make([]string, 0, len(c.config.TrustedDomains))
	seen := make(map[string]struct{})
	for _, domain := range c.config.TrustedDomains {
		domain = normalizeHost(domain)
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		values = append(values, domain)
	}
	sort.Strings(values)
	return values
}
