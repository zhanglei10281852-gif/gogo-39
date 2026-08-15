package identity

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// GlobMatch matches slash-normalized resources. '*' does not cross a slash,
// while '**' does. '?' matches one non-slash rune. Backslashes are normalized
// to slashes so snapshots behave consistently across operating systems.
func GlobMatch(pattern, value string) bool {
	pattern = strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/"))
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if pattern == "" {
		return value == ""
	}
	type state struct{ p, v int }
	memo := make(map[state]bool)
	seen := make(map[state]bool)
	var match func(int, int) bool
	match = func(pi, vi int) bool {
		key := state{pi, vi}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		if pi == len(pattern) {
			memo[key] = vi == len(value)
			return memo[key]
		}
		pr, ps := utf8.DecodeRuneInString(pattern[pi:])
		switch pr {
		case '*':
			next := pi + ps
			double := next < len(pattern) && pattern[next] == '*'
			if double {
				for next < len(pattern) && pattern[next] == '*' {
					next++
				}
			}
			if match(next, vi) {
				memo[key] = true
				return true
			}

			for cursor := vi; cursor < len(value); {
				vr, vs := utf8.DecodeRuneInString(value[cursor:])
				if !double && vr == '/' {
					break
				}
				cursor += vs
				if match(next, cursor) {
					memo[key] = true
					return true
				}
			}
		case '?':
			if vi < len(value) {
				vr, vs := utf8.DecodeRuneInString(value[vi:])
				memo[key] = vr != '/' && match(pi+ps, vi+vs)
				return memo[key]
			}
		default:
			if vi < len(value) {
				vr, vs := utf8.DecodeRuneInString(value[vi:])
				memo[key] = pr == vr && match(pi+ps, vi+vs)
				return memo[key]
			}
		}
		memo[key] = false
		return false
	}
	return match(0, 0)
}

// MatchResourceScope reports whether a resource is within at least one scope.
// An empty scope list is unrestricted.
func MatchResourceScope(scopes []string, resource string) bool {
	return MatchScope(scopes, resource)
}

// MatchToolScope reports whether a tool name is within at least one scope.
func MatchToolScope(scopes []string, tool string) bool {
	return MatchScope(scopes, tool)
}

// MatchScope reports whether value matches one normalized glob.
func MatchScope(scopes []string, value string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, scope := range scopes {
		if GlobMatch(scope, value) {
			return true
		}
	}
	return false
}

func literalPrefix(pattern string) string {
	if index := strings.IndexAny(pattern, "*?"); index >= 0 {
		return pattern[:index]
	}
	return pattern
}

// scopeSetContained conservatively establishes that every child pattern is
// bounded by some parent pattern. It deliberately rejects ambiguous narrowing.
func scopeSetContained(parent, child []string) bool {
	if len(parent) == 0 {
		return true
	}
	if len(child) == 0 {
		return false
	}
	for _, candidate := range child {
		covered := false
		for _, boundary := range parent {
			if patternContains(boundary, candidate) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func patternContains(parent, child string) bool {
	parent = strings.ReplaceAll(strings.TrimSpace(parent), "\\", "/")
	child = strings.ReplaceAll(strings.TrimSpace(child), "\\", "/")
	if parent == "*" || parent == "**" || parent == child {
		return true
	}
	prefix := literalPrefix(parent)
	if !strings.HasPrefix(child, prefix) {
		return false
	}
	if strings.HasSuffix(parent, "/**") {
		return true
	}
	if !strings.ContainsAny(child, "*?") {
		return GlobMatch(parent, child)
	}
	// Matching literal prefixes and equally restrictive wildcard shape is safe.
	return literalPrefix(child) == prefix && wildcardPower(parent) >= wildcardPower(child)
}

func wildcardPower(pattern string) int {
	power := strings.Count(pattern, "*") + strings.Count(pattern, "?")
	if strings.Contains(pattern, "**") {
		power += 1000
	}
	return power
}

func validateScopes(scopes []string, name string) error {
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "" {
			return wrap(ErrInvalid, "%s scope is empty", name)
		}
		if !utf8.ValidString(scope) {
			return fmt.Errorf("%w: %s scope is not UTF-8", ErrInvalid, name)
		}
	}
	return nil
}
