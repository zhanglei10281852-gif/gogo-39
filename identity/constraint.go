package identity

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"agentguard/model"
)

// CheckConstraints validates a grant's constraints against request state.
// Unknown constraints fail closed.
func CheckConstraints(grant model.CapabilityGrant, principal model.Identity, session model.Session, context map[string]string, at time.Time) error {
	keys := make([]string, 0, len(grant.Constraints))
	for key := range grant.Constraints {
		keys = append(keys, key)
	}
	sortStrings(keys)
	for _, key := range keys {
		expected := strings.TrimSpace(grant.Constraints[key])
		if err := checkConstraint(strings.TrimSpace(key), expected, principal, session, context, at); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrConstraint, key, err)
		}
	}
	return nil
}

func checkConstraint(key, expected string, principal model.Identity, session model.Session, context map[string]string, at time.Time) error {
	switch key {
	case "identity.kind", "kind":
		return requireValue(principal.Kind, expected)
	case "identity.issuer", "issuer":
		return requireValue(principal.Issuer, expected)
	case "identity.authenticated":
		return requireValue(strconv.FormatBool(principal.Authenticated), expected)
	case "assurance_min", "minimum_assurance", "identity.assurance_min":
		minimum, err := strconv.Atoi(expected)
		if err != nil || minimum < 0 || minimum > 4 {
			return fmt.Errorf("invalid assurance minimum %q", expected)
		}
		if principal.AssuranceLevel < minimum {
			return fmt.Errorf("assurance %d is below %d", principal.AssuranceLevel, minimum)
		}
		return nil
	case "role", "identity.role":
		return requireAny(principal.Roles, expected)
	case "group", "identity.group":
		return requireAny(principal.Groups, expected)
	case "time.before":
		boundary, err := parseConstraintTime(expected)
		if err != nil {
			return err
		}
		if !at.Before(boundary) {
			return fmt.Errorf("time is not before %s", boundary.Format(time.RFC3339Nano))
		}
		return nil

	case "time.after":
		boundary, err := parseConstraintTime(expected)
		if err != nil {
			return err
		}
		if at.Before(boundary) {
			return fmt.Errorf("time is before %s", boundary.Format(time.RFC3339Nano))
		}
		return nil
	}
	for _, prefix := range []string{"identity.attribute.", "attribute."} {
		if strings.HasPrefix(key, prefix) {
			name := strings.TrimPrefix(key, prefix)
			return requireNamed(principal.Attributes, name, expected)
		}
	}
	for _, prefix := range []string{"session.tag.", "tag."} {
		if strings.HasPrefix(key, prefix) {
			name := strings.TrimPrefix(key, prefix)
			return requireNamed(session.Tags, name, expected)
		}
	}
	if strings.HasPrefix(key, "context.") {
		name := strings.TrimPrefix(key, "context.")
		return requireNamed(context, name, expected)
	}
	return fmt.Errorf("unsupported constraint")
}

func parseConstraintTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid RFC3339 time %q", value)
	}
	return parsed, nil
}

func requireNamed(values map[string]string, name, expected string) error {
	if name == "" {
		return fmt.Errorf("empty field name")
	}
	actual, ok := values[name]
	if !ok {
		return fmt.Errorf("field %q is absent", name)
	}
	return requireValue(actual, expected)
}

func requireAny(values []string, expected string) error {
	for _, actual := range values {
		if valueMatches(actual, expected) {
			return nil
		}
	}
	return fmt.Errorf("none of %v matches %q", values, expected)
}

func requireValue(actual, expected string) error {
	if valueMatches(actual, expected) {
		return nil
	}
	return fmt.Errorf("value %q does not match %q", actual, expected)
}

func valueMatches(actual, expression string) bool {
	negated := strings.HasPrefix(expression, "!")
	if negated {
		expression = strings.TrimPrefix(expression, "!")
	}
	matched := false
	for _, candidate := range strings.Split(expression, "|") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if GlobMatch(candidate, actual) {
			matched = true
			break
		}
	}
	if negated {
		return !matched
	}
	return matched
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
