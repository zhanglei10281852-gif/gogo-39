package policy

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"agentguard/model"
)

const maxConditionDepth = 32

// Validate checks the complete policy, including recursively nested conditions.
func (p Policy) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return errors.New("policy id is required")
	}
	if strings.TrimSpace(p.Version) == "" {
		return errors.New("policy version is required")
	}
	if p.Rules == nil {
		return errors.New("policy rules is required (use an empty array for no rules)")
	}
	if err := validateEffect(p.DefaultEffect, "default_effect"); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for i := range p.Rules {
		if err := p.Rules[i].validate(0); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		if _, exists := seen[p.Rules[i].ID]; exists {
			return fmt.Errorf("rules[%d]: duplicate rule id %q", i, p.Rules[i].ID)
		}
		seen[p.Rules[i].ID] = struct{}{}
	}
	return nil
}

func validateEffect(effect Effect, field string) error {
	switch effect {
	case EffectAllow, EffectDeny, EffectRequireApproval:
		return nil
	default:
		return fmt.Errorf("%s must be allow, deny, or require_approval", field)
	}
}

func (r Rule) validate(depth int) error {
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("rule id is required")
	}
	if err := validateEffect(r.Effect, "effect"); err != nil {
		return err
	}
	if err := r.Condition.validate(depth + 1); err != nil {
		return fmt.Errorf("condition: %w", err)
	}
	return nil
}

func (c Condition) validate(depth int) error {
	if depth > maxConditionDepth {
		return fmt.Errorf("condition nesting exceeds %d", maxConditionDepth)
	}
	fields := 0
	stringsToCheck := []*StringCondition{c.Tool, c.Operation, c.Resource, c.Destination}
	for _, condition := range stringsToCheck {
		if condition != nil {
			fields++
			if err := condition.validate(); err != nil {
				return err
			}
		}
	}
	if c.Identity != nil {
		fields++
		if err := c.Identity.validate(); err != nil {
			return fmt.Errorf("identity: %w", err)
		}
	}
	if c.Session != nil {
		fields++
		if err := c.Session.validate(); err != nil {
			return fmt.Errorf("session: %w", err)
		}
	}
	if c.Capability != nil {
		fields++
		if err := c.Capability.validate(); err != nil {
			return fmt.Errorf("capability: %w", err)
		}
	}
	if c.Risk != nil {
		fields++
		if err := c.Risk.validate(); err != nil {
			return fmt.Errorf("risk: %w", err)
		}
	}
	if c.Time != nil {
		fields++
		if err := c.Time.validate(); err != nil {
			return fmt.Errorf("time: %w", err)
		}
	}
	if c.Finding != nil {
		fields++
		if err := c.Finding.validate(); err != nil {
			return fmt.Errorf("finding: %w", err)
		}
	}
	if len(c.Context) > 0 {
		fields++
		if err := validateStringMap(c.Context, "context"); err != nil {
			return err
		}
	}
	if len(c.All) > 0 {
		fields++
		for i := range c.All {
			if err := c.All[i].validate(depth + 1); err != nil {
				return fmt.Errorf("all[%d]: %w", i, err)
			}
		}
	}
	if len(c.Any) > 0 {
		fields++
		for i := range c.Any {
			if err := c.Any[i].validate(depth + 1); err != nil {
				return fmt.Errorf("any[%d]: %w", i, err)
			}
		}
	}
	if c.Not != nil {
		fields++
		if err := c.Not.validate(depth + 1); err != nil {
			return fmt.Errorf("not: %w", err)
		}
	}
	if fields == 0 {
		return errors.New("condition must contain at least one predicate")
	}
	return nil
}

func (c StringCondition) validate() error {
	positive := c.Equals != nil || len(c.OneOf) > 0 || len(c.Prefixes) > 0 ||
		len(c.Suffixes) > 0 || len(c.Patterns) > 0 || c.Present != nil
	if !positive && len(c.NotOneOf) == 0 {
		return errors.New("string condition must contain a matcher")
	}
	for i, pattern := range c.Patterns {
		if pattern == "" {
			return fmt.Errorf("patterns[%d] must not be empty", i)
		}
		if _, err := path.Match(pattern, "validation-value"); err != nil {
			return fmt.Errorf("patterns[%d]: %w", i, err)
		}
	}
	return validateNoEmptyLists(map[string][]string{
		"one_of": c.OneOf, "not_one_of": c.NotOneOf,
		"prefixes": c.Prefixes, "suffixes": c.Suffixes,
	})
}

func validateNoEmptyLists(lists map[string][]string) error {
	keys := make([]string, 0, len(lists))
	for key := range lists {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		seen := make(map[string]struct{}, len(lists[key]))
		for i, value := range lists[key] {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s[%d] must not be empty", key, i)
			}
			if _, ok := seen[value]; ok {
				return fmt.Errorf("%s contains duplicate %q", key, value)
			}
			seen[value] = struct{}{}
		}
	}
	return nil
}

func (c SetCondition) validate() error {
	if len(c.Any)+len(c.All)+len(c.None) == 0 {
		return errors.New("set condition must contain any, all, or none")
	}
	return validateNoEmptyLists(map[string][]string{"any": c.Any, "all": c.All, "none": c.None})
}

func validateStringMap(values map[string]StringCondition, field string) error {
	for key, condition := range values {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("%s contains an empty key", field)
		}
		if err := condition.validate(); err != nil {
			return fmt.Errorf("%s[%q]: %w", field, key, err)
		}
	}
	return nil
}

func (c IdentityCondition) validate() error {
	count := 0
	for name, value := range map[string]*StringCondition{"id": c.ID, "kind": c.Kind, "issuer": c.Issuer} {
		if value != nil {
			count++
			if err := value.validate(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if c.Authenticated != nil {
		count++
	}
	if c.MinAssuranceLevel != nil {
		count++
		if *c.MinAssuranceLevel < 0 || *c.MinAssuranceLevel > 4 {
			return errors.New("min_assurance_level must be between 0 and 4")
		}
	}
	if c.MaxAssuranceLevel != nil {
		count++
		if *c.MaxAssuranceLevel < 0 || *c.MaxAssuranceLevel > 4 {
			return errors.New("max_assurance_level must be between 0 and 4")
		}
	}
	if c.MinAssuranceLevel != nil && c.MaxAssuranceLevel != nil && *c.MinAssuranceLevel > *c.MaxAssuranceLevel {
		return errors.New("min_assurance_level exceeds max_assurance_level")
	}
	for name, value := range map[string]*SetCondition{"roles": c.Roles, "groups": c.Groups} {
		if value != nil {
			count++
			if err := value.validate(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if len(c.Attributes) > 0 {
		count++
		if err := validateStringMap(c.Attributes, "attributes"); err != nil {
			return err
		}
	}
	if count == 0 {
		return errors.New("identity condition must contain a predicate")
	}
	return nil
}

func (c SessionCondition) validate() error {
	count := 0
	for name, value := range map[string]*StringCondition{"id": c.ID, "parent_session_id": c.ParentSessionID, "nonce": c.Nonce} {
		if value != nil {
			count++
			if err := value.validate(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if c.Revoked != nil {
		count++
	}
	if c.MinSequence != nil {
		count++
	}
	if c.MaxSequence != nil {
		count++
	}
	if c.MinSequence != nil && c.MaxSequence != nil && *c.MinSequence > *c.MaxSequence {
		return errors.New("min_sequence exceeds max_sequence")
	}
	durations := map[string]*int64{
		"min_age_seconds": c.MinAgeSeconds, "max_age_seconds": c.MaxAgeSeconds,
		"min_remaining_seconds": c.MinRemainingSeconds, "max_remaining_seconds": c.MaxRemainingSeconds,
	}
	for name, value := range durations {
		if value != nil {
			count++
			if *value < 0 {
				return fmt.Errorf("%s must not be negative", name)
			}
		}
	}
	if c.MinAgeSeconds != nil && c.MaxAgeSeconds != nil && *c.MinAgeSeconds > *c.MaxAgeSeconds {
		return errors.New("min_age_seconds exceeds max_age_seconds")
	}
	if c.MinRemainingSeconds != nil && c.MaxRemainingSeconds != nil && *c.MinRemainingSeconds > *c.MaxRemainingSeconds {
		return errors.New("min_remaining_seconds exceeds max_remaining_seconds")
	}
	if len(c.Tags) > 0 {
		count++
		if err := validateStringMap(c.Tags, "tags"); err != nil {
			return err
		}
	}
	if count == 0 {
		return errors.New("session condition must contain a predicate")
	}
	return nil
}

func (c CapabilityCondition) validate() error {
	count := 0
	if c.Name != nil {
		count++
		if err := c.Name.validate(); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}
	if c.RequireGrant {
		count++
	}
	if c.GrantIDs != nil {
		count++
		if err := c.GrantIDs.validate(); err != nil {
			return fmt.Errorf("grant_ids: %w", err)
		}
	}
	if c.MinValidGrants != nil {
		count++
		if *c.MinValidGrants < 0 {
			return errors.New("min_valid_grants must not be negative")
		}
	}
	if c.Delegable != nil {
		count++
	}
	if len(c.Constraints) > 0 {
		count++
		if err := validateStringMap(c.Constraints, "constraints"); err != nil {
			return err
		}
	}
	if count == 0 {
		return errors.New("capability condition must contain a predicate")
	}
	return nil
}

func validRiskOrEmpty(risk model.Risk) bool { return risk == "" || risk.Rank() >= 0 }

func (c RiskCondition) validate() error {
	if !validRiskOrEmpty(c.Minimum) {
		return fmt.Errorf("invalid minimum risk %q", c.Minimum)
	}
	if !validRiskOrEmpty(c.Maximum) {
		return fmt.Errorf("invalid maximum risk %q", c.Maximum)
	}
	if !validRiskOrEmpty(c.Exact) {
		return fmt.Errorf("invalid exact risk %q", c.Exact)
	}
	if c.Minimum == "" && c.Maximum == "" && c.Exact == "" && c.MinFindings == nil && c.MaxFindings == nil {
		return errors.New("risk condition must contain a predicate")
	}
	if c.Minimum != "" && c.Maximum != "" && c.Minimum.Rank() > c.Maximum.Rank() {
		return errors.New("minimum risk exceeds maximum risk")
	}
	if c.MinFindings != nil && *c.MinFindings < 0 {
		return errors.New("min_findings must not be negative")
	}
	if c.MaxFindings != nil && *c.MaxFindings < 0 {
		return errors.New("max_findings must not be negative")
	}
	if c.MinFindings != nil && c.MaxFindings != nil && *c.MinFindings > *c.MaxFindings {
		return errors.New("min_findings exceeds max_findings")
	}
	return nil
}

func (c TimeCondition) validate() error {
	if c.NotBefore == nil && c.Before == nil && len(c.Weekdays) == 0 && c.DailyStart == "" && c.DailyEnd == "" {
		return errors.New("time condition must contain a predicate")
	}
	if c.NotBefore != nil && c.Before != nil && !c.Before.After(*c.NotBefore) {
		return errors.New("before must follow not_before")
	}
	if c.UTCOffsetMinutes < -14*60 || c.UTCOffsetMinutes > 14*60 {
		return errors.New("utc_offset_minutes must be between -840 and 840")
	}
	seen := make(map[time.Weekday]struct{}, len(c.Weekdays))
	for i, value := range c.Weekdays {
		weekday, ok := parseWeekday(value)
		if !ok {
			return fmt.Errorf("weekdays[%d] is invalid", i)
		}
		if _, exists := seen[weekday]; exists {
			return fmt.Errorf("weekdays contains duplicate %q", value)
		}
		seen[weekday] = struct{}{}
	}
	if (c.DailyStart == "") != (c.DailyEnd == "") {
		return errors.New("daily_start and daily_end must be supplied together")
	}
	if c.DailyStart != "" {
		if _, err := parseClock(c.DailyStart); err != nil {
			return fmt.Errorf("daily_start: %w", err)
		}
		if _, err := parseClock(c.DailyEnd); err != nil {
			return fmt.Errorf("daily_end: %w", err)
		}
	}
	return nil
}

func (c FindingCondition) validate() error {
	count := 0
	for name, value := range map[string]*SetCondition{"codes": c.Codes, "categories": c.Categories, "rule_ids": c.RuleIDs} {
		if value != nil {
			count++
			if err := value.validate(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if len(c.Risks) > 0 {
		count++
		seen := make(map[model.Risk]struct{}, len(c.Risks))
		for i, risk := range c.Risks {
			if risk.Rank() < 0 {
				return fmt.Errorf("risks[%d] is invalid", i)
			}
			if _, ok := seen[risk]; ok {
				return fmt.Errorf("risks contains duplicate %q", risk)
			}
			seen[risk] = struct{}{}
		}
	}
	if c.Location != nil {
		count++
		if err := c.Location.validate(); err != nil {
			return fmt.Errorf("location: %w", err)
		}
	}
	if len(c.Attributes) > 0 {
		count++
		if err := validateStringMap(c.Attributes, "attributes"); err != nil {
			return err
		}
	}
	if c.MinCount != nil {
		count++
		if *c.MinCount < 0 {
			return errors.New("min_count must not be negative")
		}
	}
	if c.MaxCount != nil {
		count++
		if *c.MaxCount < 0 {
			return errors.New("max_count must not be negative")
		}
	}
	if c.MinCount != nil && c.MaxCount != nil && *c.MinCount > *c.MaxCount {
		return errors.New("min_count exceeds max_count")
	}
	if count == 0 {
		return errors.New("finding condition must contain a predicate")
	}
	return nil
}

func parseWeekday(value string) (time.Weekday, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sunday", "sun":
		return time.Sunday, true
	case "monday", "mon":
		return time.Monday, true
	case "tuesday", "tue":
		return time.Tuesday, true
	case "wednesday", "wed":
		return time.Wednesday, true
	case "thursday", "thu":
		return time.Thursday, true
	case "friday", "fri":
		return time.Friday, true
	case "saturday", "sat":
		return time.Saturday, true
	default:
		return 0, false
	}
}

func parseClock(value string) (int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return 0, errors.New("must use HH:MM in 24-hour time")
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}
