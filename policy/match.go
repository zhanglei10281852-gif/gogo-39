package policy

import (
	"path"
	"strings"
	"time"

	"agentguard/model"
)

type matchInput struct {
	request  model.EvaluationRequest
	findings []model.Finding
	grants   []model.CapabilityGrant
	risk     model.Risk
}

func (c Condition) matches(input matchInput) bool {
	call := input.request.Call
	if c.Tool != nil && !c.Tool.matches(call.Tool) {
		return false
	}
	if c.Operation != nil && !c.Operation.matches(call.Operation) {
		return false
	}
	if c.Resource != nil && !c.Resource.matches(call.Resource) {
		return false
	}
	if c.Destination != nil && !c.Destination.matches(call.Destination) {
		return false
	}
	if c.Identity != nil && !c.Identity.matches(input.request.Identity) {
		return false
	}
	if c.Session != nil && !c.Session.matches(input.request.Session, input.request.EvaluatedAt) {
		return false
	}
	if c.Capability != nil && !c.Capability.matches(call.Capability, input.grants) {
		return false
	}
	if c.Risk != nil && !c.Risk.matches(input.risk, len(input.findings)) {
		return false
	}
	if c.Time != nil && !c.Time.matches(input.request.EvaluatedAt) {
		return false
	}
	if c.Finding != nil && !c.Finding.matches(input.findings) {
		return false
	}
	if !matchStringMap(c.Context, input.request.Context) {
		return false
	}
	for i := range c.All {
		if !c.All[i].matches(input) {
			return false
		}
	}
	if len(c.Any) > 0 {
		matched := false
		for i := range c.Any {
			if c.Any[i].matches(input) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return c.Not == nil || !c.Not.matches(input)
}

func (c StringCondition) matches(value string) bool {
	candidate := value
	equals := c.Equals
	if c.IgnoreCase {
		candidate = strings.ToLower(candidate)
	}
	normalize := func(s string) string {
		if c.IgnoreCase {
			return strings.ToLower(s)
		}
		return s
	}
	for _, excluded := range c.NotOneOf {
		if candidate == normalize(excluded) {
			return false
		}
	}
	if c.Present != nil && *c.Present != (value != "") {
		return false
	}
	positiveCount := 0
	positiveMatch := false
	if equals != nil {
		positiveCount++
		positiveMatch = positiveMatch || candidate == normalize(*equals)
	}
	for _, expected := range c.OneOf {
		positiveCount++
		if candidate == normalize(expected) {
			positiveMatch = true
		}
	}
	for _, prefix := range c.Prefixes {
		positiveCount++
		if strings.HasPrefix(candidate, normalize(prefix)) {
			positiveMatch = true
		}
	}
	for _, suffix := range c.Suffixes {
		positiveCount++
		if strings.HasSuffix(candidate, normalize(suffix)) {
			positiveMatch = true
		}
	}
	for _, pattern := range c.Patterns {
		positiveCount++
		matched, _ := path.Match(normalize(pattern), candidate)
		if matched {
			positiveMatch = true
		}
	}
	return positiveCount == 0 || positiveMatch
}

func (c SetCondition) matches(values []string) bool {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	if len(c.Any) > 0 {
		matched := false
		for _, value := range c.Any {
			if _, ok := set[value]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, value := range c.All {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	for _, value := range c.None {
		if _, ok := set[value]; ok {
			return false
		}
	}
	return true
}

func matchStringMap(conditions map[string]StringCondition, values map[string]string) bool {
	for key, condition := range conditions {
		value, present := values[key]
		if condition.Present != nil && *condition.Present != present {
			return false
		}
		if !present {
			value = ""
		}
		if !condition.matches(value) {
			return false
		}
	}
	return true
}

func (c IdentityCondition) matches(identity model.Identity) bool {
	if c.ID != nil && !c.ID.matches(identity.ID) {
		return false
	}
	if c.Kind != nil && !c.Kind.matches(identity.Kind) {
		return false
	}
	if c.Issuer != nil && !c.Issuer.matches(identity.Issuer) {
		return false
	}
	if c.Authenticated != nil && *c.Authenticated != identity.Authenticated {
		return false
	}
	if c.MinAssuranceLevel != nil && identity.AssuranceLevel < *c.MinAssuranceLevel {
		return false
	}
	if c.MaxAssuranceLevel != nil && identity.AssuranceLevel > *c.MaxAssuranceLevel {
		return false
	}
	if c.Roles != nil && !c.Roles.matches(identity.Roles) {
		return false
	}
	if c.Groups != nil && !c.Groups.matches(identity.Groups) {
		return false
	}
	return matchStringMap(c.Attributes, identity.Attributes)
}

func (c SessionCondition) matches(session model.Session, now time.Time) bool {
	if c.ID != nil && !c.ID.matches(session.ID) {
		return false
	}
	if c.ParentSessionID != nil && !c.ParentSessionID.matches(session.ParentSessionID) {
		return false
	}
	if c.Nonce != nil && !c.Nonce.matches(session.Nonce) {
		return false
	}
	if c.Revoked != nil && *c.Revoked != session.Revoked {
		return false
	}
	if c.MinSequence != nil && session.Sequence < *c.MinSequence {
		return false
	}
	if c.MaxSequence != nil && session.Sequence > *c.MaxSequence {
		return false
	}
	age := int64(now.Sub(session.CreatedAt) / time.Second)
	remaining := int64(session.ExpiresAt.Sub(now) / time.Second)
	if c.MinAgeSeconds != nil && age < *c.MinAgeSeconds {
		return false
	}
	if c.MaxAgeSeconds != nil && age > *c.MaxAgeSeconds {
		return false
	}
	if c.MinRemainingSeconds != nil && remaining < *c.MinRemainingSeconds {
		return false
	}
	if c.MaxRemainingSeconds != nil && remaining > *c.MaxRemainingSeconds {
		return false
	}
	return matchStringMap(c.Tags, session.Tags)
}

func (c CapabilityCondition) matches(name string, grants []model.CapabilityGrant) bool {
	if c.Name != nil && !c.Name.matches(name) {
		return false
	}
	filtered := make([]model.CapabilityGrant, 0, len(grants))
	for _, grant := range grants {
		if c.Delegable != nil && grant.Delegable != *c.Delegable {
			continue
		}
		if !matchStringMap(c.Constraints, grant.Constraints) {
			continue
		}
		filtered = append(filtered, grant)
	}
	ids := make([]string, 0, len(filtered))
	for _, grant := range filtered {
		ids = append(ids, grant.ID)
	}
	if c.GrantIDs != nil && !c.GrantIDs.matches(ids) {
		return false
	}
	minimum := 0
	if c.RequireGrant {
		minimum = 1
	}
	if c.MinValidGrants != nil {
		minimum = *c.MinValidGrants
	}
	return len(filtered) >= minimum
}

func (c RiskCondition) matches(risk model.Risk, count int) bool {
	if c.Exact != "" && risk != c.Exact {
		return false
	}
	if c.Minimum != "" && risk.Rank() < c.Minimum.Rank() {
		return false
	}
	if c.Maximum != "" && risk.Rank() > c.Maximum.Rank() {
		return false
	}
	if c.MinFindings != nil && count < *c.MinFindings {
		return false
	}
	if c.MaxFindings != nil && count > *c.MaxFindings {
		return false
	}
	return true
}

func (c TimeCondition) matches(at time.Time) bool {
	if c.NotBefore != nil && at.Before(*c.NotBefore) {
		return false
	}
	if c.Before != nil && !at.Before(*c.Before) {
		return false
	}
	zone := time.FixedZone("policy", c.UTCOffsetMinutes*60)
	local := at.In(zone)
	if len(c.Weekdays) > 0 {
		matched := false
		for _, value := range c.Weekdays {
			weekday, _ := parseWeekday(value)
			if local.Weekday() == weekday {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if c.DailyStart != "" {
		start, _ := parseClock(c.DailyStart)
		end, _ := parseClock(c.DailyEnd)
		minute := local.Hour()*60 + local.Minute()
		if start < end {
			if minute < start || minute >= end {
				return false
			}
		} else if start > end {
			if minute < start && minute >= end {
				return false
			}
		} else {
			// Equal endpoints intentionally represent the full day.
		}
	}
	return true
}

func (c FindingCondition) matches(findings []model.Finding) bool {
	count := 0
	for _, finding := range findings {
		if c.Codes != nil && !c.Codes.matches([]string{finding.Code}) {
			continue
		}
		if c.Categories != nil && !c.Categories.matches([]string{finding.Category}) {
			continue
		}
		if len(c.Risks) > 0 {
			matched := false
			for _, risk := range c.Risks {
				if finding.Risk == risk {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if c.RuleIDs != nil && !c.RuleIDs.matches([]string{finding.RuleID}) {
			continue
		}
		if c.Location != nil && !c.Location.matches(finding.Location) {
			continue
		}
		if !matchStringMap(c.Attributes, finding.Attributes) {
			continue
		}
		count++
	}
	minimum := 1
	if c.MaxCount != nil {
		minimum = 0
	}
	if c.MinCount != nil {
		minimum = *c.MinCount
	}
	if count < minimum {
		return false
	}
	return c.MaxCount == nil || count <= *c.MaxCount
}

func usableGrants(request model.EvaluationRequest) []model.CapabilityGrant {
	out := make([]model.CapabilityGrant, 0, len(request.Grants))
	for _, grant := range request.Grants {
		if grant.Validate(request.EvaluatedAt) != nil {
			continue
		}
		if grant.SubjectID != request.Identity.ID {
			continue
		}
		if grant.SessionID != "" && grant.SessionID != request.Session.ID {
			continue
		}
		if !grant.HasCapability(request.Call.Capability) {
			continue
		}
		if !scopeMatches(grant.ToolScopes, request.Call.Tool) {
			continue
		}
		if !scopeMatches(grant.ResourceScopes, request.Call.Resource) {
			continue
		}
		if !grantConstraintsMatch(grant.Constraints, request) {
			continue
		}
		out = append(out, grant)
	}
	return out
}

func scopeMatches(scopes []string, value string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, scope := range scopes {
		if scope == "*" || scope == value {
			return true
		}
		if matched, err := path.Match(scope, value); err == nil && matched {
			return true
		}
	}
	return false
}

func grantConstraintsMatch(constraints map[string]string, request model.EvaluationRequest) bool {
	for key, expected := range constraints {
		var actual string
		switch key {
		case "tool":
			actual = request.Call.Tool
		case "operation":
			actual = request.Call.Operation
		case "resource":
			actual = request.Call.Resource
		case "destination":
			actual = request.Call.Destination
		case "identity.kind":
			actual = request.Identity.Kind
		case "session.id":
			actual = request.Session.ID
		default:
			var ok bool
			actual, ok = request.Context[key]
			if !ok {
				return false
			}
		}
		if actual != expected {
			return false
		}
	}
	return true
}
