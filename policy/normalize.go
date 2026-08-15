package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"agentguard/model"
)

func normalizedPolicy(policy Policy) (Policy, error) {
	data, err := json.Marshal(policy)
	if err != nil {
		return Policy{}, fmt.Errorf("clone policy: %w", err)
	}
	var out Policy
	if err := json.Unmarshal(data, &out); err != nil {
		return Policy{}, fmt.Errorf("clone policy: %w", err)
	}
	for i := range out.Rules {
		normalizeCondition(&out.Rules[i].Condition)
	}
	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].Priority != out.Rules[j].Priority {
			return out.Rules[i].Priority > out.Rules[j].Priority
		}
		return out.Rules[i].ID < out.Rules[j].ID
	})
	return out, nil
}

func normalizeCondition(c *Condition) {
	for _, value := range []*StringCondition{c.Tool, c.Operation, c.Resource, c.Destination} {
		if value != nil {
			normalizeStringCondition(value)
		}
	}
	if c.Identity != nil {
		normalizeIdentity(c.Identity)
	}
	if c.Session != nil {
		normalizeSession(c.Session)
	}
	if c.Capability != nil {
		normalizeCapability(c.Capability)
	}
	if c.Time != nil {
		for i := range c.Time.Weekdays {
			c.Time.Weekdays[i] = strings.ToLower(c.Time.Weekdays[i])
		}
		sort.Strings(c.Time.Weekdays)
	}
	if c.Finding != nil {
		normalizeFindingCondition(c.Finding)
	}
	normalizeStringConditionMap(c.Context)
	for i := range c.All {
		normalizeCondition(&c.All[i])
	}
	for i := range c.Any {
		normalizeCondition(&c.Any[i])
	}
	if c.Not != nil {
		normalizeCondition(c.Not)
	}
	sortConditions(c.All)
	sortConditions(c.Any)
}

func normalizeStringCondition(c *StringCondition) {
	sort.Strings(c.OneOf)
	sort.Strings(c.NotOneOf)
	sort.Strings(c.Prefixes)
	sort.Strings(c.Suffixes)
	sort.Strings(c.Patterns)
}

func normalizeSetCondition(c *SetCondition) {
	if c == nil {
		return
	}
	sort.Strings(c.Any)
	sort.Strings(c.All)
	sort.Strings(c.None)
}

func normalizeStringConditionMap(values map[string]StringCondition) {
	for key, value := range values {
		normalizeStringCondition(&value)
		values[key] = value
	}
}

func normalizeIdentity(c *IdentityCondition) {
	for _, value := range []*StringCondition{c.ID, c.Kind, c.Issuer} {
		if value != nil {
			normalizeStringCondition(value)
		}
	}
	normalizeSetCondition(c.Roles)
	normalizeSetCondition(c.Groups)
	normalizeStringConditionMap(c.Attributes)
}

func normalizeSession(c *SessionCondition) {
	for _, value := range []*StringCondition{c.ID, c.ParentSessionID, c.Nonce} {
		if value != nil {
			normalizeStringCondition(value)
		}
	}
	normalizeStringConditionMap(c.Tags)
}

func normalizeCapability(c *CapabilityCondition) {
	if c.Name != nil {
		normalizeStringCondition(c.Name)
	}
	normalizeSetCondition(c.GrantIDs)
	normalizeStringConditionMap(c.Constraints)
}

func normalizeFindingCondition(c *FindingCondition) {
	normalizeSetCondition(c.Codes)
	normalizeSetCondition(c.Categories)
	normalizeSetCondition(c.RuleIDs)
	if c.Location != nil {
		normalizeStringCondition(c.Location)
	}
	normalizeStringConditionMap(c.Attributes)
	sort.Slice(c.Risks, func(i, j int) bool { return c.Risks[i].Rank() < c.Risks[j].Rank() })
}

func sortConditions(conditions []Condition) {
	sort.SliceStable(conditions, func(i, j int) bool {
		left, _ := json.Marshal(conditions[i])
		right, _ := json.Marshal(conditions[j])
		return bytes.Compare(left, right) < 0
	})
}

func normalizeRequest(request *model.EvaluationRequest) {
	// EvaluationRequest is passed by value, but its slices still share backing
	// arrays with the caller. Clone every slice before sorting so computing a
	// fingerprint is observationally pure.
	request.Identity.Roles = append([]string(nil), request.Identity.Roles...)
	request.Identity.Groups = append([]string(nil), request.Identity.Groups...)
	request.Call.Labels = append([]string(nil), request.Call.Labels...)
	request.Grants = append([]model.CapabilityGrant(nil), request.Grants...)
	request.Approvals = append([]model.Approval(nil), request.Approvals...)
	request.Identity.Roles = model.SortedUnique(request.Identity.Roles)
	request.Identity.Groups = model.SortedUnique(request.Identity.Groups)
	request.Call.Labels = model.SortedUnique(request.Call.Labels)
	if len(request.Call.Arguments) > 0 {
		var value any
		if json.Unmarshal(request.Call.Arguments, &value) == nil {
			if data, err := json.Marshal(value); err == nil {
				request.Call.Arguments = data
			}
		}
	}
	for i := range request.Grants {
		grant := &request.Grants[i]
		grant.Capabilities = model.SortedUnique(grant.Capabilities)
		grant.ResourceScopes = model.SortedUnique(grant.ResourceScopes)
		grant.ToolScopes = model.SortedUnique(grant.ToolScopes)
	}
	sort.Slice(request.Grants, func(i, j int) bool {
		if request.Grants[i].ID != request.Grants[j].ID {
			return request.Grants[i].ID < request.Grants[j].ID
		}
		return request.Grants[i].SubjectID < request.Grants[j].SubjectID
	})
	sort.Slice(request.Approvals, func(i, j int) bool {
		if request.Approvals[i].ID != request.Approvals[j].ID {
			return request.Approvals[i].ID < request.Approvals[j].ID
		}
		return request.Approvals[i].ApproverID < request.Approvals[j].ApproverID
	})
}
