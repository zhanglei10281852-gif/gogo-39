package approval

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

func validateRecord(record Record) error {
	if err := record.Request.validate(); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if !record.Status.valid() {
		return fmt.Errorf("invalid approval status %q", record.Status)
	}
	if err := validateCanonicalRequest(record.Request); err != nil {
		return err
	}
	if err := validateVotes(record); err != nil {
		return err
	}
	if err := validateState(record); err != nil {
		return err
	}
	if len(record.Signature) != 64 || strings.ToLower(record.Signature) != record.Signature {
		return errors.New("approval signature must be a lowercase SHA-256 digest")
	}
	if expected := signRecord(record); record.Signature != expected {
		return errors.New("approval signature verification failed")
	}
	return nil
}

func validateCanonicalRequest(request Request) error {
	if request.CreatedAt != canonicalTime(request.CreatedAt) || request.ExpiresAt != canonicalTime(request.ExpiresAt) {
		return errors.New("approval request timestamps are not canonical UTC values")
	}
	if !sort.StringsAreSorted(request.Requirements.Roles) || !sort.StringsAreSorted(request.Requirements.Groups) {
		return errors.New("approval requirements must be sorted")
	}
	if request.ID != strings.TrimSpace(request.ID) || request.RequestID != strings.TrimSpace(request.RequestID) ||
		request.CallID != strings.TrimSpace(request.CallID) || request.SubjectID != strings.TrimSpace(request.SubjectID) ||
		request.PolicyID != strings.TrimSpace(request.PolicyID) || request.Reason != strings.TrimSpace(request.Reason) {
		return errors.New("approval request string fields must be trimmed")
	}
	return nil
}
func validateVotes(record Record) error {
	seen := make(map[string]struct{}, len(record.Votes))
	var previous time.Time
	negative := 0
	for index, vote := range record.Votes {
		if vote.ApproverID == "" || vote.ApproverID != strings.TrimSpace(vote.ApproverID) {
			return fmt.Errorf("vote %d has invalid approver_id", index)
		}
		if _, exists := seen[vote.ApproverID]; exists {
			return fmt.Errorf("duplicate vote from %q", vote.ApproverID)
		}
		seen[vote.ApproverID] = struct{}{}
		if vote.Assurance < 0 || vote.Assurance > 4 {
			return fmt.Errorf("vote %d has invalid assurance", index)
		}
		if vote.Assurance < record.Request.Requirements.MinAssurance {
			return fmt.Errorf("vote %d does not meet assurance requirement", index)
		}
		if vote.ApproverID == record.Request.SubjectID && !record.Request.Requirements.AllowSelfApproval {
			return fmt.Errorf("vote %d violates self-approval restriction", index)
		}
		if !vote.DecidedAt.Equal(canonicalTime(vote.DecidedAt)) || vote.DecidedAt.Before(record.Request.CreatedAt) || !vote.DecidedAt.Before(record.Request.ExpiresAt) {
			return fmt.Errorf("vote %d has invalid decision time", index)
		}
		if !previous.IsZero() && vote.DecidedAt.Before(previous) {
			return errors.New("approval votes are not chronological")
		}
		previous = vote.DecidedAt
		if vote.Reason != strings.TrimSpace(vote.Reason) {
			return fmt.Errorf("vote %d reason must be trimmed", index)
		}
		if err := validateVoteAuthorization(record.Request.Requirements, vote, index); err != nil {
			return err
		}
		if !vote.Approved {
			negative++
			if index != len(record.Votes)-1 {
				return errors.New("rejection vote must be the final vote")
			}
		}
	}
	if negative > 1 {
		return errors.New("approval record contains multiple rejection votes")
	}
	return nil
}

func validateVoteAuthorization(requirements Requirements, vote Vote, index int) error {
	if !sort.StringsAreSorted(vote.Roles) || !sort.StringsAreSorted(vote.Groups) {
		return fmt.Errorf("vote %d roles and groups must be sorted", index)
	}
	if err := validateNames("vote role", vote.Roles); err != nil {
		return err
	}
	if err := validateNames("vote group", vote.Groups); err != nil {
		return err
	}
	if len(requirements.Roles) > 0 && !hasAny(vote.Roles, requirements.Roles) {
		return fmt.Errorf("vote %d lacks required role", index)
	}
	if len(requirements.Groups) > 0 && !hasAny(vote.Groups, requirements.Groups) {
		return fmt.Errorf("vote %d lacks required group", index)
	}
	return nil
}
func validateState(record Record) error {
	affirmative := affirmativeVotes(record.Votes)
	negative := len(record.Votes) - affirmative
	decisionSet := !record.DecidedAt.IsZero()
	expirationSet := !record.ExpiredAt.IsZero()
	consumptionSet := !record.ConsumedAt.IsZero()
	if decisionSet && record.DecidedAt != canonicalTime(record.DecidedAt) {
		return errors.New("approval decision timestamp is not canonical")
	}
	if expirationSet && record.ExpiredAt != canonicalTime(record.ExpiredAt) {
		return errors.New("approval expiration timestamp is not canonical")
	}
	if consumptionSet && record.ConsumedAt != canonicalTime(record.ConsumedAt) {
		return errors.New("approval consumption timestamp is not canonical")
	}
	if record.CancelledBy != "" && record.CancelledBy != strings.TrimSpace(record.CancelledBy) {
		return errors.New("cancelled_by must be trimmed")
	}

	switch record.Status {
	case StatusPending:
		if affirmative >= record.Request.Requirements.Quorum || negative != 0 || decisionSet || expirationSet || consumptionSet || record.CancelledBy != "" {
			return errors.New("pending approval has terminal state data")
		}
	case StatusApproved:
		if affirmative < record.Request.Requirements.Quorum || negative != 0 || !decisionSet || expirationSet || consumptionSet || record.CancelledBy != "" {
			return errors.New("approved record does not satisfy approval invariants")
		}
		if err := validateApprovalTime(record); err != nil {
			return err
		}
	case StatusRejected:
		if affirmative >= record.Request.Requirements.Quorum || negative != 1 || !decisionSet || expirationSet || consumptionSet || record.CancelledBy != "" {
			return errors.New("rejected record does not contain one rejection decision")
		}
		if !record.DecidedAt.Equal(record.Votes[len(record.Votes)-1].DecidedAt) {
			return errors.New("rejection time does not match rejection vote")
		}
	case StatusCancelled:
		if affirmative >= record.Request.Requirements.Quorum || negative != 0 || !decisionSet || expirationSet || consumptionSet || record.CancelledBy == "" {
			return errors.New("cancelled record has invalid cancellation data")
		}
		if record.DecidedAt.Before(record.Request.CreatedAt) || !record.DecidedAt.Before(record.Request.ExpiresAt) {
			return errors.New("cancellation time is outside request lifetime")
		}
	case StatusExpired:
		if negative != 0 || !expirationSet || consumptionSet || record.CancelledBy != "" || !record.ExpiredAt.Equal(record.Request.ExpiresAt) {
			return errors.New("expired record has invalid expiration data")
		}
		if decisionSet {
			if affirmative < record.Request.Requirements.Quorum {
				return errors.New("expired approved record does not meet quorum")
			}
			if err := validateApprovalTime(record); err != nil {
				return err
			}
		} else if affirmative >= record.Request.Requirements.Quorum {
			return errors.New("expired pending record unexpectedly meets quorum")
		}
	case StatusConsumed:
		if affirmative < record.Request.Requirements.Quorum || negative != 0 || !decisionSet || expirationSet || !consumptionSet || record.CancelledBy != "" {
			return errors.New("consumed record does not satisfy approval invariants")
		}
		if err := validateApprovalTime(record); err != nil {
			return err
		}
		if record.ConsumedAt.Before(record.DecidedAt) || !record.ConsumedAt.Before(record.Request.ExpiresAt) {
			return errors.New("consumption time is outside approved lifetime")
		}
	}
	return nil
}

func validateApprovalTime(record Record) error {
	if record.DecidedAt.Before(record.Request.CreatedAt) || !record.DecidedAt.Before(record.Request.ExpiresAt) {
		return errors.New("approval time is outside request lifetime")
	}
	count := 0
	for _, vote := range record.Votes {
		if vote.Approved {
			count++
			if count == record.Request.Requirements.Quorum {
				if !record.DecidedAt.Equal(vote.DecidedAt) {
					return errors.New("approval time does not match quorum vote")
				}
				return nil
			}
		}
	}
	return errors.New("approval quorum is not represented by votes")
}
