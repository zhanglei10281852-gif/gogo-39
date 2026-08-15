package approval

import (
	"fmt"
	"sort"
	"time"

	"agentguard/model"
)

// Get returns one model approval and lazily persists expiration when due.
func (s *Service) Get(id string, at time.Time) (model.Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[id]; !exists {
		return model.Approval{}, ErrNotFound
	}
	if err := s.refreshDueLocked(canonicalTime(at)); err != nil {
		return model.Approval{}, err
	}
	return project(s.records[id]), nil
}

// Inspect returns a defensive copy including votes for audit and diagnostics.
func (s *Service) Inspect(id string, at time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[id]; !exists {
		return Record{}, ErrNotFound
	}
	if err := s.refreshDueLocked(canonicalTime(at)); err != nil {
		return Record{}, err
	}
	return cloneRecord(s.records[id]), nil
}

// List returns stable ID-sorted model approvals matching all filter fields.
func (s *Service) List(filter Filter, at time.Time) ([]model.Approval, error) {
	if filter.Status != "" && !filter.Status.valid() {
		return nil, fmt.Errorf("invalid status filter %q", filter.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshDueLocked(canonicalTime(at)); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(s.records))
	for id, record := range s.records {
		if matches(record, filter) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	result := make([]model.Approval, 0, len(ids))
	for _, id := range ids {
		result = append(result, project(s.records[id]))
	}
	return result, nil
}
func matches(record Record, filter Filter) bool {
	if filter.Status != "" && record.Status != filter.Status {
		return false
	}
	if filter.SubjectID != "" && record.Request.SubjectID != filter.SubjectID {
		return false
	}
	if filter.PolicyID != "" && record.Request.PolicyID != filter.PolicyID {
		return false
	}
	if !filter.CreatedFrom.IsZero() && record.Request.CreatedAt.Before(filter.CreatedFrom) {
		return false
	}
	if !filter.CreatedTo.IsZero() && !record.Request.CreatedAt.Before(filter.CreatedTo) {
		return false
	}
	if filter.ApproverID != "" {
		found := false
		for _, vote := range record.Votes {
			if vote.ApproverID == filter.ApproverID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Statistics expires due workflows, then counts states and votes. PendingDue
// and ApprovedDue count requests expiring within the next 24 hours.
func (s *Service) Statistics(at time.Time) (Stats, error) {
	return s.StatisticsWithin(at, 24*time.Hour)
}

// StatisticsWithin uses a caller-selected non-negative due horizon.
func (s *Service) StatisticsWithin(at time.Time, horizon time.Duration) (Stats, error) {
	if horizon < 0 {
		return Stats{}, fmt.Errorf("statistics horizon cannot be negative")
	}
	at = canonicalTime(at)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshDueLocked(at); err != nil {
		return Stats{}, err
	}
	stats := Stats{ByStatus: make(map[Status]int)}
	deadline := at.Add(horizon)
	for _, record := range s.records {
		stats.Total++
		stats.ByStatus[record.Status]++
		stats.Votes += len(record.Votes)
		if !at.IsZero() && !record.Request.ExpiresAt.After(deadline) {
			switch record.Status {
			case StatusPending:
				stats.PendingDue++
			case StatusApproved:
				stats.ApprovedDue++
			}
		}
	}
	return stats, nil
}

// SweepExpired advances every due pending or approved request in one atomic
// repository save and returns the changed projections in stable ID order.
func (s *Service) SweepExpired(at time.Time) ([]model.Approval, error) {
	at = canonicalTime(at)
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := make([]string, 0)
	next := make(map[string]Record, len(s.records))
	for id, current := range s.records {
		record := cloneRecord(current)
		if expireIfDue(&record, at) {
			changed = append(changed, id)
		}
		next[id] = record
	}
	if len(changed) == 0 {
		return []model.Approval{}, nil
	}
	if err := s.saveMapLocked(next); err != nil {
		return nil, err
	}
	s.records = next
	sort.Strings(changed)
	result := make([]model.Approval, 0, len(changed))
	for _, id := range changed {
		result = append(result, project(next[id]))
	}
	return result, nil
}

func (s *Service) refreshDueLocked(at time.Time) error {
	if at.IsZero() {
		return nil
	}
	changed := false
	next := make(map[string]Record, len(s.records))
	for id, current := range s.records {
		record := cloneRecord(current)
		if expireIfDue(&record, at) {
			changed = true
		}
		next[id] = record
	}
	if !changed {
		return nil
	}
	if err := s.saveMapLocked(next); err != nil {
		return err
	}
	s.records = next
	return nil
}

func (s *Service) saveMapLocked(records map[string]Record) error {
	snapshot := make([]Record, 0, len(records))
	for _, record := range records {
		snapshot = append(snapshot, cloneRecord(record))
	}
	sort.Slice(snapshot, func(i, j int) bool {
		return snapshot[i].Request.ID < snapshot[j].Request.ID
	})
	if err := s.repo.Save(snapshot); err != nil {
		return fmt.Errorf("save approvals: %w", err)
	}
	return nil
}
