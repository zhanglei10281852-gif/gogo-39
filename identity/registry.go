package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentguard/model"
)

const snapshotVersion = 1

// Registry stores identities and their mutable security state in memory.
type Registry struct {
	mu         sync.RWMutex
	clock      Clock
	identities map[string]model.Identity
	sessions   map[string]model.Session
	grants     map[string]model.CapabilityGrant
	nonces     map[string]map[string]struct{}
	parents    map[string]string
}

// NewRegistry constructs an empty registry. Options are applied in order.
func NewRegistry(options ...Option) *Registry {
	r := &Registry{
		clock:      time.Now,
		identities: make(map[string]model.Identity),
		sessions:   make(map[string]model.Session),
		grants:     make(map[string]model.CapabilityGrant),
		nonces:     make(map[string]map[string]struct{}),
		parents:    make(map[string]string),
	}
	for _, option := range options {
		if option != nil {
			_ = option(r)
		}
	}
	return r
}

// NewRegistryWithClock is a convenience constructor for fixed clocks.
func NewRegistryWithClock(clock Clock) (*Registry, error) {
	if clock == nil {
		return nil, errors.Join(ErrInvalid, errors.New("nil clock"))
	}
	return NewRegistry(WithClock(clock)), nil
}

func (r *Registry) now() time.Time {
	return r.clock().UTC()
}

// DeterministicID hashes length-framed inputs, avoiding ambiguous concatenation.
func DeterministicID(prefix string, parts ...string) string {
	h := sha256.New()
	writeHashPart(h, prefix)
	for _, part := range parts {
		writeHashPart(h, part)
	}
	return prefix + "_" + hex.EncodeToString(h.Sum(nil))[:32]
}

type hashWriter interface{ Write([]byte) (int, error) }

func writeHashPart(w hashWriter, value string) {
	_, _ = w.Write([]byte(strconv.Itoa(len(value))))
	_, _ = w.Write([]byte{':'})
	_, _ = w.Write([]byte(value))
	_, _ = w.Write([]byte{'|'})
}

func canonicalStrings(values []string) string {
	return strings.Join(model.SortedUnique(values), "\x00")
}

func canonicalMap(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		writeHashPart(&b, key)
		writeHashPart(&b, values[key])
	}
	return b.String()
}

func cloneMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func cloneIdentity(value model.Identity) model.Identity {
	value.Roles = append([]string(nil), value.Roles...)
	value.Groups = append([]string(nil), value.Groups...)
	value.Attributes = cloneMap(value.Attributes)
	return value
}

func normalizeIdentity(value model.Identity) model.Identity {
	value.ID = strings.TrimSpace(value.ID)
	value.Kind = strings.TrimSpace(value.Kind)
	value.Issuer = strings.TrimSpace(value.Issuer)
	value.Roles = model.SortedUnique(value.Roles)
	value.Groups = model.SortedUnique(value.Groups)
	value.Attributes = cloneMap(value.Attributes)
	return value
}

func cloneSession(value model.Session) model.Session {
	value.Tags = cloneMap(value.Tags)
	return value
}

func cloneGrant(value model.CapabilityGrant) model.CapabilityGrant {
	value.Capabilities = append([]string(nil), value.Capabilities...)
	value.ResourceScopes = append([]string(nil), value.ResourceScopes...)
	value.ToolScopes = append([]string(nil), value.ToolScopes...)
	value.Constraints = cloneMap(value.Constraints)
	return value
}

func normalizeGrant(value model.CapabilityGrant) model.CapabilityGrant {
	value.SubjectID = strings.TrimSpace(value.SubjectID)
	value.SessionID = strings.TrimSpace(value.SessionID)
	value.Capabilities = model.SortedUnique(value.Capabilities)
	value.ResourceScopes = model.SortedUnique(value.ResourceScopes)
	value.ToolScopes = model.SortedUnique(value.ToolScopes)
	value.Constraints = cloneMap(value.Constraints)
	return value
}

func wrap(kind error, format string, args ...any) error {
	return errors.Join(kind, fmt.Errorf(format, args...))
}

// MarshalSnapshot exports a stable JSON encoding suitable for persistence.
func (r *Registry) MarshalSnapshot() ([]byte, error) {
	snapshot := r.ExportSnapshot()
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("marshal identity snapshot: %w", err)
	}
	return data, nil
}

// UnmarshalSnapshot atomically replaces registry data from JSON.
func (r *Registry) UnmarshalSnapshot(data []byte) error {
	var snapshot Snapshot
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("decode identity snapshot: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("decode identity snapshot: multiple JSON values")
		}
		return fmt.Errorf("decode identity snapshot trailing data: %w", err)
	}
	return r.ImportSnapshot(snapshot)
}
