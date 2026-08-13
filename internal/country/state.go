package country

import (
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sync"
)

// StateStore keeps route-country evidence across process restarts. Keys are
// caller-provided opaque identities and the persisted payload contains no proxy
// address or credentials.
type StateStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]RouteCountries
}

func OpenStateStore(path string) (*StateStore, error) {
	store := &StateStore{path: path, entries: make(map[string]RouteCountries)}
	if path == "" {
		return store, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store.entries); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *StateStore) Get(key string) (RouteCountries, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.entries[key]
	return value, ok
}

func (s *StateStore) Set(key string, countries RouteCountries) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = countries
}

func (s *StateStore) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	data, err := json.Marshal(maps.Clone(s.entries))
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".countries-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

// NeedsReprobe reports whether either output route lacks stable country
// evidence. This deliberately excludes unavailable IPv6 when IPv4 is stable.
func NeedsReprobe(route RouteCountries) bool {
	return familyNeedsReprobe(route.DirectV4, route.DirectV6) || familyNeedsReprobe(route.WarpV4, route.WarpV6)
}

func familyNeedsReprobe(primary, secondary FamilyResult) bool {
	if primary.Available && primary.Status == Confirmed && primary.Country != "" {
		return secondary.Available && (secondary.Status != Confirmed || secondary.Country == "")
	}
	return true
}
