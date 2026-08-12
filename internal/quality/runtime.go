package quality

import (
	"maps"
	"sync"
	"time"
)

type Runtime struct {
	Key                    string
	State                  State
	Reachable              bool
	Labels                 map[string]string
	LastBandwidthAttemptAt time.Time
	LastBandwidthSuccessAt time.Time
}
type Store struct {
	mu      sync.RWMutex
	entries map[string]Runtime
}

func NewStore() *Store { return &Store{entries: make(map[string]Runtime)} }
func (s *Store) Set(runtime Runtime) {
	s.mu.Lock()
	defer s.mu.Unlock()
	runtime.Labels = maps.Clone(runtime.Labels)
	s.entries[runtime.Key] = runtime
}
func (s *Store) Snapshot() []Runtime {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Runtime, 0, len(s.entries))
	for _, runtime := range s.entries {
		runtime.Labels = maps.Clone(runtime.Labels)
		out = append(out, runtime)
	}
	return out
}
