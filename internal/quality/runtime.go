package quality

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/geo"
)

func Identity(protocol, host string, port int, credential string, params map[string]string) string {
	host = strings.Trim(strings.ToLower(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{protocol, host, strconv.Itoa(port), credential}
	for _, key := range keys {
		parts = append(parts, key+"="+params[key])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

type Runtime struct {
	Key                    string
	State                  State
	Reachable              bool
	Labels                 map[string]string
	Metrics                Metrics
	RawScore               float64
	ScoreEWMA              float64
	HasScore               bool
	StateData              RuntimeState
	LastBandwidthAttemptAt time.Time
	LastBandwidthSuccessAt time.Time
	LastSuccessfulAt       time.Time
	GeoInfo                *geo.GeoInfo
	Countries              country.RouteCountries
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
func (s *Store) Get(key string) (Runtime, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	runtime, ok := s.entries[key]
	runtime.Labels = maps.Clone(runtime.Labels)
	return runtime, ok
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
