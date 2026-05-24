package probe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type ProbeResult struct {
	Reachable   bool
	LatencyMs   int64
	FailureType string // "refused", "timeout", "error"
}

type HostSpec struct {
	Host string
	IP   string
	Port int
}

func TCPProbeAll(ctx context.Context, hosts []HostSpec, maxConcurrent int, timeout time.Duration) map[string]*ProbeResult {
	results := make(map[string]*ProbeResult, len(hosts))
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host, ip string, port int) {
			defer wg.Done()
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return
			default:
			}
			key := fmt.Sprintf("%s:%d", host, port)
			target := ip
			if target == "" {
				target = host
			}
			result := tcpProbe(ctx, target, port, timeout)
			mu.Lock()
			results[key] = result
			mu.Unlock()
		}(h.Host, h.IP, h.Port)
	}

	wg.Wait()
	return results
}

func tcpProbe(ctx context.Context, host string, port int, timeout time.Duration) *ProbeResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		ft := "error"
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			ft = "timeout"
		} else {
			ft = "refused"
		}
		return &ProbeResult{Reachable: false, FailureType: ft}
	}
	conn.Close()
	return &ProbeResult{Reachable: true, LatencyMs: time.Since(start).Milliseconds()}
}
