package probe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
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
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrent)

	for _, h := range hosts {
		h := h
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			key := fmt.Sprintf("%s:%d", h.Host, h.Port)
			target := h.IP
			if target == "" {
				target = h.Host
			}
			result := tcpProbe(ctx, target, h.Port, timeout)
			mu.Lock()
			results[key] = result
			mu.Unlock()
			return nil
		})
	}
	g.Wait()
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
