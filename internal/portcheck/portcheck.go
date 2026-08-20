package portcheck

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	Open     Status = "open"
	Closed   Status = "closed"
	Filtered Status = "filtered"
	Unknown  Status = "unknown"
)

type PortResult struct {
	Port   int
	Status Status
}

var DefaultPorts = []int{80, 443, 25, 587, 465, 1080, 8080, 1194, 51820, 8388, 8443}

func CheckPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, maxConcurrent int) []PortResult {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	results := make([]PortResult, len(ports))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = PortResult{Port: port, Status: Unknown}
				return
			}
			defer func() { <-sem }()
			results[i] = PortResult{Port: port, Status: probePort(ctx, ip, port, timeout)}
		}(i, port)
	}
	wg.Wait()
	return results
}

func probePort(ctx context.Context, ip string, port int, timeout time.Duration) Status {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err == nil {
		conn.Close()
		return Open
	}
	if isTimeout(err) || ctx.Err() != nil {
		return Filtered
	}
	if isConnectionRefused(err) {
		return Closed
	}
	return Unknown
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "i/o timeout") || contains(s, "deadline") || contains(s, "timeout")
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), "connection refused")
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
