package portcheck

import (
	"context"
	"testing"
	"time"
)

func TestCheckPortsClosedAndFiltered(t *testing.T) {
	// 127.0.0.1 high ports are almost certainly not listening.
	results := CheckPorts(context.Background(), "127.0.0.1", []int{39999, 39998}, 500*time.Millisecond, 2)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.Status != Filtered && r.Status != Closed && r.Status != Unknown {
			t.Fatalf("port %d status = %s, want filtered/closed/unknown", r.Port, r.Status)
		}
	}
}

func TestDefaultPorts(t *testing.T) {
	if len(DefaultPorts) == 0 {
		t.Fatal("no default ports")
	}
}
