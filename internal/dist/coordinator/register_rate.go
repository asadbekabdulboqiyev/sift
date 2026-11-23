package coordinator

// register_rate.go — a small, dependency-free window limit for Register.
//
// This is a flood brake, not authentication: the token/pin/attestation gate in
// Master.Register decides WHO may register. Without a cap, any client that can
// reach the control-plane port could submit endless identities and force both
// map growth and repeated address-classification work.

import (
	"context"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc/peer"
)

const (
	registerRateLimit  = 30
	registerRateWindow = 10 * time.Second
	// A caller without a gRPC peer (in-process use) is keyed by worker id, so
	// bound the map against an unbounded stream of fresh ids.
	registerRateMaxBuckets = 4096
)

type registerBucket struct {
	count int
	reset time.Time
}

type registerLimiter struct {
	mu      sync.Mutex
	buckets map[string]*registerBucket
}

func newRegisterLimiter() *registerLimiter {
	return &registerLimiter{buckets: make(map[string]*registerBucket)}
}

// allow consumes one slot in the caller's fixed window. Expired buckets start
// a new window; callers must treat false as a rejected registration.
func (l *registerLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil || !now.Before(b.reset) {
		b = &registerBucket{reset: now.Add(registerRateWindow)}
		l.buckets[key] = b
	}
	if len(l.buckets) > registerRateMaxBuckets {
		for k, old := range l.buckets {
			if !now.Before(old.reset) {
				delete(l.buckets, k)
			}
		}
	}
	if b.count >= registerRateLimit {
		return false
	}
	b.count++
	return true
}

// registrationSourceKey prefers the remote IP so many worker ids behind one
// NAT share a budget. gRPC peers include a port that changes per connection;
// keying on it would let a caller reset the window by reconnecting.
func registrationSourceKey(ctx context.Context, workerID string) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil && host != "" {
			return "peer:" + host
		}
		return "peer:" + p.Addr.String()
	}
	return "id:" + workerID
}
