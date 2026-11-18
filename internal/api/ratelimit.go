package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter implements a thread-safe per-IP token bucket limiter with bounded state cleanup.
type RateLimiter struct {
	mu       sync.Mutex
	ratePerS float64
	burst    float64
	buckets  map[string]*bucket
}

// NewRateLimiter constructs a per-IP limiter refilling ratePerSec tokens up to burst.
func NewRateLimiter(ratePerSec, burst float64) *RateLimiter {
	return &RateLimiter{
		ratePerS: ratePerSec,
		burst:    burst,
		buckets:  make(map[string]*bucket),
	}
}

// Allow checks and consumes one token for the client key.
func (rl *RateLimiter) Allow(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.buckets) > 10000 {
		for k, b := range rl.buckets {
			if now.Sub(b.lastRefill) > 10*time.Minute {
				delete(rl.buckets, k)
			}
		}
	}
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.burst - 1, lastRefill: now}
		return true
	}
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.ratePerS
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.lastRefill = now
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
