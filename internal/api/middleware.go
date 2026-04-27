package api

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter provides per-IP rate limiting for the admin API.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int           // requests per window
	window   time.Duration // time window
}

type visitor struct {
	count    int
	lastSeen time.Time
}

func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}

	// Cleanup expired entries every minute
	go func() {
		for {
			time.Sleep(time.Minute)
			rl.cleanup()
		}
	}()

	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for ip, v := range rl.visitors {
		if time.Since(v.lastSeen) > rl.window*2 {
			delete(rl.visitors, ip)
		}
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &visitor{count: 1, lastSeen: time.Now()}
		return true
	}

	if time.Since(v.lastSeen) > rl.window {
		v.count = 1
		v.lastSeen = time.Now()
		return true
	}

	v.count++
	v.lastSeen = time.Now()
	return v.count <= rl.rate
}

// SecurityHeaders adds standard security headers to responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:")
		next.ServeHTTP(w, r)
	})
}

// RequestLogger logs incoming requests.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			logger.Info("admin request",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"duration", time.Since(start),
			)
		})
	}
}

// NetworkWhitelist restricts access to a list of allowed CIDR networks.
// If no networks are provided, it falls back to localhost-only access.
func NetworkWhitelist(networks []string) func(http.Handler) http.Handler {
	// Parse CIDR networks at setup time
	var allowed []*net.IPNet
	for _, cidr := range networks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try treating it as a plain IP address
			ip := net.ParseIP(cidr)
			if ip != nil {
				mask := net.CIDRMask(128, 128)
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				}
				ipNet = &net.IPNet{IP: ip, Mask: mask}
			} else {
				continue
			}
		}
		allowed = append(allowed, ipNet)
	}

	// Fall back to localhost if no valid networks configured
	if len(allowed) == 0 {
		_, loopback4, _ := net.ParseCIDR("127.0.0.0/8")
		_, loopback6, _ := net.ParseCIDR("::1/128")
		allowed = []*net.IPNet{loopback4, loopback6}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			ip := net.ParseIP(host)
			if ip == nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			for _, ipNet := range allowed {
				if ipNet.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden - IP not in allowed networks", http.StatusForbidden)
		})
	}
}

// RateLimit wraps a handler with rate limiting.
func RateLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if !rl.Allow(host) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Chain applies middlewares in order.
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
