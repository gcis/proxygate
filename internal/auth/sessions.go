package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Sessions is an in-memory session table. A restart signs everyone out,
// which is acceptable for a single-admin tool and avoids a session file.
type Sessions struct {
	mu   sync.Mutex
	m    map[string]session
	idle time.Duration
	max  time.Duration
	now  func() time.Time
}

type session struct {
	created  time.Time
	lastSeen time.Time
	epoch    int
}

// NewSessions creates a session table with the given idle and absolute limits.
func NewSessions(idle, max time.Duration) *Sessions {
	return &Sessions{m: map[string]session{}, idle: idle, max: max, now: time.Now}
}

// Create starts a session bound to the current password epoch and returns
// its ID (256 bits, URL-safe).
func (s *Sessions) Create(epoch int) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.m[id] = session{created: now, lastSeen: now, epoch: epoch}
	return id, nil
}

// Valid reports whether id is a live session for epoch, refreshing its idle
// timer. Expired or stale sessions are removed.
func (s *Sessions) Valid(id string, epoch int) bool {
	if id == "" {
		return false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return false
	}
	if sess.epoch != epoch || now.Sub(sess.lastSeen) > s.idle || now.Sub(sess.created) > s.max {
		delete(s.m, id)
		return false
	}
	sess.lastSeen = now
	s.m[id] = sess
	return true
}

// Delete ends one session.
func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

func (s *Sessions) pruneLocked(now time.Time) {
	for id, sess := range s.m {
		if now.Sub(sess.lastSeen) > s.idle || now.Sub(sess.created) > s.max {
			delete(s.m, id)
		}
	}
}

// LoginLimiter throttles failed logins per client address: after maxFails
// failures within window, further attempts are refused until it ends.
type LoginLimiter struct {
	mu       sync.Mutex
	fails    map[string]failRecord
	maxFails int
	window   time.Duration
	now      func() time.Time
}

type failRecord struct {
	count int
	first time.Time
}

// NewLoginLimiter returns a limiter allowing maxFails failures per window.
func NewLoginLimiter(maxFails int, window time.Duration) *LoginLimiter {
	return &LoginLimiter{fails: map[string]failRecord{}, maxFails: maxFails, window: window, now: time.Now}
}

// Blocked reports whether addr is currently blocked and for how long.
func (l *LoginLimiter) Blocked(addr string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.fails[addr]
	if !ok {
		return false, 0
	}
	if now.Sub(rec.first) > l.window {
		delete(l.fails, addr)
		return false, 0
	}
	if rec.count >= l.maxFails {
		return true, l.window - now.Sub(rec.first)
	}
	return false, 0
}

// Fail records a failed attempt from addr.
func (l *LoginLimiter) Fail(addr string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.fails[addr]
	if !ok || now.Sub(rec.first) > l.window {
		rec = failRecord{first: now}
	}
	rec.count++
	l.fails[addr] = rec
}

// Succeed clears the failure count for addr.
func (l *LoginLimiter) Succeed(addr string) {
	l.mu.Lock()
	delete(l.fails, addr)
	l.mu.Unlock()
}
