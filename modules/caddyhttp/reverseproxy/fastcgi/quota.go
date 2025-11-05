package fastcgi

import "sync"

type fileQuotaLimiter struct {
	maxUsage     int64
	currentUsage int64
	mu           sync.Mutex
}

func newFileQuotaLimiter(maxUsage int64) *fileQuotaLimiter {
	return &fileQuotaLimiter{
		maxUsage: maxUsage,
	}
}

func (l *fileQuotaLimiter) acquire(n int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.currentUsage+n > l.maxUsage {
		return false
	}

	l.currentUsage += n
	return true
}

func (l *fileQuotaLimiter) release(n int64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.currentUsage -= n
}
