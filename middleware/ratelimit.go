package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/kafka"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/ratelimiter"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/repository"
)

type RateLimitMiddleware struct {
	limiter       *ratelimiter.RateLimiter
	userRepo      *repository.UserRepository
	producer      *kafka.Producer
	defaultLimit  int
	windowSeconds int
}

func NewRateLimitMiddleware(
	limiter *ratelimiter.RateLimiter,
	userRepo *repository.UserRepository,
	producer *kafka.Producer,
	defaultLimit int,
	windowSeconds int,
) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		limiter:       limiter,
		userRepo:      userRepo,
		producer:      producer,
		defaultLimit:  defaultLimit,
		windowSeconds: windowSeconds,
	}
}

func (m *RateLimitMiddleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		ip := getClientIP(r)
		userID := GetUserID(ctx)
		plan := GetUserPlan(ctx)

		limit := m.getLimitForPlan(ctx, plan)

		var key string
		if userID != "" {
			key = fmt.Sprintf("rate:user:%s:%s", userID, r.URL.Path)
		} else {
			key = fmt.Sprintf("rate:ip:%s:%s", ip, r.URL.Path)
		}

		allowed, err := m.limiter.Allow(ctx, key, limit, m.windowSeconds)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		remaining, _ := m.limiter.GetRemaining(ctx, key, limit, m.windowSeconds)
		resetTime := time.Now().Add(time.Duration(m.windowSeconds) * time.Second)

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(m.windowSeconds))

			if m.producer != nil {
				event := kafka.NewAbuseEvent(
					ip,
					userID,
					string(kafka.EventRateLimitExceeded),
					r.URL.Path,
					r.Method,
					r.UserAgent(),
				)
				m.producer.PublishAbuseEvent(ctx, event)
			}

			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "rate limit exceeded", "retry_after": ` + strconv.Itoa(m.windowSeconds) + `}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *RateLimitMiddleware) getLimitForPlan(ctx context.Context, plan string) int {
	if m.userRepo != nil {
		limit, err := m.userRepo.GetRateLimitByPlan(ctx, plan)
		if err == nil {
			return limit
		}
	}

	switch plan {
	case "ENTERPRISE":
		return 10000
	case "PRO":
		return 1000
	default:
		return m.defaultLimit
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return strings.Trim(ip, "[]")
}
