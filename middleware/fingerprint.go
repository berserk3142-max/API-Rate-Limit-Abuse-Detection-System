package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/kafka"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/repository"
)

type FingerprintKey string

const FingerprintContextKey FingerprintKey = "fingerprint"

type FingerprintMiddleware struct {
	ipRepo   *repository.IPReputationRepository
	producer *kafka.Producer
}

func NewFingerprintMiddleware(ipRepo *repository.IPReputationRepository, producer *kafka.Producer) *FingerprintMiddleware {
	return &FingerprintMiddleware{
		ipRepo:   ipRepo,
		producer: producer,
	}
}

func (m *FingerprintMiddleware) Fingerprint(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ip := getClientIP(r)

		if m.ipRepo != nil {
			blocked, err := m.ipRepo.IsBlocked(ctx, ip)
			if err == nil && blocked {
				if m.producer != nil {
					event := kafka.NewAbuseEvent(
						ip,
						GetUserID(ctx),
						string(kafka.EventIPBlocked),
						r.URL.Path,
						r.Method,
						r.UserAgent(),
					)
					m.producer.PublishAbuseEvent(ctx, event)
				}

				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error": "ip blocked"}`))
				return
			}
		}

		fingerprint := generateFingerprint(r)
		ctx = context.WithValue(ctx, FingerprintContextKey, fingerprint)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateFingerprint(r *http.Request) string {
	components := []string{
		getClientIP(r),
		r.UserAgent(),
		r.Header.Get("Accept-Language"),
		r.Header.Get("Accept-Encoding"),
		r.Header.Get("Accept"),
	}

	data := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func GetFingerprint(ctx context.Context) string {
	if val := ctx.Value(FingerprintContextKey); val != nil {
		return val.(string)
	}
	return ""
}

type RequestInfo struct {
	IP          string
	UserAgent   string
	Fingerprint string
	Endpoint    string
	Method      string
	UserID      string
}

func ExtractRequestInfo(r *http.Request) *RequestInfo {
	ctx := r.Context()
	return &RequestInfo{
		IP:          getClientIP(r),
		UserAgent:   r.UserAgent(),
		Fingerprint: GetFingerprint(ctx),
		Endpoint:    r.URL.Path,
		Method:      r.Method,
		UserID:      GetUserID(ctx),
	}
}
