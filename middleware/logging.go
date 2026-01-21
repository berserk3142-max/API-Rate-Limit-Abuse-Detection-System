package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/handlers"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

type LoggingMiddleware struct {
	logger *log.Logger
}

func NewLoggingMiddleware(logger *log.Logger) *LoggingMiddleware {
	return &LoggingMiddleware{logger: logger}
}

func (m *LoggingMiddleware) Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		latencyMs := duration.Milliseconds()

		// Get client IP
		ip := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			ip = strings.TrimSpace(ips[0])
		} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
			ip = xri
		}

		// Log request for tracking
		blocked := rw.statusCode == 429
		requestID := handlers.LogRequest(ip, r.URL.Path, r.Method, r.UserAgent(), rw.statusCode, latencyMs, blocked)

		m.logger.Printf(
			"[%s] %s %s %s %d %d %s %s",
			requestID,
			r.Method,
			r.URL.Path,
			ip,
			rw.statusCode,
			rw.size,
			duration,
			r.UserAgent(),
		)
	})
}

func DefaultLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		log.Printf(
			"%s %s %s %d %s",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			rw.statusCode,
			duration,
		)
	})
}
