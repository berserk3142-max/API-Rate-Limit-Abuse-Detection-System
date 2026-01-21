package middleware

import (
	"log"
	"net/http"
	"sync"
	"time"
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

// RequestLog stores information about each request for dashboard display
type RequestLog struct {
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	IP         string    `json:"ip"`
	StatusCode int       `json:"status_code"`
	Duration   string    `json:"duration"`
	UserAgent  string    `json:"user_agent"`
	Size       int       `json:"size"`
}

// RequestLogStore stores recent requests in memory
type RequestLogStore struct {
	logs    []RequestLog
	mu      sync.RWMutex
	maxSize int
}

var globalRequestStore = &RequestLogStore{
	logs:    make([]RequestLog, 0, 100),
	maxSize: 100,
}

// AddLog adds a new request log entry
func (s *RequestLogStore) AddLog(log RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logs = append(s.logs, log)
	if len(s.logs) > s.maxSize {
		s.logs = s.logs[len(s.logs)-s.maxSize:]
	}
}

// GetRecentLogs returns recent request logs
func (s *RequestLogStore) GetRecentLogs(limit int) []RequestLog {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit > len(s.logs) {
		limit = len(s.logs)
	}

	// Return in reverse order (newest first)
	result := make([]RequestLog, limit)
	for i := 0; i < limit; i++ {
		result[i] = s.logs[len(s.logs)-1-i]
	}
	return result
}

// GetRecentRequests returns recent requests from global store
func GetRecentRequests(limit int) []RequestLog {
	return globalRequestStore.GetRecentLogs(limit)
}

// GetRequestStats returns stats about requests
func GetRequestStats() map[string]interface{} {
	globalRequestStore.mu.RLock()
	defer globalRequestStore.mu.RUnlock()

	total := len(globalRequestStore.logs)
	blocked := 0
	for _, l := range globalRequestStore.logs {
		if l.StatusCode == 429 {
			blocked++
		}
	}

	return map[string]interface{}{
		"total":   total,
		"blocked": blocked,
	}
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

		// Store the request log for dashboard
		reqLog := RequestLog{
			Timestamp:  start,
			Method:     r.Method,
			Path:       r.URL.Path,
			IP:         r.RemoteAddr,
			StatusCode: rw.statusCode,
			Duration:   duration.String(),
			UserAgent:  r.UserAgent(),
			Size:       rw.size,
		}
		globalRequestStore.AddLog(reqLog)

		m.logger.Printf(
			"[%s] %s %s %d %d %s %s",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
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
