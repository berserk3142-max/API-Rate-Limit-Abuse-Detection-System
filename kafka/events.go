package kafka

import (
	"time"

	"github.com/google/uuid"
)

type AbuseEvent struct {
	ID           string    `json:"id"`
	IP           string    `json:"ip"`
	UserID       string    `json:"user_id"`
	EventType    string    `json:"event_type"`
	AnomalyScore float64   `json:"anomaly_score"`
	Endpoint     string    `json:"endpoint"`
	Method       string    `json:"method"`
	UserAgent    string    `json:"user_agent"`
	Timestamp    int64     `json:"timestamp"`
	CreatedAt    time.Time `json:"created_at"`
}

func NewAbuseEvent(ip string, userID string, eventType string, endpoint string, method string, userAgent string) *AbuseEvent {
	return &AbuseEvent{
		ID:           uuid.New().String(),
		IP:           ip,
		UserID:       userID,
		EventType:    eventType,
		AnomalyScore: 0.0,
		Endpoint:     endpoint,
		Method:       method,
		UserAgent:    userAgent,
		Timestamp:    time.Now().Unix(),
		CreatedAt:    time.Now(),
	}
}

type EventType string

const (
	EventRateLimitExceeded EventType = "RATE_LIMIT_EXCEEDED"
	EventAuthFailure       EventType = "AUTH_FAILURE"
	EventSuspiciousPattern EventType = "SUSPICIOUS_PATTERN"
	EventIPBlocked         EventType = "IP_BLOCKED"
	EventBruteForce        EventType = "BRUTE_FORCE"
	EventScanningDetected  EventType = "SCANNING_DETECTED"
	EventAnomalyDetected   EventType = "ANOMALY_DETECTED"
)
