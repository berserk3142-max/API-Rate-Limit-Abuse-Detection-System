package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID `json:"id"`
	Email           string    `json:"email"`
	Plan            string    `json:"plan"`
	ReputationScore float64   `json:"reputation_score"`
	CreatedAt       time.Time `json:"created_at"`
}

type APIKey struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	APIKey    string    `json:"api_key"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

type IPReputation struct {
	IP        string    `json:"ip"`
	Score     float64   `json:"score"`
	LastSeen  time.Time `json:"last_seen"`
	IsBlocked bool      `json:"is_blocked"`
}

type AbuseEvent struct {
	ID           uuid.UUID `json:"id"`
	IP           string    `json:"ip"`
	UserID       uuid.UUID `json:"user_id"`
	EventType    string    `json:"event_type"`
	AnomalyScore float64   `json:"anomaly_score"`
	CreatedAt    time.Time `json:"created_at"`
}

type RateLimitRule struct {
	Plan           string `json:"plan"`
	RequestsPerMin int    `json:"requests_per_min"`
}

type UserPlan string

const (
	PlanFree       UserPlan = "FREE"
	PlanPro        UserPlan = "PRO"
	PlanEnterprise UserPlan = "ENTERPRISE"
)

type EventType string

const (
	EventRateLimitExceeded EventType = "RATE_LIMIT_EXCEEDED"
	EventAuthFailure       EventType = "AUTH_FAILURE"
	EventSuspiciousPattern EventType = "SUSPICIOUS_PATTERN"
	EventIPBlocked         EventType = "IP_BLOCKED"
	EventAnomalyDetected   EventType = "ANOMALY_DETECTED"
)

type RequestContext struct {
	IP        string
	UserID    string
	APIKey    string
	Endpoint  string
	Method    string
	UserAgent string
	Timestamp time.Time
}

type RateLimitInfo struct {
	Limit     int
	Remaining int
	ResetAt   time.Time
}
