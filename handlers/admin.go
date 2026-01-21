package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/models"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/repository"
	"github.com/google/uuid"
)

// RequestLog stores recent requests for tracking
type RequestLog struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	Status    int       `json:"status"`
	Latency   int64     `json:"latency_ms"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
	Blocked   bool      `json:"blocked"`
}

// TrafficStats tracks traffic statistics
type TrafficStats struct {
	TotalRequests   int64 `json:"total_requests"`
	SuccessRequests int64 `json:"success_requests"`
	BlockedRequests int64 `json:"blocked_requests"`
	AvgLatency      int64 `json:"avg_latency_ms"`
}

// IPReputation tracks IP behavior for abuse detection
type IPReputation struct {
	IP              string    `json:"ip"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	SuccessRequests int64     `json:"success_requests"`
	Score           float64   `json:"score"` // 0-100, lower = more suspicious
	IsBlocked       bool      `json:"is_blocked"`
	IsSuspicious    bool      `json:"is_suspicious"`
	LastSeen        time.Time `json:"last_seen"`
	FirstSeen       time.Time `json:"first_seen"`
	UserAgents      []string  `json:"user_agents"`
	Reason          string    `json:"reason,omitempty"`
}

var (
	recentRequests = make([]RequestLog, 0, 100)
	requestsMutex  sync.RWMutex
	trafficStats   = TrafficStats{}
	statsMutex     sync.RWMutex
	latencySum     int64

	// IP Reputation tracking (in-memory)
	ipReputations   = make(map[string]*IPReputation)
	ipReputationsMu sync.RWMutex
	blockedIPs      = make(map[string]*IPReputation)
	blockedIPsMu    sync.RWMutex

	// Database repositories for persistence (set via SetDBRepositories)
	dbIPRepo  *repository.IPReputationRepository
	dbLogRepo *repository.RequestLogRepository
)

// SetDBRepositories sets the database repositories for persistence
func SetDBRepositories(ipRepo *repository.IPReputationRepository, logRepo *repository.RequestLogRepository) {
	dbIPRepo = ipRepo
	dbLogRepo = logRepo
}

// Thresholds for automatic detection
const (
	SuspiciousBlockedThreshold = 5  // Block count to mark as suspicious
	AutoBlockThreshold         = 20 // Block count to auto-block
	SuspiciousScoreThreshold   = 30 // Score below this is suspicious
	MinRequestsForScore        = 3  // Minimum requests before calculating score
)

// UpdateIPReputation updates the reputation for an IP based on request outcome
func UpdateIPReputation(ip, userAgent string, blocked bool) *IPReputation {
	ipReputationsMu.Lock()
	defer ipReputationsMu.Unlock()

	// Clean IP (remove port)
	cleanIP := ip
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		cleanIP = ip[:idx]
	}
	cleanIP = strings.Trim(cleanIP, "[]")

	rep, exists := ipReputations[cleanIP]
	if !exists {
		rep = &IPReputation{
			IP:         cleanIP,
			Score:      100, // Start with perfect score
			FirstSeen:  time.Now(),
			UserAgents: []string{},
		}
		ipReputations[cleanIP] = rep
	}

	rep.TotalRequests++
	rep.LastSeen = time.Now()

	if blocked {
		rep.BlockedRequests++
	} else {
		rep.SuccessRequests++
	}

	// Track user agents (keep last 5)
	if userAgent != "" {
		found := false
		for _, ua := range rep.UserAgents {
			if ua == userAgent {
				found = true
				break
			}
		}
		if !found {
			rep.UserAgents = append(rep.UserAgents, userAgent)
			if len(rep.UserAgents) > 5 {
				rep.UserAgents = rep.UserAgents[1:]
			}
		}
	}

	// Calculate reputation score (only after minimum requests)
	if rep.TotalRequests >= MinRequestsForScore {
		// Score based on success rate and blocked count
		successRate := float64(rep.SuccessRequests) / float64(rep.TotalRequests) * 100
		blockPenalty := float64(rep.BlockedRequests) * 5 // Each block costs 5 points
		rep.Score = successRate - blockPenalty
		if rep.Score < 0 {
			rep.Score = 0
		}
	}

	// Check if suspicious
	if rep.BlockedRequests >= SuspiciousBlockedThreshold || rep.Score < SuspiciousScoreThreshold {
		rep.IsSuspicious = true
		rep.Reason = "High number of blocked requests"
	}

	// Auto-block if too many blocks
	if rep.BlockedRequests >= AutoBlockThreshold && !rep.IsBlocked {
		rep.IsBlocked = true
		rep.Reason = "Automatically blocked: exceeded block threshold"

		blockedIPsMu.Lock()
		blockedIPs[cleanIP] = rep
		blockedIPsMu.Unlock()
	}

	// Sync to database (async to not block requests)
	go syncIPToDatabase(rep)

	return rep
}

// syncIPToDatabase persists IP reputation to Neon PostgreSQL
func syncIPToDatabase(rep *IPReputation) {
	if dbIPRepo == nil {
		return // No database connection
	}

	// Convert to models.IPReputation for database
	modelRep := &models.IPReputation{
		IP:              rep.IP,
		Score:           rep.Score,
		TotalRequests:   rep.TotalRequests,
		SuccessRequests: rep.SuccessRequests,
		BlockedRequests: rep.BlockedRequests,
		IsBlocked:       rep.IsBlocked,
		IsSuspicious:    rep.IsSuspicious,
		Reason:          rep.Reason,
		FirstSeen:       rep.FirstSeen,
		LastSeen:        rep.LastSeen,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := dbIPRepo.UpsertIPReputation(ctx, modelRep); err != nil {
		// Log error but don't fail the request
		log.Printf("Failed to sync IP reputation to database: %v", err)
	}
}

// GetIPReputation returns the reputation for an IP
func GetIPReputation(ip string) *IPReputation {
	cleanIP := ip
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		cleanIP = ip[:idx]
	}
	cleanIP = strings.Trim(cleanIP, "[]")

	ipReputationsMu.RLock()
	defer ipReputationsMu.RUnlock()

	if rep, exists := ipReputations[cleanIP]; exists {
		return rep
	}

	// Return default for unknown IPs
	return &IPReputation{
		IP:    cleanIP,
		Score: 100,
	}
}

// GetAllIPReputations returns all tracked IPs
func GetAllIPReputations() []*IPReputation {
	ipReputationsMu.RLock()
	defer ipReputationsMu.RUnlock()

	result := make([]*IPReputation, 0, len(ipReputations))
	for _, rep := range ipReputations {
		result = append(result, rep)
	}
	return result
}

// GetSuspiciousIPs returns IPs flagged as suspicious
func GetSuspiciousIPs() []*IPReputation {
	ipReputationsMu.RLock()
	defer ipReputationsMu.RUnlock()

	result := make([]*IPReputation, 0)
	for _, rep := range ipReputations {
		if rep.IsSuspicious || rep.IsBlocked {
			result = append(result, rep)
		}
	}
	return result
}

// GetBlockedIPsList returns all blocked IPs
func GetBlockedIPsList() []*IPReputation {
	blockedIPsMu.RLock()
	defer blockedIPsMu.RUnlock()

	result := make([]*IPReputation, 0, len(blockedIPs))
	for _, rep := range blockedIPs {
		result = append(result, rep)
	}
	return result
}

// ManualBlockIP blocks an IP manually
func ManualBlockIP(ip, reason string) *IPReputation {
	cleanIP := ip
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		cleanIP = ip[:idx]
	}
	cleanIP = strings.Trim(cleanIP, "[]")

	ipReputationsMu.Lock()
	rep, exists := ipReputations[cleanIP]
	if !exists {
		rep = &IPReputation{
			IP:        cleanIP,
			Score:     0,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		ipReputations[cleanIP] = rep
	}
	rep.IsBlocked = true
	rep.IsSuspicious = true
	if reason != "" {
		rep.Reason = reason
	} else {
		rep.Reason = "Manually blocked by admin"
	}
	ipReputationsMu.Unlock()

	blockedIPsMu.Lock()
	blockedIPs[cleanIP] = rep
	blockedIPsMu.Unlock()

	return rep
}

// ManualUnblockIP unblocks an IP
func ManualUnblockIP(ip string) bool {
	cleanIP := ip
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		cleanIP = ip[:idx]
	}
	cleanIP = strings.Trim(cleanIP, "[]")

	blockedIPsMu.Lock()
	delete(blockedIPs, cleanIP)
	blockedIPsMu.Unlock()

	ipReputationsMu.Lock()
	if rep, exists := ipReputations[cleanIP]; exists {
		rep.IsBlocked = false
		rep.Reason = "Unblocked by admin"
	}
	ipReputationsMu.Unlock()

	return true
}

// IsIPBlocked checks if an IP is blocked
func IsIPBlocked(ip string) bool {
	cleanIP := ip
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		cleanIP = ip[:idx]
	}
	cleanIP = strings.Trim(cleanIP, "[]")

	blockedIPsMu.RLock()
	defer blockedIPsMu.RUnlock()
	_, blocked := blockedIPs[cleanIP]
	return blocked
}

// LogRequest adds a request to the recent requests log
func LogRequest(ip, path, method, userAgent string, status int, latency int64, blocked bool) string {
	requestID := uuid.New().String()[:8]

	log := RequestLog{
		ID:        requestID,
		IP:        ip,
		Path:      path,
		Method:    method,
		Status:    status,
		Latency:   latency,
		UserAgent: userAgent,
		Timestamp: time.Now(),
		Blocked:   blocked,
	}

	requestsMutex.Lock()
	recentRequests = append([]RequestLog{log}, recentRequests...)
	if len(recentRequests) > 100 {
		recentRequests = recentRequests[:100]
	}
	requestsMutex.Unlock()

	statsMutex.Lock()
	trafficStats.TotalRequests++
	if blocked || status == 429 {
		trafficStats.BlockedRequests++
	} else if status >= 200 && status < 400 {
		trafficStats.SuccessRequests++
	}
	latencySum += latency
	trafficStats.AvgLatency = latencySum / trafficStats.TotalRequests
	statsMutex.Unlock()

	// Update IP reputation
	UpdateIPReputation(ip, userAgent, blocked || status == 429)

	return requestID
}

// GetRecentRequests returns the recent requests
func GetRecentRequests() []RequestLog {
	requestsMutex.RLock()
	defer requestsMutex.RUnlock()
	return recentRequests
}

// GetTrafficStats returns traffic statistics
func GetTrafficStats() TrafficStats {
	statsMutex.RLock()
	defer statsMutex.RUnlock()
	return trafficStats
}

type AdminHandler struct {
	ipRepo    *repository.IPReputationRepository
	abuseRepo *repository.AbuseEventRepository
	userRepo  *repository.UserRepository
}

func NewAdminHandler(
	ipRepo *repository.IPReputationRepository,
	abuseRepo *repository.AbuseEventRepository,
	userRepo *repository.UserRepository,
) *AdminHandler {
	return &AdminHandler{
		ipRepo:    ipRepo,
		abuseRepo: abuseRepo,
		userRepo:  userRepo,
	}
}

func (h *AdminHandler) GetBlockedIPs(w http.ResponseWriter, r *http.Request) {
	// Use in-memory blocked IPs list
	ips := GetBlockedIPsList()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked_ips": ips,
		"count":       len(ips),
	})
}

func (h *AdminHandler) BlockIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.IP == "" {
		http.Error(w, `{"error": "ip is required"}`, http.StatusBadRequest)
		return
	}

	rep := ManualBlockIP(req.IP, req.Reason)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "ip blocked successfully",
		"ip":         req.IP,
		"reputation": rep,
	})
}

func (h *AdminHandler) UnblockIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.IP == "" {
		http.Error(w, `{"error": "ip is required"}`, http.StatusBadRequest)
		return
	}

	ManualUnblockIP(req.IP)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "ip unblocked successfully",
		"ip":      req.IP,
	})
}

func (h *AdminHandler) GetIPRiskScore(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, `{"error": "ip parameter is required"}`, http.StatusBadRequest)
		return
	}

	rep := GetIPReputation(ip)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":               rep.IP,
		"reputation_score": rep.Score,
		"is_blocked":       rep.IsBlocked,
		"is_suspicious":    rep.IsSuspicious,
		"total_requests":   rep.TotalRequests,
		"blocked_requests": rep.BlockedRequests,
		"last_seen":        rep.LastSeen,
		"first_seen":       rep.FirstSeen,
		"user_agents":      rep.UserAgents,
		"reason":           rep.Reason,
	})
}

func (h *AdminHandler) GetSuspiciousIPsHandler(w http.ResponseWriter, r *http.Request) {
	ips := GetSuspiciousIPs()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"suspicious_ips": ips,
		"count":          len(ips),
	})
}

func (h *AdminHandler) GetAllIPsHandler(w http.ResponseWriter, r *http.Request) {
	ips := GetAllIPReputations()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ips":   ips,
		"count": len(ips),
	})
}

func (h *AdminHandler) GetAbuseEvents(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, `{"error": "ip parameter is required"}`, http.StatusBadRequest)
		return
	}

	// Get requests from recent logs for this IP
	requests := GetRecentRequests()
	ipRequests := make([]RequestLog, 0)
	for _, req := range requests {
		if strings.Contains(req.IP, ip) {
			ipRequests = append(ipRequests, req)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":       ip,
		"requests": ipRequests,
		"count":    len(ipRequests),
	})
}

type TrafficMetrics struct {
	TotalBlockedIPs   int `json:"total_blocked_ips"`
	AbuseEventsLast1h int `json:"abuse_events_last_1h"`
}

func (h *AdminHandler) GetTrafficMetrics(w http.ResponseWriter, r *http.Request) {
	// Use in-memory blocked IPs for safety
	blockedIPsList := GetBlockedIPsList()
	stats := GetTrafficStats()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_blocked_ips": len(blockedIPsList),
		"total_requests":    stats.TotalRequests,
		"success_requests":  stats.SuccessRequests,
		"blocked_requests":  stats.BlockedRequests,
		"avg_latency_ms":    stats.AvgLatency,
		"status":            "healthy",
	})
}

func (h *AdminHandler) GetRecentRequestsHandler(w http.ResponseWriter, r *http.Request) {
	requests := GetRecentRequests()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests": requests,
		"count":    len(requests),
	})
}

func (h *AdminHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	stats := GetTrafficStats()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "healthy",
		"service":          "api-gateway",
		"total_requests":   stats.TotalRequests,
		"blocked_requests": stats.BlockedRequests,
		"uptime":           "running",
	})
}
