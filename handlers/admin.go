package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/repository"
)

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
	ctx := r.Context()

	ips, err := h.ipRepo.GetBlockedIPs(ctx)
	if err != nil {
		http.Error(w, `{"error": "failed to get blocked ips"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked_ips": ips,
		"count":       len(ips),
	})
}

func (h *AdminHandler) BlockIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	h.ipRepo.GetOrCreate(ctx, req.IP)

	if err := h.ipRepo.Block(ctx, req.IP); err != nil {
		http.Error(w, `{"error": "failed to block ip"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "ip blocked successfully",
		"ip":      req.IP,
	})
}

func (h *AdminHandler) UnblockIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	if err := h.ipRepo.Unblock(ctx, req.IP); err != nil {
		http.Error(w, `{"error": "failed to unblock ip"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "ip unblocked successfully",
		"ip":      req.IP,
	})
}

func (h *AdminHandler) GetIPRiskScore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, `{"error": "ip parameter is required"}`, http.StatusBadRequest)
		return
	}

	rep, err := h.ipRepo.GetOrCreate(ctx, ip)
	if err != nil {
		http.Error(w, `{"error": "failed to get ip reputation"}`, http.StatusInternalServerError)
		return
	}

	eventCount, _ := h.abuseRepo.CountByIPInWindow(ctx, ip, 60)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":                   rep.IP,
		"reputation_score":     rep.Score,
		"is_blocked":           rep.IsBlocked,
		"last_seen":            rep.LastSeen,
		"abuse_events_last_hr": eventCount,
	})
}

func (h *AdminHandler) GetAbuseEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, `{"error": "ip parameter is required"}`, http.StatusBadRequest)
		return
	}

	events, err := h.abuseRepo.GetByIP(ctx, ip, 100)
	if err != nil {
		http.Error(w, `{"error": "failed to get abuse events"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":     ip,
		"events": events,
		"count":  len(events),
	})
}

type TrafficMetrics struct {
	TotalBlockedIPs   int `json:"total_blocked_ips"`
	AbuseEventsLast1h int `json:"abuse_events_last_1h"`
}

func (h *AdminHandler) GetTrafficMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	blockedIPs, _ := h.ipRepo.GetBlockedIPs(ctx)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_blocked_ips": len(blockedIPs),
		"status":            "healthy",
	})
}

func (h *AdminHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": "api-gateway",
	})
}
