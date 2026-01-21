package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/models"
	"github.com/google/uuid"
)

type IPReputationRepository struct {
	db *sql.DB
}

func NewIPReputationRepository(db *sql.DB) *IPReputationRepository {
	return &IPReputationRepository{db: db}
}

// GetOrCreate retrieves an IP reputation record or creates a new one
func (r *IPReputationRepository) GetOrCreate(ctx context.Context, ip string) (*models.IPReputation, error) {
	rep := &models.IPReputation{}
	query := `SELECT ip, score, total_requests, success_requests, blocked_requests, 
			  is_blocked, is_suspicious, reason, first_seen, last_seen 
			  FROM ip_reputation WHERE ip = $1`

	var reason sql.NullString
	err := r.db.QueryRowContext(ctx, query, ip).Scan(
		&rep.IP, &rep.Score, &rep.TotalRequests, &rep.SuccessRequests,
		&rep.BlockedRequests, &rep.IsBlocked, &rep.IsSuspicious,
		&reason, &rep.FirstSeen, &rep.LastSeen,
	)

	if reason.Valid {
		rep.Reason = reason.String
	}

	if err == sql.ErrNoRows {
		rep = &models.IPReputation{
			IP:              ip,
			Score:           100.0,
			TotalRequests:   0,
			SuccessRequests: 0,
			BlockedRequests: 0,
			IsBlocked:       false,
			IsSuspicious:    false,
			FirstSeen:       time.Now(),
			LastSeen:        time.Now(),
		}
		insertQuery := `INSERT INTO ip_reputation (ip, score, total_requests, success_requests, 
						blocked_requests, is_blocked, is_suspicious, first_seen, last_seen) 
						VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
		_, err = r.db.ExecContext(ctx, insertQuery, rep.IP, rep.Score, rep.TotalRequests,
			rep.SuccessRequests, rep.BlockedRequests, rep.IsBlocked, rep.IsSuspicious,
			rep.FirstSeen, rep.LastSeen)
		if err != nil {
			return nil, err
		}
		return rep, nil
	}
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// UpsertIPReputation inserts or updates an IP reputation record (for syncing from in-memory)
func (r *IPReputationRepository) UpsertIPReputation(ctx context.Context, rep *models.IPReputation) error {
	query := `INSERT INTO ip_reputation (ip, score, total_requests, success_requests, 
			  blocked_requests, is_blocked, is_suspicious, reason, first_seen, last_seen)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			  ON CONFLICT (ip) DO UPDATE SET 
			  	score = EXCLUDED.score,
			  	total_requests = EXCLUDED.total_requests,
			  	success_requests = EXCLUDED.success_requests,
			  	blocked_requests = EXCLUDED.blocked_requests,
			  	is_blocked = EXCLUDED.is_blocked,
			  	is_suspicious = EXCLUDED.is_suspicious,
			  	reason = EXCLUDED.reason,
			  	last_seen = EXCLUDED.last_seen`

	var reason interface{}
	if rep.Reason != "" {
		reason = rep.Reason
	} else {
		reason = nil
	}

	_, err := r.db.ExecContext(ctx, query, rep.IP, rep.Score, rep.TotalRequests,
		rep.SuccessRequests, rep.BlockedRequests, rep.IsBlocked, rep.IsSuspicious,
		reason, rep.FirstSeen, rep.LastSeen)
	return err
}

// GetAllIPReputations retrieves all IP reputation records
func (r *IPReputationRepository) GetAllIPReputations(ctx context.Context) ([]*models.IPReputation, error) {
	query := `SELECT ip, score, total_requests, success_requests, blocked_requests, 
			  is_blocked, is_suspicious, reason, first_seen, last_seen 
			  FROM ip_reputation ORDER BY last_seen DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*models.IPReputation
	for rows.Next() {
		rep := &models.IPReputation{}
		var reason sql.NullString
		if err := rows.Scan(
			&rep.IP, &rep.Score, &rep.TotalRequests, &rep.SuccessRequests,
			&rep.BlockedRequests, &rep.IsBlocked, &rep.IsSuspicious,
			&reason, &rep.FirstSeen, &rep.LastSeen,
		); err != nil {
			return nil, err
		}
		if reason.Valid {
			rep.Reason = reason.String
		}
		ips = append(ips, rep)
	}
	return ips, nil
}

// UpdateScore updates the reputation score for an IP
func (r *IPReputationRepository) UpdateScore(ctx context.Context, ip string, score float64) error {
	query := `UPDATE ip_reputation SET score = $1, last_seen = $2 WHERE ip = $3`
	_, err := r.db.ExecContext(ctx, query, score, time.Now(), ip)
	return err
}

// Block marks an IP as blocked
func (r *IPReputationRepository) Block(ctx context.Context, ip string, reason string) error {
	query := `UPDATE ip_reputation SET is_blocked = true, reason = $1, last_seen = $2 WHERE ip = $3`
	_, err := r.db.ExecContext(ctx, query, reason, time.Now(), ip)
	return err
}

// Unblock removes the block from an IP
func (r *IPReputationRepository) Unblock(ctx context.Context, ip string) error {
	query := `UPDATE ip_reputation SET is_blocked = false, reason = NULL, last_seen = $1 WHERE ip = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), ip)
	return err
}

// IsBlocked checks if an IP is blocked
func (r *IPReputationRepository) IsBlocked(ctx context.Context, ip string) (bool, error) {
	var blocked bool
	query := `SELECT is_blocked FROM ip_reputation WHERE ip = $1`
	err := r.db.QueryRowContext(ctx, query, ip).Scan(&blocked)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return blocked, nil
}

// GetBlockedIPs retrieves all blocked IPs
func (r *IPReputationRepository) GetBlockedIPs(ctx context.Context) ([]*models.IPReputation, error) {
	query := `SELECT ip, score, total_requests, success_requests, blocked_requests, 
			  is_blocked, is_suspicious, reason, first_seen, last_seen 
			  FROM ip_reputation WHERE is_blocked = true ORDER BY last_seen DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*models.IPReputation
	for rows.Next() {
		rep := &models.IPReputation{}
		var reason sql.NullString
		if err := rows.Scan(
			&rep.IP, &rep.Score, &rep.TotalRequests, &rep.SuccessRequests,
			&rep.BlockedRequests, &rep.IsBlocked, &rep.IsSuspicious,
			&reason, &rep.FirstSeen, &rep.LastSeen,
		); err != nil {
			return nil, err
		}
		if reason.Valid {
			rep.Reason = reason.String
		}
		ips = append(ips, rep)
	}
	return ips, nil
}

// GetSuspiciousIPs retrieves all suspicious IPs
func (r *IPReputationRepository) GetSuspiciousIPs(ctx context.Context) ([]*models.IPReputation, error) {
	query := `SELECT ip, score, total_requests, success_requests, blocked_requests, 
			  is_blocked, is_suspicious, reason, first_seen, last_seen 
			  FROM ip_reputation WHERE is_suspicious = true ORDER BY score ASC, last_seen DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*models.IPReputation
	for rows.Next() {
		rep := &models.IPReputation{}
		var reason sql.NullString
		if err := rows.Scan(
			&rep.IP, &rep.Score, &rep.TotalRequests, &rep.SuccessRequests,
			&rep.BlockedRequests, &rep.IsBlocked, &rep.IsSuspicious,
			&reason, &rep.FirstSeen, &rep.LastSeen,
		); err != nil {
			return nil, err
		}
		if reason.Valid {
			rep.Reason = reason.String
		}
		ips = append(ips, rep)
	}
	return ips, nil
}

// AbuseEventRepository handles abuse event database operations
type AbuseEventRepository struct {
	db *sql.DB
}

func NewAbuseEventRepository(db *sql.DB) *AbuseEventRepository {
	return &AbuseEventRepository{db: db}
}

func (r *AbuseEventRepository) Create(ctx context.Context, event *models.AbuseEvent) error {
	event.ID = uuid.New()
	event.CreatedAt = time.Now()
	query := `INSERT INTO abuse_events (id, ip, user_id, event_type, anomaly_score, created_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.db.ExecContext(ctx, query, event.ID, event.IP, event.UserID, event.EventType, event.AnomalyScore, event.CreatedAt)
	return err
}

func (r *AbuseEventRepository) GetByIP(ctx context.Context, ip string, limit int) ([]*models.AbuseEvent, error) {
	query := `SELECT id, ip, user_id, event_type, anomaly_score, created_at FROM abuse_events WHERE ip = $1 ORDER BY created_at DESC LIMIT $2`
	rows, err := r.db.QueryContext(ctx, query, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.AbuseEvent
	for rows.Next() {
		event := &models.AbuseEvent{}
		if err := rows.Scan(&event.ID, &event.IP, &event.UserID, &event.EventType, &event.AnomalyScore, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func (r *AbuseEventRepository) CountByIPInWindow(ctx context.Context, ip string, windowMinutes int) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM abuse_events WHERE ip = $1 AND created_at > NOW() - INTERVAL '1 minute' * $2`
	err := r.db.QueryRowContext(ctx, query, ip, windowMinutes).Scan(&count)
	return count, err
}

// RequestLogRepository handles request log database operations
type RequestLogRepository struct {
	db *sql.DB
}

func NewRequestLogRepository(db *sql.DB) *RequestLogRepository {
	return &RequestLogRepository{db: db}
}

// InsertLog inserts a request log into the database
func (r *RequestLogRepository) InsertLog(ctx context.Context, id, ip, path, method, userAgent string, status int, latency int64, blocked bool) error {
	query := `INSERT INTO request_logs (id, ip, path, method, status, latency_ms, user_agent, blocked) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.db.ExecContext(ctx, query, id, ip, path, method, status, latency, userAgent, blocked)
	return err
}

// GetRecentLogs retrieves recent request logs
func (r *RequestLogRepository) GetRecentLogs(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	query := `SELECT id, ip, path, method, status, latency_ms, user_agent, blocked, created_at 
			  FROM request_logs ORDER BY created_at DESC LIMIT $1`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id, ip, path, method, userAgent string
		var status int
		var latency int64
		var blocked bool
		var createdAt time.Time

		if err := rows.Scan(&id, &ip, &path, &method, &status, &latency, &userAgent, &blocked, &createdAt); err != nil {
			return nil, err
		}

		logs = append(logs, map[string]interface{}{
			"id":         id,
			"ip":         ip,
			"path":       path,
			"method":     method,
			"status":     status,
			"latency_ms": latency,
			"user_agent": userAgent,
			"blocked":    blocked,
			"timestamp":  createdAt,
		})
	}
	return logs, nil
}
