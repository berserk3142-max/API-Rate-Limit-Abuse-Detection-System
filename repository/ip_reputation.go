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

func (r *IPReputationRepository) GetOrCreate(ctx context.Context, ip string) (*models.IPReputation, error) {
	rep := &models.IPReputation{}
	query := `SELECT ip, score, last_seen, is_blocked FROM ip_reputation WHERE ip = $1`
	err := r.db.QueryRowContext(ctx, query, ip).Scan(&rep.IP, &rep.Score, &rep.LastSeen, &rep.IsBlocked)
	if err == sql.ErrNoRows {
		rep = &models.IPReputation{
			IP:        ip,
			Score:     1.0,
			LastSeen:  time.Now(),
			IsBlocked: false,
		}
		insertQuery := `INSERT INTO ip_reputation (ip, score, last_seen, is_blocked) VALUES ($1, $2, $3, $4)`
		_, err = r.db.ExecContext(ctx, insertQuery, rep.IP, rep.Score, rep.LastSeen, rep.IsBlocked)
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

func (r *IPReputationRepository) UpdateScore(ctx context.Context, ip string, score float64) error {
	query := `UPDATE ip_reputation SET score = $1, last_seen = $2 WHERE ip = $3`
	_, err := r.db.ExecContext(ctx, query, score, time.Now(), ip)
	return err
}

func (r *IPReputationRepository) Block(ctx context.Context, ip string) error {
	query := `UPDATE ip_reputation SET is_blocked = true, last_seen = $1 WHERE ip = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), ip)
	return err
}

func (r *IPReputationRepository) Unblock(ctx context.Context, ip string) error {
	query := `UPDATE ip_reputation SET is_blocked = false, last_seen = $1 WHERE ip = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), ip)
	return err
}

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

func (r *IPReputationRepository) GetBlockedIPs(ctx context.Context) ([]*models.IPReputation, error) {
	query := `SELECT ip, score, last_seen, is_blocked FROM ip_reputation WHERE is_blocked = true ORDER BY last_seen DESC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*models.IPReputation
	for rows.Next() {
		rep := &models.IPReputation{}
		if err := rows.Scan(&rep.IP, &rep.Score, &rep.LastSeen, &rep.IsBlocked); err != nil {
			return nil, err
		}
		ips = append(ips, rep)
	}
	return ips, nil
}

func (r *IPReputationRepository) GetAllIPs(ctx context.Context) ([]*models.IPReputation, error) {
	query := `SELECT ip, score, last_seen, is_blocked FROM ip_reputation ORDER BY last_seen DESC LIMIT 100`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*models.IPReputation
	for rows.Next() {
		rep := &models.IPReputation{}
		if err := rows.Scan(&rep.IP, &rep.Score, &rep.LastSeen, &rep.IsBlocked); err != nil {
			return nil, err
		}
		ips = append(ips, rep)
	}
	return ips, nil
}

func (r *IPReputationRepository) GetStats(ctx context.Context) (totalIPs int, blockedIPs int, err error) {
	query := `SELECT 
		COUNT(*) as total,
		COUNT(CASE WHEN is_blocked = true THEN 1 END) as blocked
	FROM ip_reputation`
	err = r.db.QueryRowContext(ctx, query).Scan(&totalIPs, &blockedIPs)
	return
}

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
