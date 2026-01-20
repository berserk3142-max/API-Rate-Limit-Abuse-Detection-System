package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/models"
	"github.com/google/uuid"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	if user.ReputationScore == 0 {
		user.ReputationScore = 1.0
	}
	if user.Plan == "" {
		user.Plan = string(models.PlanFree)
	}

	query := `INSERT INTO users (id, email, plan, reputation_score, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.ExecContext(ctx, query, user.ID, user.Email, user.Plan, user.ReputationScore, user.CreatedAt)
	return err
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, email, plan, reputation_score, created_at FROM users WHERE id = $1`
	err := r.db.QueryRowContext(ctx, query, id).Scan(&user.ID, &user.Email, &user.Plan, &user.ReputationScore, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, email, plan, reputation_score, created_at FROM users WHERE email = $1`
	err := r.db.QueryRowContext(ctx, query, email).Scan(&user.ID, &user.Email, &user.Plan, &user.ReputationScore, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) UpdateReputationScore(ctx context.Context, id uuid.UUID, score float64) error {
	query := `UPDATE users SET reputation_score = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, score, id)
	return err
}

func (r *UserRepository) UpdatePlan(ctx context.Context, id uuid.UUID, plan string) error {
	query := `UPDATE users SET plan = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, plan, id)
	return err
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *UserRepository) GetRateLimitByPlan(ctx context.Context, plan string) (int, error) {
	var limit int
	query := `SELECT requests_per_min FROM rate_limit_rules WHERE plan = $1`
	err := r.db.QueryRowContext(ctx, query, plan).Scan(&limit)
	if err != nil {
		return 100, nil
	}
	return limit, nil
}
