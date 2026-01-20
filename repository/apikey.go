package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/models"
	"github.com/google/uuid"
)

type APIKeyRepository struct {
	db *sql.DB
}

func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

func (r *APIKeyRepository) Create(ctx context.Context, userID uuid.UUID) (*models.APIKey, error) {
	apiKey := &models.APIKey{
		ID:        uuid.New(),
		UserID:    userID,
		APIKey:    generateAPIKey(),
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	query := `INSERT INTO api_keys (id, user_id, api_key, is_active, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.ExecContext(ctx, query, apiKey.ID, apiKey.UserID, apiKey.APIKey, apiKey.IsActive, apiKey.CreatedAt)
	if err != nil {
		return nil, err
	}
	return apiKey, nil
}

func (r *APIKeyRepository) GetByKey(ctx context.Context, key string) (*models.APIKey, error) {
	apiKey := &models.APIKey{}
	query := `SELECT id, user_id, api_key, is_active, created_at FROM api_keys WHERE api_key = $1`
	err := r.db.QueryRowContext(ctx, query, key).Scan(&apiKey.ID, &apiKey.UserID, &apiKey.APIKey, &apiKey.IsActive, &apiKey.CreatedAt)
	if err != nil {
		return nil, err
	}
	return apiKey, nil
}

func (r *APIKeyRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	query := `SELECT id, user_id, api_key, is_active, created_at FROM api_keys WHERE user_id = $1`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*models.APIKey
	for rows.Next() {
		key := &models.APIKey{}
		if err := rows.Scan(&key.ID, &key.UserID, &key.APIKey, &key.IsActive, &key.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (r *APIKeyRepository) Deactivate(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET is_active = false WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *APIKeyRepository) Activate(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET is_active = true WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *APIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *APIKeyRepository) ValidateKey(ctx context.Context, key string) (uuid.UUID, bool, error) {
	apiKey, err := r.GetByKey(ctx, key)
	if err != nil {
		return uuid.Nil, false, err
	}
	return apiKey.UserID, apiKey.IsActive, nil
}

func generateAPIKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return "sk_" + hex.EncodeToString(bytes)
}
