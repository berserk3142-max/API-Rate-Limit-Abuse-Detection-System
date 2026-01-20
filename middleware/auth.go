package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type contextKey string

const (
	UserIDKey  contextKey = "user_id"
	APIKeyKey  contextKey = "api_key"
	UserPlanKey contextKey = "user_plan"
)

type AuthMiddleware struct {
	jwtSecret     string
	apiKeyRepo    *repository.APIKeyRepository
	userRepo      *repository.UserRepository
}

func NewAuthMiddleware(jwtSecret string, apiKeyRepo *repository.APIKeyRepository, userRepo *repository.UserRepository) *AuthMiddleware {
	return &AuthMiddleware{
		jwtSecret:  jwtSecret,
		apiKeyRepo: apiKeyRepo,
		userRepo:   userRepo,
	}
}

func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" {
			userID, isActive, err := m.apiKeyRepo.ValidateKey(ctx, apiKey)
			if err == nil && isActive {
				user, err := m.userRepo.GetByID(ctx, userID)
				if err == nil {
					ctx = context.WithValue(ctx, UserIDKey, userID.String())
					ctx = context.WithValue(ctx, APIKeyKey, apiKey)
					ctx = context.WithValue(ctx, UserPlanKey, user.Plan)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return []byte(m.jwtSecret), nil
			})

			if err == nil && token.Valid {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					if userIDStr, ok := claims["user_id"].(string); ok {
						userID, err := uuid.Parse(userIDStr)
						if err == nil {
							user, err := m.userRepo.GetByID(ctx, userID)
							if err == nil {
								ctx = context.WithValue(ctx, UserIDKey, userIDStr)
								ctx = context.WithValue(ctx, UserPlanKey, user.Plan)
								next.ServeHTTP(w, r.WithContext(ctx))
								return
							}
						}
					}
				}
			}
		}

		http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
	})
}

func (m *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" {
			userID, isActive, err := m.apiKeyRepo.ValidateKey(ctx, apiKey)
			if err == nil && isActive {
				user, err := m.userRepo.GetByID(ctx, userID)
				if err == nil {
					ctx = context.WithValue(ctx, UserIDKey, userID.String())
					ctx = context.WithValue(ctx, APIKeyKey, apiKey)
					ctx = context.WithValue(ctx, UserPlanKey, user.Plan)
					r = r.WithContext(ctx)
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func GetUserID(ctx context.Context) string {
	if val := ctx.Value(UserIDKey); val != nil {
		return val.(string)
	}
	return ""
}

func GetUserPlan(ctx context.Context) string {
	if val := ctx.Value(UserPlanKey); val != nil {
		return val.(string)
	}
	return "FREE"
}
