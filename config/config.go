package config

import (
	"os"
	"strconv"
)

type Config struct {
	ServerPort      string
	RedisAddr       string
	RedisPassword   string
	RedisDB         int
	PostgresDSN     string
	KafkaBrokers    []string
	KafkaTopic      string
	JWTSecret       string
	BackendURL      string
	RateLimitWindow int
	RateLimitMax    int
}

func Load() *Config {
	return &Config{
		ServerPort:      getEnv("SERVER_PORT", "8080"),
		RedisAddr:       getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:   getEnv("REDIS_PASSWORD", ""),
		RedisDB:         getEnvInt("REDIS_DB", 0),
		PostgresDSN:     getEnv("POSTGRES_DSN", "postgres://postgres:password@localhost:5432/ratelimiter?sslmode=disable"),
		KafkaBrokers:    []string{getEnv("KAFKA_BROKERS", "localhost:9092")},
		KafkaTopic:      getEnv("KAFKA_TOPIC", "abuse-events"),
		JWTSecret:       getEnv("JWT_SECRET", "your-secret-key-change-in-production"),
		BackendURL:      getEnv("BACKEND_URL", "http://localhost:9000"),
		RateLimitWindow: getEnvInt("RATE_LIMIT_WINDOW", 60),
		RateLimitMax:    getEnvInt("RATE_LIMIT_MAX", 100),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultVal
}
