package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/config"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/database"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/handlers"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/kafka"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/middleware"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/proxy"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/ratelimiter"
	"github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System/repository"
)

func main() {
	cfg := config.Load()

	logger := log.New(os.Stdout, "[API-GATEWAY] ", log.LstdFlags|log.Lshortfile)

	var db *database.Database
	var userRepo *repository.UserRepository
	var apiKeyRepo *repository.APIKeyRepository
	var ipRepo *repository.IPReputationRepository
	var abuseRepo *repository.AbuseEventRepository

	db, err := database.New(cfg.PostgresDSN)
	if err != nil {
		logger.Printf("Warning: PostgreSQL connection failed: %v. Running without database.", err)
	} else {
		if err := db.InitSchema(); err != nil {
			logger.Printf("Warning: Schema initialization failed: %v", err)
		}
		userRepo = repository.NewUserRepository(db.Conn())
		apiKeyRepo = repository.NewAPIKeyRepository(db.Conn())
		ipRepo = repository.NewIPReputationRepository(db.Conn())
		abuseRepo = repository.NewAbuseEventRepository(db.Conn())
		defer db.Close()
	}

	limiter := ratelimiter.New(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err := limiter.Ping(context.Background()); err != nil {
		logger.Printf("Warning: Redis connection failed: %v. Rate limiting may not work.", err)
	}
	defer limiter.Close()

	var producer *kafka.Producer
	producer = kafka.NewProducer(cfg.KafkaBrokers, cfg.KafkaTopic)
	defer producer.Close()

	var consumer *kafka.Consumer
	if abuseRepo != nil {
		handler := &kafka.DefaultEventHandler{}
		consumer = kafka.NewConsumer(cfg.KafkaBrokers, cfg.KafkaTopic, "abuse-detectors", handler)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		consumer.Start(ctx)
		defer consumer.Close()
	}

	reverseProxy, err := proxy.NewReverseProxy(cfg.BackendURL)
	if err != nil {
		logger.Printf("Warning: Failed to create reverse proxy: %v", err)
	}

	loggingMiddleware := middleware.NewLoggingMiddleware(logger)
	rateLimitMiddleware := middleware.NewRateLimitMiddleware(limiter, userRepo, producer, cfg.RateLimitMax, cfg.RateLimitWindow)
	fingerprintMiddleware := middleware.NewFingerprintMiddleware(ipRepo, producer)
	authMiddleware := middleware.NewAuthMiddleware(cfg.JWTSecret, apiKeyRepo, userRepo)

	adminHandler := handlers.NewAdminHandler(ipRepo, abuseRepo, userRepo)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"service": "API Rate-Limit & Abuse Detection Gateway",
			"version": "1.0.0",
			"status": "running",
			"endpoints": {
				"health": "/health",
				"api": "/api/*",
				"admin": {
					"blocked_ips": "/admin/blocked-ips",
					"unblock": "/admin/unblock",
					"ip_risk": "/admin/ip-risk",
					"abuse_events": "/admin/abuse-events",
					"metrics": "/admin/metrics"
				}
			}
		}`))
	})

	mux.HandleFunc("/health", adminHandler.HealthCheck)

	// Serve dashboard
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/dashboard.html")
	})

	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	mux.HandleFunc("/admin/blocked-ips", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			adminHandler.GetBlockedIPs(w, r)
		case http.MethodPost:
			adminHandler.BlockIP(w, r)
		default:
			http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/admin/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		adminHandler.UnblockIP(w, r)
	})

	mux.HandleFunc("/admin/ip-risk", adminHandler.GetIPRiskScore)
	mux.HandleFunc("/admin/abuse-events", adminHandler.GetAbuseEvents)
	mux.HandleFunc("/admin/metrics", adminHandler.GetTrafficMetrics)
	mux.HandleFunc("/admin/all-ips", adminHandler.GetAllIPs)
	mux.HandleFunc("/admin/recent-requests", adminHandler.GetRecentRequests)
	mux.HandleFunc("/admin/system-status", adminHandler.GetSystemStatus)

	if reverseProxy != nil {
		mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
			reverseProxy.ServeHTTP(w, r)
		})
	} else {
		mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message": "API Gateway is running", "path": "` + r.URL.Path + `"}`))
		})
	}

	var handler http.Handler = mux
	handler = rateLimitMiddleware.RateLimit(handler)
	handler = fingerprintMiddleware.Fingerprint(handler)
	handler = authMiddleware.OptionalAuth(handler)
	handler = loggingMiddleware.Log(handler)

	server := &http.Server{
		Addr:         ":" + cfg.ServerPort,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Printf("Starting API Gateway on port %s", cfg.ServerPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Println("Server exited")
}
