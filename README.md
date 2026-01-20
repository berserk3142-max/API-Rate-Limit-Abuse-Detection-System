# API Rate-Limit & Abuse Detection System

A production-grade API Gateway with rate limiting, abuse detection, and event streaming built in Go.

## Features

- **Sliding Window Rate Limiting** - Redis-based atomic rate limiting with Lua scripts
- **Multi-tier Rate Limits** - Different limits for FREE, PRO, and ENTERPRISE plans
- **IP Fingerprinting** - Track and block suspicious IPs
- **JWT & API Key Authentication** - Flexible authentication options
- **Kafka Event Streaming** - Real-time abuse event publishing and consumption
- **Admin APIs** - Manage blocked IPs, view metrics, and abuse events
- **Reverse Proxy** - Forward requests to backend services

## Project Structure

```
├── main.go                 # Application entry point
├── config/
│   └── config.go           # Environment configuration
├── proxy/
│   └── forward.go          # Reverse proxy implementation
├── ratelimiter/
│   └── limiter.go          # Redis sliding window rate limiter
├── middleware/
│   ├── auth.go             # JWT/API key authentication
│   ├── logging.go          # Request logging
│   ├── ratelimit.go        # Rate limiting middleware
│   └── fingerprint.go      # IP fingerprinting
├── database/
│   ├── connection.go       # PostgreSQL connection
│   └── schema.sql          # Database schema
├── models/
│   └── models.go           # Data models
├── repository/
│   ├── user.go             # User repository
│   ├── apikey.go           # API key repository
│   └── ip_reputation.go    # IP reputation repository
├── kafka/
│   ├── events.go           # Event definitions
│   ├── producer.go         # Kafka producer
│   └── consumer.go         # Kafka consumer
└── handlers/
    └── admin.go            # Admin API handlers
```

## Prerequisites

- Go 1.21+
- Redis
- PostgreSQL
- Kafka (optional)

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System.git
cd API-Rate-Limit-Abuse-Detection-System
```

### 2. Install dependencies

```bash
go mod tidy
```

### 3. Start infrastructure (Docker)

```bash
docker run -d --name redis -p 6379:6379 redis
docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=password postgres
```

### 4. Set environment variables

```bash
export SERVER_PORT=8080
export REDIS_ADDR=localhost:6379
export POSTGRES_DSN="postgres://postgres:password@localhost:5432/ratelimiter?sslmode=disable"
export JWT_SECRET=your-secret-key
export BACKEND_URL=http://localhost:9000
```

### 5. Run the application

```bash
go run main.go
```

## API Endpoints

### Health Check
```
GET /health
```

### Admin APIs
```
GET  /admin/blocked-ips     # List blocked IPs
POST /admin/blocked-ips     # Block an IP
POST /admin/unblock         # Unblock an IP
GET  /admin/ip-risk?ip=X    # Get IP risk score
GET  /admin/abuse-events?ip=X  # Get abuse events for IP
GET  /admin/metrics         # Get traffic metrics
```

### Proxy
```
ANY /api/*                  # Proxied to backend service
```

## Rate Limit Headers

All responses include:
- `X-RateLimit-Limit` - Maximum requests allowed
- `X-RateLimit-Remaining` - Requests remaining in window
- `X-RateLimit-Reset` - Unix timestamp when limit resets

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| SERVER_PORT | 8080 | Server listen port |
| REDIS_ADDR | localhost:6379 | Redis address |
| REDIS_PASSWORD | "" | Redis password |
| REDIS_DB | 0 | Redis database number |
| POSTGRES_DSN | postgres://... | PostgreSQL connection string |
| KAFKA_BROKERS | localhost:9092 | Kafka broker addresses |
| KAFKA_TOPIC | abuse-events | Kafka topic for events |
| JWT_SECRET | your-secret-key | JWT signing secret |
| BACKEND_URL | http://localhost:9000 | Backend service URL |
| RATE_LIMIT_WINDOW | 60 | Rate limit window in seconds |
| RATE_LIMIT_MAX | 100 | Default max requests per window |

## Rate Limit Plans

| Plan | Requests/min |
|------|-------------|
| FREE | 100 |
| PRO | 1000 |
| ENTERPRISE | 10000 |

## License

MIT
