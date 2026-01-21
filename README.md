# 🛡️ API Rate-Limit & Abuse Detection System

A production-grade API Gateway with intelligent rate limiting, automatic abuse detection, IP reputation tracking, and real-time monitoring dashboard built in Go.

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Production_Ready-brightgreen?style=flat)

---

## 📋 Table of Contents

- [Problem Statement](#-problem-statement)
- [Solution Overview](#-solution-overview)
- [Architecture](#-architecture)
- [How It Works](#-how-it-works)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [API Reference](#-api-reference)
- [Dashboard](#-dashboard)
- [Configuration](#-configuration)
- [Real-World Use Cases](#-real-world-use-cases)

---

## 🎯 Problem Statement

Modern APIs face critical challenges:

| Problem | Impact | Without Protection |
|---------|--------|-------------------|
| **DDoS Attacks** | Server crashes | Millions of requests overwhelm servers |
| **Brute Force** | Security breach | Unlimited login attempts |
| **Data Scraping** | Data theft | Competitors steal your data |
| **Resource Abuse** | High costs | Single user consumes all resources |
| **Bot Traffic** | Poor UX | Real users can't access services |

---

## 💡 Solution Overview

This system acts as a **security gateway** between users and your backend API:

```mermaid
flowchart LR
    A[Client] --> B[API Gateway]
    B --> C{Rate Limiter}
    C -->|Allowed| D[Backend API]
    C -->|Blocked| E[429 Error]
    
    B --> F[(Redis)]
    B --> G[Dashboard]
    
    style A fill:#e1f5fe
    style B fill:#fff3e0
    style C fill:#fce4ec
    style D fill:#e8f5e9
    style E fill:#ffebee
    style F fill:#f3e5f5
    style G fill:#e0f2f1
```

---

## 🏗️ Architecture

### High-Level System Architecture

```mermaid
flowchart TB
    subgraph Client Layer
        A[Web Browser]
        B[Mobile App]
        C[API Client]
    end
    
    subgraph API Gateway
        D[Logging Middleware]
        E[Auth Middleware]
        F[Fingerprint Middleware]
        G[Rate Limit Middleware]
        H[Reverse Proxy]
    end
    
    subgraph Data Stores
        I[(Redis<br/>Rate Counters)]
        J[(PostgreSQL<br/>User Data)]
        K[Kafka<br/>Events]
    end
    
    subgraph Backend
        L[Your API<br/>Service]
    end
    
    A --> D
    B --> D
    C --> D
    D --> E --> F --> G --> H
    G <--> I
    E <--> J
    F --> K
    H --> L
    
    style D fill:#bbdefb
    style E fill:#c8e6c9
    style F fill:#fff9c4
    style G fill:#ffccbc
    style H fill:#e1bee7
```

### Request Processing Flow

```mermaid
flowchart TD
    A[Incoming Request] --> B[Generate Request ID]
    B --> C[Log Request Details]
    C --> D{Authenticated?}
    
    D -->|Yes| E[Extract User Plan]
    D -->|No| F[Use IP-based Limit]
    
    E --> G{Check Rate Limit}
    F --> G
    
    G -->|Under Limit| H[Update IP Reputation<br/>Score: +0]
    G -->|Over Limit| I[Update IP Reputation<br/>Score: -5]
    
    H --> J[Forward to Backend]
    I --> K[Return 429 Error]
    
    J --> L[Log Response]
    K --> L
    
    L --> M[Send Response to Client]
    
    style A fill:#e3f2fd
    style B fill:#f3e5f5
    style G fill:#fff3e0
    style H fill:#e8f5e9
    style I fill:#ffebee
    style J fill:#c8e6c9
    style K fill:#ffcdd2
```

### Middleware Chain

```mermaid
flowchart LR
    subgraph Middleware Chain
        direction LR
        A[Logging] --> B[CORS]
        B --> C[Auth]
        C --> D[Fingerprint]
        D --> E[Rate Limit]
    end
    
    E --> F{Allowed?}
    F -->|Yes| G[Backend]
    F -->|No| H[429 Response]
    
    style A fill:#e1f5fe
    style B fill:#f1f8e9
    style C fill:#fff8e1
    style D fill:#fce4ec
    style E fill:#e8eaf6
    style G fill:#c8e6c9
    style H fill:#ffcdd2
```

---

## ⚙️ How It Works

### 1. Rate Limiting (Sliding Window Algorithm)

```mermaid
flowchart LR
    subgraph Window["60 Second Window"]
        R1[R1] --> R2[R2]
        R2 --> R3[R3]
        R3 --> R4[...]
        R4 --> R99[R99]
        R99 --> R100[R100]
    end
    
    R100 --> CHECK{Request 101?}
    CHECK -->|Over Limit| BLOCK[❌ BLOCKED<br/>429 Error]
    
    subgraph After30["After 30 seconds"]
        OLD[Old requests<br/>slide out] --> NEW[New slot<br/>available]
    end
    
    style BLOCK fill:#ffcdd2
    style NEW fill:#c8e6c9
```

### 2. IP Reputation System

```mermaid
flowchart TD
    A[New IP Detected] --> B[Score: 100<br/>Perfect]
    
    B --> C{Request Outcome}
    
    C -->|Success 200| D[Score Unchanged]
    C -->|Blocked 429| E[Score -= 5]
    
    D --> F{Check Thresholds}
    E --> F
    
    F -->|Score < 30| G[🚨 SUSPICIOUS]
    F -->|Blocks >= 5| G
    F -->|Blocks >= 20| H[🚫 AUTO-BLOCKED]
    F -->|Normal| I[✅ OK]
    
    style A fill:#e3f2fd
    style B fill:#c8e6c9
    style G fill:#fff3e0
    style H fill:#ffcdd2
    style I fill:#e8f5e9
```

### 3. Multi-Tier Rate Limits

```mermaid
flowchart LR
    subgraph Plans
        FREE[FREE<br/>100/min]
        PRO[PRO<br/>1000/min]
        ENT[ENTERPRISE<br/>10000/min]
    end
    
    USER[User Request] --> AUTH{Auth Check}
    AUTH -->|No Token| FREE
    AUTH -->|Pro Token| PRO
    AUTH -->|Enterprise| ENT
    
    style FREE fill:#e3f2fd
    style PRO fill:#fff3e0
    style ENT fill:#e8f5e9
```

### 4. Abuse Detection Flow

```mermaid
flowchart TD
    A[Request Received] --> B[Track IP]
    B --> C[Update Counters]
    
    C --> D{Blocked Request?}
    D -->|Yes| E[Increment Block Count]
    D -->|No| F[Increment Success Count]
    
    E --> G{Block Count >= 5?}
    G -->|Yes| H[Mark SUSPICIOUS]
    G -->|No| I[Continue Monitoring]
    
    H --> J{Block Count >= 20?}
    J -->|Yes| K[AUTO-BLOCK IP]
    J -->|No| L[Alert Admin]
    
    K --> M[Add to Blocked List]
    M --> N[Reject All Future Requests]
    
    style H fill:#fff3e0
    style K fill:#ffcdd2
    style N fill:#ffebee
```

---

## ✨ Features

### Core Features

| Feature | Description |
|---------|-------------|
| 🚦 **Sliding Window Rate Limiting** | Redis-based atomic counters using Lua scripts |
| 🔍 **IP Reputation Tracking** | Automatic scoring and suspicious IP detection |
| 🚫 **Auto-Block** | IPs with 20+ blocks are automatically banned |
| 🎫 **JWT & API Key Auth** | Flexible authentication options |
| 📊 **Real-time Dashboard** | Beautiful UI for monitoring |
| 📝 **Request Logging** | Every request gets a unique ID |
| 🌐 **Reverse Proxy** | Forward requests to backend services |

### Complete Feature Flow

```mermaid
flowchart TB
    subgraph Features
        A[Rate Limiting] --> B[IP Tracking]
        B --> C[Auto Detection]
        C --> D[Dashboard]
        D --> E[Alerting]
    end
    
    subgraph Actions
        F[Block IP]
        G[Unblock IP]
        H[View Logs]
        I[Check Score]
    end
    
    D --> F
    D --> G
    D --> H
    D --> I
```

---

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Redis (for rate limiting)
- PostgreSQL (optional, for persistence)

### 1. Clone & Install

```bash
git clone https://github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System.git
cd API-Rate-Limit-Abuse-Detection-System
go mod tidy
```

### 2. Start Redis (Docker)

```bash
docker run -d --name redis -p 6379:6379 redis
```

### 3. Run the Server

```bash
go run main.go
```

### 4. Open Dashboard

```
http://localhost:8080/dashboard
```

---

## 🐳 Docker Deployment

### Quick Docker Start

```bash
# Clone the repository
git clone https://github.com/berserk3142-max/API-Rate-Limit-Abuse-Detection-System.git
cd API-Rate-Limit-Abuse-Detection-System

# Start all services with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f api-gateway
```

### Docker Architecture

```mermaid
flowchart TB
    subgraph Docker Network
        A[API Gateway<br/>:8080] --> B[(Redis<br/>:6379)]
        A --> C[(PostgreSQL<br/>:5432)]
        A --> D[Kafka<br/>:9092]
        D --> E[Zookeeper<br/>:2181]
    end
    
    F[Client] --> A
    
    style A fill:#fff3e0
    style B fill:#ffcdd2
    style C fill:#c8e6c9
    style D fill:#e1bee7
```

### Services Included

| Service | Port | Purpose |
|---------|------|---------|
| **api-gateway** | 8080 | Main application |
| **redis** | 6379 | Rate limiting cache |
| **postgres** | 5432 | Persistent storage |
| **kafka** | 9092 | Event streaming |
| **zookeeper** | 2181 | Kafka coordination |

### Build Only the API Gateway

```bash
# Build the Docker image
docker build -t api-gateway .

# Run with environment variables
docker run -d \
  --name api-gateway \
  -p 8080:8080 \
  -e REDIS_ADDR=your-redis-host:6379 \
  -e POSTGRES_DSN=your-postgres-dsn \
  api-gateway
```

### Production Configuration

Create a `.env` file from the template:

```bash
cp .env.example .env
# Edit .env with your production values
```

Key production considerations:
- Use external managed Redis (e.g., Redis Cloud, AWS ElastiCache)
- Use Neon or managed PostgreSQL
- Set strong `JWT_SECRET`
- Configure proper `BACKEND_URL`

---

## 📡 API Reference

### Endpoint Overview

```mermaid
flowchart LR
    subgraph Public
        A["/health"]
        B["/api/*"]
    end
    
    subgraph Admin
        C["/admin/metrics"]
        D["/admin/blocked-ips"]
        E["/admin/suspicious-ips"]
        F["/admin/ip-risk"]
        G["/admin/all-ips"]
        H["/admin/recent-requests"]
    end
    
    subgraph Dashboard
        I["/dashboard"]
    end
```

### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "api-gateway",
  "total_requests": 150,
  "blocked_requests": 5
}
```

### Admin Endpoints

#### Get All Tracked IPs

```http
GET /admin/all-ips
```

#### Get IP Risk Score

```http
GET /admin/ip-risk?ip=192.168.1.1
```

**Response:**
```json
{
  "ip": "192.168.1.1",
  "reputation_score": 85,
  "is_blocked": false,
  "is_suspicious": false,
  "total_requests": 100,
  "blocked_requests": 3,
  "user_agents": ["Mozilla/5.0...", "curl/8.0"],
  "first_seen": "2026-01-22T00:00:00Z",
  "last_seen": "2026-01-22T01:30:00Z"
}
```

#### Get Suspicious IPs

```http
GET /admin/suspicious-ips
```

#### Block an IP

```http
POST /admin/blocked-ips
Content-Type: application/json

{
  "ip": "192.168.1.100",
  "reason": "Suspicious bot activity"
}
```

#### Unblock an IP

```http
POST /admin/unblock
Content-Type: application/json

{
  "ip": "192.168.1.100"
}
```

#### Get Recent Requests

```http
GET /admin/recent-requests
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | 8080 | Server listen port |
| `REDIS_ADDR` | localhost:6379 | Redis address |
| `REDIS_PASSWORD` | "" | Redis password |
| `POSTGRES_DSN` | - | PostgreSQL connection string |
| `JWT_SECRET` | your-secret-key | JWT signing secret |
| `BACKEND_URL` | http://localhost:9000 | Backend service URL |
| `RATE_LIMIT_WINDOW` | 60 | Window in seconds |
| `RATE_LIMIT_MAX` | 100 | Max requests per window |

---

## 🌍 Real-World Use Cases

### Use Case Flow

```mermaid
flowchart TB
    subgraph E-Commerce
        A1[Product API] --> A2[Rate Limit]
        A2 --> A3[Block Scrapers]
    end
    
    subgraph Banking
        B1[Login API] --> B2[Track Attempts]
        B2 --> B3[Block Brute Force]
    end
    
    subgraph SaaS
        C1[API Access] --> C2[Check Plan]
        C2 --> C3[Enforce Limits]
    end
    
    subgraph Gaming
        D1[Game API] --> D2[Per-User Limit]
        D2 --> D3[Block Cheaters]
    end
```

---

## 🔧 Response Headers

Every response includes rate limit headers:

```http
X-RateLimit-Limit: 100        # Max requests allowed
X-RateLimit-Remaining: 95     # Requests remaining
X-RateLimit-Reset: 1642857600 # Unix timestamp for reset
```

When rate limited (429 response):
```http
Retry-After: 60               # Seconds until retry
```

---

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

<p align="center">
  Built with ❤️ using Go, Redis, and modern web technologies
</p>
