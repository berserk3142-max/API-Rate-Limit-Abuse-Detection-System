# Complete Setup Guide - API Rate-Limit & Abuse Detection System

This guide will help you enable **ALL features** of the API Gateway step by step.

---

## Prerequisites

Before starting, make sure you have:
- ✅ **Go 1.21+** (already installed)
- ✅ **Docker Desktop** (required for Redis, PostgreSQL, Kafka)

### Install Docker Desktop (if not installed)

**Windows:**
1. Download from: https://www.docker.com/products/docker-desktop/
2. Run the installer
3. Restart your computer
4. Open Docker Desktop and wait for it to start

---

## Step 1: Start Redis (Rate Limiting)

Redis is used for the sliding window rate limiting algorithm.

### Start Redis Container

```powershell
docker run -d --name redis -p 6379:6379 redis:latest
```

### Verify Redis is Running

```powershell
docker ps | findstr redis
```

You should see something like:
```
abc123  redis:latest  "docker-entrypoint..."  Up 5 seconds  0.0.0.0:6379->6379/tcp  redis
```

### Test Redis Connection

```powershell
docker exec -it redis redis-cli ping
```

Expected output: `PONG`

---

## Step 2: Start PostgreSQL (Database)

PostgreSQL stores users, API keys, IP reputation, and abuse events.

### Start PostgreSQL Container

```powershell
docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_DB=ratelimiter postgres:latest
```

### Verify PostgreSQL is Running

```powershell
docker ps | findstr postgres
```

### Test PostgreSQL Connection

```powershell
docker exec -it postgres psql -U postgres -d ratelimiter -c "SELECT 1"
```

Expected output: Shows "1" in a table

---

## Step 3: Start Kafka (Event Streaming) - Optional

Kafka is used for streaming abuse events to other services (ML, alerting, etc.).

### Option A: Use Docker Compose (Recommended)

Create a file called `docker-compose.yml` in your project folder:

```yaml
version: '3'
services:
  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
    ports:
      - "2181:2181"

  kafka:
    image: confluentinc/cp-kafka:latest
    depends_on:
      - zookeeper
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
```

Then run:

```powershell
docker-compose up -d
```

### Verify Kafka is Running

```powershell
docker ps | findstr kafka
```

---

## Step 4: Restart the API Gateway

After starting all services, restart the API Gateway:

### Stop the current server

Press `Ctrl+C` in the terminal running the server

### Start with all services

```powershell
$env:Path = "C:\Program Files\Go\bin;" + $env:Path
go run main.go
```

You should now see:
```
[API-GATEWAY] Starting API Gateway on port 8080
```

**No more warnings** about Redis or PostgreSQL!

---

## Step 5: Test All Features

### Test 1: Rate Limiting

Send 105 requests to trigger rate limiting (limit is 100/min):

```powershell
for ($i=1; $i -le 105; $i++) { 
    $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing
    Write-Host "Request $i : Status $($response.StatusCode)"
}
```

After 100 requests, you'll see `429 Too Many Requests`!

### Test 2: Check Rate Limit Headers

```powershell
curl -i http://localhost:8080/health
```

Look for these headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1737358200
```

### Test 3: Admin APIs

**Get traffic metrics:**
```powershell
curl http://localhost:8080/admin/metrics
```

**Get blocked IPs:**
```powershell
curl http://localhost:8080/admin/blocked-ips
```

**Block an IP:**
```powershell
curl -X POST -H "Content-Type: application/json" -d '{"ip":"1.2.3.4"}' http://localhost:8080/admin/blocked-ips
```

**Unblock an IP:**
```powershell
curl -X POST -H "Content-Type: application/json" -d '{"ip":"1.2.3.4"}' http://localhost:8080/admin/unblock
```

---

## Step 6: Create Test Users (Optional)

Connect to PostgreSQL and create test users:

```powershell
docker exec -it postgres psql -U postgres -d ratelimiter
```

Then run these SQL commands:

```sql
-- Create a test user
INSERT INTO users (id, email, plan, reputation_score) 
VALUES ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'test@example.com', 'PRO', 1.0);

-- Create an API key for this user
INSERT INTO api_keys (id, user_id, api_key, is_active) 
VALUES ('b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12', 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'sk_test123456789', true);

-- Exit psql
\q
```

Now test with the API key:

```powershell
curl -H "X-API-Key: sk_test123456789" http://localhost:8080/health
```

PRO users get 1000 requests/min instead of 100!

---

## Quick Start Commands Summary

```powershell
# 1. Start all services
docker run -d --name redis -p 6379:6379 redis:latest
docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_DB=ratelimiter postgres:latest

# 2. Run the API Gateway
cd "c:\Users\piyus\OneDrive\Desktop\API rate limiter"
$env:Path = "C:\Program Files\Go\bin;" + $env:Path
go run main.go

# 3. Test it
curl http://localhost:8080/
curl http://localhost:8080/health
curl http://localhost:8080/admin/metrics
```

---

## Stop & Cleanup

```powershell
# Stop containers
docker stop redis postgres

# Remove containers (optional)
docker rm redis postgres

# Stop everything if using docker-compose
docker-compose down
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| SERVER_PORT | 8080 | Server port |
| REDIS_ADDR | localhost:6379 | Redis address |
| REDIS_PASSWORD | "" | Redis password |
| POSTGRES_DSN | postgres://postgres:password@localhost:5432/ratelimiter?sslmode=disable | Database connection |
| KAFKA_BROKERS | localhost:9092 | Kafka brokers |
| RATE_LIMIT_MAX | 100 | Default rate limit |
| RATE_LIMIT_WINDOW | 60 | Window in seconds |

---

## Rate Limits by Plan

| Plan | Requests/min |
|------|-------------|
| FREE | 100 |
| PRO | 1,000 |
| ENTERPRISE | 10,000 |

---

🎉 **You now have a fully functional API Rate-Limit & Abuse Detection System!**
