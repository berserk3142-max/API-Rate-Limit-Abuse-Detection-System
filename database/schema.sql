-- Enhanced schema for API Rate Limiter with IP Reputation Tracking

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    plan TEXT CHECK (plan IN ('FREE', 'PRO', 'ENTERPRISE')) DEFAULT 'FREE',
    reputation_score FLOAT DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT now()
);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    api_key TEXT UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT now()
);

-- Enhanced IP Reputation table
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip TEXT PRIMARY KEY,
    score FLOAT DEFAULT 100.0,
    total_requests BIGINT DEFAULT 0,
    success_requests BIGINT DEFAULT 0,
    blocked_requests BIGINT DEFAULT 0,
    is_blocked BOOLEAN DEFAULT false,
    is_suspicious BOOLEAN DEFAULT false,
    reason TEXT,
    user_agents TEXT[],
    first_seen TIMESTAMP DEFAULT now(),
    last_seen TIMESTAMP DEFAULT now()
);

-- Request logs table
CREATE TABLE IF NOT EXISTS request_logs (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER NOT NULL,
    latency_ms BIGINT NOT NULL,
    user_agent TEXT,
    blocked BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now()
);

-- Abuse events table  
CREATE TABLE IF NOT EXISTS abuse_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip TEXT,
    user_id UUID,
    event_type TEXT NOT NULL,
    anomaly_score FLOAT DEFAULT 0.0,
    details JSONB,
    created_at TIMESTAMP DEFAULT now()
);

-- Rate limit rules
CREATE TABLE IF NOT EXISTS rate_limit_rules (
    plan TEXT PRIMARY KEY,
    requests_per_min INT NOT NULL
);

-- Insert default rate limit rules
INSERT INTO rate_limit_rules (plan, requests_per_min) VALUES
    ('FREE', 100),
    ('PRO', 1000),
    ('ENTERPRISE', 10000)
ON CONFLICT (plan) DO NOTHING;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_request_logs_ip ON request_logs(ip);
CREATE INDEX IF NOT EXISTS idx_request_logs_created ON request_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_status ON request_logs(status);
CREATE INDEX IF NOT EXISTS idx_abuse_events_ip ON abuse_events(ip);
CREATE INDEX IF NOT EXISTS idx_abuse_events_user ON abuse_events(user_id);
CREATE INDEX IF NOT EXISTS idx_abuse_events_created ON abuse_events(created_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_blocked ON ip_reputation(is_blocked);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_suspicious ON ip_reputation(is_suspicious);
