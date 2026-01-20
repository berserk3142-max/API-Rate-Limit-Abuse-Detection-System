CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    plan TEXT CHECK (plan IN ('FREE', 'PRO', 'ENTERPRISE')) DEFAULT 'FREE',
    reputation_score FLOAT DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    api_key TEXT UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip INET PRIMARY KEY,
    score FLOAT DEFAULT 1.0,
    last_seen TIMESTAMP DEFAULT now(),
    is_blocked BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS abuse_events (
    id UUID PRIMARY KEY,
    ip INET,
    user_id UUID,
    event_type TEXT NOT NULL,
    anomaly_score FLOAT DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rate_limit_rules (
    plan TEXT PRIMARY KEY,
    requests_per_min INT NOT NULL
);

INSERT INTO rate_limit_rules (plan, requests_per_min) VALUES
    ('FREE', 100),
    ('PRO', 1000),
    ('ENTERPRISE', 10000)
ON CONFLICT (plan) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_abuse_events_ip ON abuse_events(ip);
CREATE INDEX IF NOT EXISTS idx_abuse_events_user ON abuse_events(user_id);
CREATE INDEX IF NOT EXISTS idx_abuse_events_created ON abuse_events(created_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
