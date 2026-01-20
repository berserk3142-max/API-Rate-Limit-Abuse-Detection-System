package database

import (
	"database/sql"
	"time"

	_ "github.com/lib/pq"
)

type Database struct {
	conn *sql.DB
}

func New(dsn string) (*Database, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &Database{conn: db}, nil
}

func (d *Database) Conn() *sql.DB {
	return d.conn
}

func (d *Database) Close() error {
	return d.conn.Close()
}

func (d *Database) Ping() error {
	return d.conn.Ping()
}

func (d *Database) InitSchema() error {
	schema := `
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
	`
	_, err := d.conn.Exec(schema)
	return err
}
