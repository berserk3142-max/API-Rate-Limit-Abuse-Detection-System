package ratelimiter

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	client *redis.Client
	script *redis.Script
}

const luaScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

redis.call("ZREMRANGEBYSCORE", key, 0, now - window)
local count = redis.call("ZCARD", key)

if count >= limit then
    return 0
end

redis.call("ZADD", key, now, now)
redis.call("EXPIRE", key, window)
return 1
`

func New(addr string, password string, db int) *RateLimiter {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RateLimiter{
		client: client,
		script: redis.NewScript(luaScript),
	}
}

func (rl *RateLimiter) Allow(ctx context.Context, key string, limit int, windowSec int) (bool, error) {
	now := time.Now().Unix()
	res, err := rl.script.Run(ctx, rl.client, []string{key}, now, windowSec, limit).Int()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (rl *RateLimiter) GetRemaining(ctx context.Context, key string, limit int, windowSec int) (int, error) {
	now := time.Now().Unix()
	rl.client.ZRemRangeByScore(ctx, key, "0", string(rune(now-int64(windowSec))))
	count, err := rl.client.ZCard(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	return limit - int(count), nil
}

func (rl *RateLimiter) Reset(ctx context.Context, key string) error {
	return rl.client.Del(ctx, key).Err()
}

func (rl *RateLimiter) Close() error {
	return rl.client.Close()
}

func (rl *RateLimiter) Ping(ctx context.Context) error {
	return rl.client.Ping(ctx).Err()
}
