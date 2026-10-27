// Package config loads AuthCell settings from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// MinTokenLength is the shortest admin/verify token AuthCell will accept.
const MinTokenLength = 32

type Config struct {
	Env  string
	Port int

	// DatabaseURL is a full postgres:// connection string. Built from the
	// DB_* variables when DATABASE_URL is not set.
	DatabaseURL string

	// AdminToken guards every management endpoint (create, list, revoke...).
	AdminToken string
	// VerifyToken, when set, must be sent to POST /v1/keys/verify.
	VerifyToken string

	// RateLimitWindow is the fixed window used for per-key rate limits.
	RateLimitWindow time.Duration
	// UsageRetention controls how long api_usage rows are kept. 0 keeps forever.
	UsageRetention time.Duration

	CORSOrigins    string
	TrustedProxies []string

	DBMaxConns        int
	DBMinConns        int
	DBConnMaxLifetime time.Duration
	RequestTimeout    time.Duration
}

// Load reads configuration from the environment and validates it.
func Load() (Config, error) {
	cfg := Config{
		Env:               getenv("APP_ENV", "production"),
		AdminToken:        strings.TrimSpace(os.Getenv("AUTHCELL_ADMIN_TOKEN")),
		VerifyToken:       strings.TrimSpace(os.Getenv("AUTHCELL_VERIFY_TOKEN")),
		CORSOrigins:       strings.TrimSpace(os.Getenv("CORS_ORIGINS")),
		TrustedProxies:    splitList(os.Getenv("TRUSTED_PROXIES")),
		DBConnMaxLifetime: 30 * time.Minute,
	}

	var errs []error
	var err error

	if cfg.Port, err = intEnv("PORT", 8080); err != nil {
		errs = append(errs, err)
	} else if cfg.Port < 1 || cfg.Port > 65535 {
		errs = append(errs, fmt.Errorf("PORT must be between 1 and 65535, got %d", cfg.Port))
	}
	if cfg.DBMaxConns, err = intEnv("DB_MAX_CONNS", 25); err != nil {
		errs = append(errs, err)
	}
	if cfg.DBMinConns, err = intEnv("DB_MIN_CONNS", 2); err != nil {
		errs = append(errs, err)
	}
	if cfg.RateLimitWindow, err = durationEnv("RATE_LIMIT_WINDOW", time.Minute); err != nil {
		errs = append(errs, err)
	} else if cfg.RateLimitWindow < time.Second {
		errs = append(errs, errors.New("RATE_LIMIT_WINDOW must be at least 1s"))
	}
	if cfg.RequestTimeout, err = durationEnv("REQUEST_TIMEOUT", 10*time.Second); err != nil {
		errs = append(errs, err)
	}
	retentionDays, err := intEnv("USAGE_RETENTION_DAYS", 90)
	if err != nil {
		errs = append(errs, err)
	} else if retentionDays < 0 {
		errs = append(errs, errors.New("USAGE_RETENTION_DAYS cannot be negative"))
	}
	cfg.UsageRetention = time.Duration(retentionDays) * 24 * time.Hour

	if cfg.AdminToken == "" {
		errs = append(errs, errors.New("AUTHCELL_ADMIN_TOKEN is required (generate one with: openssl rand -hex 32)"))
	} else if strings.Contains(strings.ToLower(cfg.AdminToken), "change-me") {
		errs = append(errs, errors.New("AUTHCELL_ADMIN_TOKEN still has the placeholder value from .env.example"))
	} else if len(cfg.AdminToken) < MinTokenLength {
		errs = append(errs, fmt.Errorf("AUTHCELL_ADMIN_TOKEN must be at least %d characters", MinTokenLength))
	}
	if cfg.VerifyToken != "" && len(cfg.VerifyToken) < MinTokenLength {
		errs = append(errs, fmt.Errorf("AUTHCELL_VERIFY_TOKEN must be at least %d characters", MinTokenLength))
	}
	if cfg.VerifyToken != "" && cfg.VerifyToken == cfg.AdminToken {
		errs = append(errs, errors.New("AUTHCELL_VERIFY_TOKEN must differ from AUTHCELL_ADMIN_TOKEN"))
	}

	cfg.DatabaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = buildDatabaseURL()
	}

	return cfg, errors.Join(errs...)
}

// buildDatabaseURL assembles a connection string from DB_* variables.
// url.URL takes care of escaping passwords with special characters.
func buildDatabaseURL() string {
	q := url.Values{}
	q.Set("sslmode", getenv("DB_SSLMODE", "disable"))
	if schema := getenv("DB_SCHEMA", "public"); schema != "" {
		q.Set("search_path", schema)
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(getenv("DB_USERNAME", "postgres"), os.Getenv("DB_PASSWORD")),
		Host:     getenv("DB_HOST", "localhost") + ":" + getenv("DB_PORT", "5432"),
		Path:     "/" + getenv("DB_DATABASE", "postgres"),
		RawQuery: q.Encode(),
	}
	return u.String()
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func intEnv(key string, fallback int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q", key, v)
	}
	return n, nil
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 30s or 1m, got %q", key, v)
	}
	return d, nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
