package config

import (
	"strings"
	"testing"
)

func TestLoadRequiresAdminToken(t *testing.T) {
	t.Setenv("AUTHCELL_ADMIN_TOKEN", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AUTHCELL_ADMIN_TOKEN") {
		t.Fatalf("expected admin token error, got %v", err)
	}
	t.Setenv("AUTHCELL_ADMIN_TOKEN", "short")
	if _, err := Load(); err == nil {
		t.Fatal("short admin token should be rejected")
	}
}

func TestLoadDefaultsAndEscaping(t *testing.T) {
	t.Setenv("AUTHCELL_ADMIN_TOKEN", strings.Repeat("a", 40))
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PORT", "")
	t.Setenv("DB_PASSWORD", "p@ss:w/rd#1")
	t.Setenv("DB_HOST", "db")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 8080 {
		t.Fatalf("default port = %d", cfg.Port)
	}
	if !strings.Contains(cfg.DatabaseURL, "p%40ss%3Aw%2Frd%231@db:5432") {
		t.Fatalf("password not escaped: %s", cfg.DatabaseURL)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	t.Setenv("AUTHCELL_ADMIN_TOKEN", strings.Repeat("a", 40))
	t.Setenv("PORT", "abc")
	if _, err := Load(); err == nil {
		t.Fatal("bad PORT should fail")
	}
	t.Setenv("PORT", "8080")
	t.Setenv("AUTHCELL_VERIFY_TOKEN", strings.Repeat("a", 40))
	if _, err := Load(); err == nil {
		t.Fatal("verify token equal to admin token should fail")
	}
}
