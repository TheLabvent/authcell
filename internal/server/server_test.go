package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"authcell/internal/config"
	"authcell/internal/database"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
)

const (
	adminToken  = "admin-token-0123456789abcdef0123456789"
	verifyToken = "verify-token-0123456789abcdef012345678"
)

// stubDB satisfies database.Service for tests that never reach storage.
type stubDB struct{ database.Service }

func (stubDB) Ping(context.Context) error { return nil }
func (stubDB) Stats() map[string]any      { return map[string]any{} }

func testConfig() config.Config {
	return config.Config{
		Port: 8080, AdminToken: adminToken, RateLimitWindow: time.Minute, RequestTimeout: 5 * time.Second,
	}
}

type envelope struct {
	Status  string          `json:"status"`
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
	Meta    json.RawMessage `json:"meta"`
}

func do(t *testing.T, app *fiber.App, method, path, token string, body any) (int, envelope, http.Header) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, 10_000)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("%s %s: non-JSON response %q", method, path, raw)
	}
	return resp.StatusCode, env, resp.Header
}

func TestManagementRequiresAdminToken(t *testing.T) {
	app := New(testConfig(), stubDB{}, "test")
	routes := []struct{ method, path string }{
		{"POST", "/v1/keys"},
		{"GET", "/v1/keys"},
		{"GET", "/v1/keys/00000000-0000-0000-0000-000000000000"},
		{"PATCH", "/v1/keys/00000000-0000-0000-0000-000000000000"},
		{"DELETE", "/v1/keys/00000000-0000-0000-0000-000000000000"},
		{"POST", "/v1/keys/00000000-0000-0000-0000-000000000000/rotate"},
		{"GET", "/v1/usage/00000000-0000-0000-0000-000000000000"},
		{"GET", "/v1/audit"},
	}
	for _, r := range routes {
		for _, tok := range []string{"", "wrong-token", verifyToken} {
			code, env, _ := do(t, app, r.method, r.path, tok, nil)
			if code != http.StatusUnauthorized || env.Status != "error" {
				t.Errorf("%s %s with token %q: got %d", r.method, r.path, tok, code)
			}
		}
	}
}

func TestVerifyTokenEnforcedWhenConfigured(t *testing.T) {
	cfg := testConfig()
	cfg.VerifyToken = verifyToken
	app := New(cfg, stubDB{}, "test")
	code, _, _ := do(t, app, "POST", "/v1/keys/verify", "", map[string]string{"api_key": "x"})
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without verify token, got %d", code)
	}
}

func TestHealthAndNotFound(t *testing.T) {
	app := New(testConfig(), stubDB{}, "test")
	if code, env, _ := do(t, app, "GET", "/v1/health", "", nil); code != 200 || env.Status != "success" {
		t.Fatalf("health: %d %+v", code, env)
	}
	if code, env, _ := do(t, app, "GET", "/nope", "", nil); code != 404 || env.Status != "error" {
		t.Fatalf("404: %d %+v", code, env)
	}
}

// ---------------------------------------------------------------------------
// Integration tests: these need a real Postgres. Set AUTHCELL_TEST_DATABASE_URL
// (see Makefile `itest`). Each run uses a fresh schema.

func integrationApp(t *testing.T, cfg config.Config) *fiber.App {
	t.Helper()
	dsn := os.Getenv("AUTHCELL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHCELL_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("authcell_test_%d", time.Now().UnixNano())
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		conn.Close(context.Background())
	})

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := database.Connect(ctx, dsn+sep+"search_path="+schema, database.Options{MaxConns: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return New(cfg, db, "test")
}

type createdKey struct {
	APIKey    string          `json:"api_key"`
	ID        string          `json:"id"`
	KeyID     string          `json:"key_id"`
	KeyPrefix string          `json:"key_prefix"`
	Name      string          `json:"name"`
	Metadata  json.RawMessage `json:"metadata"`
	IsActive  bool            `json:"is_active"`
	RateLimit int             `json:"rate_limit"`
	KeyHash   *string         `json:"key_hash"`
}

func create(t *testing.T, app *fiber.App, body map[string]any) createdKey {
	t.Helper()
	code, env, _ := do(t, app, "POST", "/v1/keys", adminToken, body)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, env.Message)
	}
	var k createdKey
	if err := json.Unmarshal(env.Data, &k); err != nil {
		t.Fatal(err)
	}
	return k
}

type verifyData struct {
	Valid     bool   `json:"valid"`
	Reason    string `json:"reason"`
	ID        string `json:"id"`
	KeyPrefix string `json:"key_prefix"`
	RateLimit *struct {
		Limit     int `json:"limit"`
		Remaining int `json:"remaining"`
	} `json:"rate_limit"`
}

func verify(t *testing.T, app *fiber.App, key string) (int, verifyData) {
	t.Helper()
	code, env, _ := do(t, app, "POST", "/v1/keys/verify", "", map[string]string{"api_key": key})
	var v verifyData
	if len(env.Data) > 0 {
		_ = json.Unmarshal(env.Data, &v)
	}
	return code, v
}

func TestKeyLifecycle(t *testing.T) {
	app := integrationApp(t, testConfig())

	k := create(t, app, map[string]any{
		"key_prefix": "demo_", "name": "CI key", "metadata": map[string]any{"team": "core"},
	})
	if !strings.HasPrefix(k.APIKey, "demo_"+k.KeyID+"_") {
		t.Fatalf("unexpected key format %q", k.APIKey)
	}
	if k.KeyHash != nil {
		t.Fatal("key_hash must never be returned")
	}

	code, v := verify(t, app, k.APIKey)
	if code != 200 || !v.Valid || v.ID != k.ID || v.KeyPrefix != "demo" {
		t.Fatalf("verify valid: %d %+v", code, v)
	}

	// Wrong secret, unknown id, garbage: all generic "invalid".
	for _, bad := range []string{k.APIKey[:len(k.APIKey)-1] + "0", "demo_0123456789abcdef_" + strings.Repeat("a", 48), "garbage", "live_" + k.APIKey[5:]} {
		if code, v := verify(t, app, bad); code != 401 || v.Reason != "invalid" {
			t.Fatalf("verify %q: %d %+v", bad, code, v)
		}
	}

	// Header form works too.
	req := httptest.NewRequest("POST", "/v1/keys/verify", nil)
	req.Header.Set("X-API-Key", k.APIKey)
	if resp, _ := app.Test(req); resp.StatusCode != 200 {
		t.Fatalf("header verify: %d", resp.StatusCode)
	}

	// Get, list, patch.
	if code, env, _ := do(t, app, "GET", "/v1/keys/"+k.ID, adminToken, nil); code != 200 || strings.Contains(string(env.Data), "key_hash") {
		t.Fatalf("get: %d %s", code, env.Data)
	}
	code, env, _ := do(t, app, "GET", "/v1/keys?active=true&prefix=demo", adminToken, nil)
	if code != 200 || !strings.Contains(string(env.Meta), `"total":1`) {
		t.Fatalf("list: %d %s", code, env.Meta)
	}
	code, env, _ = do(t, app, "PATCH", "/v1/keys/"+k.ID, adminToken, map[string]any{"name": "renamed", "rate_limit": 5})
	if code != 200 || !strings.Contains(string(env.Data), `"renamed"`) {
		t.Fatalf("patch: %d %s", code, env.Data)
	}

	// Usage was recorded.
	code, env, _ = do(t, app, "GET", "/v1/usage/"+k.ID, adminToken, nil)
	if code != 200 || !strings.Contains(string(env.Data), `"status":200`) {
		t.Fatalf("usage: %d %s", code, env.Data)
	}

	// Revoke, then verify says revoked.
	if code, _, _ := do(t, app, "DELETE", "/v1/keys/"+k.ID, adminToken, nil); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, v := verify(t, app, k.APIKey); code != 401 || v.Reason != "revoked" {
		t.Fatalf("verify revoked: %d %+v", code, v)
	}
	if code, _, _ := do(t, app, "DELETE", "/v1/keys/00000000-0000-0000-0000-000000000000", adminToken, nil); code != 404 {
		t.Fatalf("revoke unknown: %d", code)
	}
	if code, _, _ := do(t, app, "DELETE", "/v1/keys/not-a-uuid", adminToken, nil); code != 400 {
		t.Fatalf("revoke bad id: %d", code)
	}

	// Audit trail has the events.
	code, env, _ = do(t, app, "GET", "/v1/audit?event_type=revoke_key", adminToken, nil)
	if code != 200 || !strings.Contains(string(env.Data), k.ID) {
		t.Fatalf("audit: %d %s", code, env.Data)
	}
}

func TestNoPrefixAndValidation(t *testing.T) {
	app := integrationApp(t, testConfig())
	k := create(t, app, map[string]any{})
	if code, v := verify(t, app, k.APIKey); code != 200 || !v.Valid {
		t.Fatalf("no-prefix verify: %d %+v", code, v)
	}
	for _, body := range []map[string]any{
		{"key_prefix": "bad-prefix"},
		{"rate_limit": -1},
		{"expires_at": time.Now().Add(-time.Hour).Format(time.RFC3339)},
		{"metadata": []int{1, 2}},
	} {
		if code, _, _ := do(t, app, "POST", "/v1/keys", adminToken, body); code != 400 {
			t.Errorf("create %v: expected 400, got %d", body, code)
		}
	}
}

func TestExpiry(t *testing.T) {
	app := integrationApp(t, testConfig())
	k := create(t, app, map[string]any{"expires_at": time.Now().Add(1500 * time.Millisecond).Format(time.RFC3339Nano)})
	if code, _ := verify(t, app, k.APIKey); code != 200 {
		t.Fatalf("before expiry: %d", code)
	}
	time.Sleep(1600 * time.Millisecond)
	if code, v := verify(t, app, k.APIKey); code != 401 || v.Reason != "expired" {
		t.Fatalf("after expiry: %d %+v", code, v)
	}
}

func TestRateLimit(t *testing.T) {
	app := integrationApp(t, testConfig())
	k := create(t, app, map[string]any{"rate_limit": 3})
	for i := 0; i < 3; i++ {
		code, v := verify(t, app, k.APIKey)
		if code != 200 || v.RateLimit == nil || v.RateLimit.Remaining != 2-i {
			t.Fatalf("call %d: %d %+v", i, code, v)
		}
	}
	code, env, hdr := do(t, app, "POST", "/v1/keys/verify", "", map[string]string{"api_key": k.APIKey})
	if code != 429 || hdr.Get("Retry-After") == "" || !strings.Contains(string(env.Data), "rate_limited") {
		t.Fatalf("over limit: %d %s", code, env.Data)
	}
}

func TestRotate(t *testing.T) {
	app := integrationApp(t, testConfig())
	old := create(t, app, map[string]any{"key_prefix": "live", "name": "svc", "rate_limit": 10})
	code, env, _ := do(t, app, "POST", "/v1/keys/"+old.ID+"/rotate", adminToken, nil)
	if code != 201 {
		t.Fatalf("rotate: %d %s", code, env.Message)
	}
	var fresh createdKey
	_ = json.Unmarshal(env.Data, &fresh)
	if fresh.ID == old.ID || fresh.Name != "svc" || fresh.RateLimit != 10 || !strings.HasPrefix(fresh.APIKey, "live_") {
		t.Fatalf("rotated key: %+v", fresh)
	}
	if code, v := verify(t, app, old.APIKey); code != 401 || v.Reason != "revoked" {
		t.Fatalf("old key after rotate: %d %+v", code, v)
	}
	if code, _ := verify(t, app, fresh.APIKey); code != 200 {
		t.Fatalf("new key after rotate: %d", code)
	}
	if code, _, _ := do(t, app, "POST", "/v1/keys/"+old.ID+"/rotate", adminToken, nil); code != 409 {
		t.Fatalf("rotate revoked: %d", code)
	}
}
