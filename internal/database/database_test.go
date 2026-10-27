package database

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// freshSchema creates an isolated schema and returns a DSN pointing at it.
func freshSchema(t *testing.T) (string, *pgx.Conn, string) {
	t.Helper()
	dsn := os.Getenv("AUTHCELL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHCELL_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("authcell_dbtest_%d", time.Now().UnixNano())
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
	return dsn + sep + "search_path=" + schema, conn, schema
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dsn, _, _ := freshSchema(t)
	for i := 0; i < 2; i++ {
		db, err := Connect(context.Background(), dsn, Options{})
		if err != nil {
			t.Fatalf("connect #%d: %v", i, err)
		}
		db.Close()
	}
}

// TestUpgradeFromLegacySchema builds the schema the original AuthCell created,
// inserts a row the old code would have written, and checks it survives.
func TestUpgradeFromLegacySchema(t *testing.T) {
	dsn, conn, schema := freshSchema(t)
	ctx := context.Background()
	_, err := conn.Exec(ctx, `SET search_path=`+schema+`;`+migrations[0]+`
		CREATE INDEX IF NOT EXISTS idx_key_id ON api_key (key_id);
		INSERT INTO api_key (key_id, key_hash, key_prefix, is_active, rate_limit, usage_count)
		VALUES ('4d83e91f', '$2a$10$abcdefghijklmnopqrstuv', 'demo_', NULL, NULL, NULL);
		INSERT INTO audit_log (actor_id, actor_type, event_type) VALUES (gen_random_uuid(), 'system', 'create_key');
		RESET search_path;`)
	if err != nil {
		t.Fatal(err)
	}

	db, err := Connect(ctx, dsn, Options{})
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer db.Close()

	k, err := db.GetAPIKeyByKeyID(ctx, "4d83e91f")
	if err != nil {
		t.Fatal(err)
	}
	if !k.IsActive || k.RateLimit != 0 || k.UsageCount != 0 || string(k.Metadata) != "{}" {
		t.Fatalf("legacy row not normalized: %+v", k)
	}
	logs, err := db.ListAuditLog(ctx, AuditFilter{Limit: 10})
	if err != nil || len(logs) != 1 {
		t.Fatalf("legacy audit rows: %v %d", err, len(logs))
	}
}

func TestRecordUseWindow(t *testing.T) {
	dsn, _, _ := freshSchema(t)
	ctx := context.Background()
	db, err := Connect(ctx, dsn, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	k, err := db.CreateAPIKey(ctx, NewAPIKey{KeyID: "aaaaaaaaaaaaaaaa", KeyHash: "sha256:x", RateLimit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAPIKey(ctx, NewAPIKey{KeyID: "aaaaaaaaaaaaaaaa", KeyHash: "sha256:y"}); err != ErrDuplicate {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}

	window := time.Second
	for want := 1; want <= 3; want++ {
		r, err := db.RecordUse(ctx, k.ID, window)
		if err != nil {
			t.Fatal(err)
		}
		if r.WindowCount != want {
			t.Fatalf("window count %d, want %d", r.WindowCount, want)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	r, err := db.RecordUse(ctx, k.ID, window)
	if err != nil || r.WindowCount != 1 {
		t.Fatalf("window did not reset: %+v %v", r, err)
	}
	got, _ := db.GetAPIKeyByID(ctx, k.ID)
	if got.UsageCount != 4 || got.LastUsedAt == nil {
		t.Fatalf("usage not tracked: %+v", got)
	}

	if _, err := db.GetAPIKeyByID(ctx, "not-a-uuid"); err != ErrNotFound {
		t.Fatalf("bad uuid should be ErrNotFound, got %v", err)
	}

	// Usage with no key and a junk IP must not error.
	if err := db.TrackUsage(ctx, "", "/v1/keys/verify", "not-an-ip", 401); err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneUsage(ctx, time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
}
