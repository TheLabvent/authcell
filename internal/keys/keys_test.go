package keys

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNormalizePrefix(t *testing.T) {
	cases := map[string]struct {
		want    string
		wantErr bool
	}{
		"":                      {"", false},
		"demo":                  {"demo", false},
		"demo_":                 {"demo", false},
		" live__ ":              {"live", false},
		"my_app":                {"my_app", false},
		"my__app":               {"", true},
		"bad-char":              {"", true},
		"sp ace":                {"", true},
		"_leading":              {"", true},
		strings.Repeat("a", 33): {"", true},
	}
	for in, tc := range cases {
		got, err := NormalizePrefix(in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("NormalizePrefix(%q) = %q, %v; want %q, err=%v", in, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestGenerateParseRoundTrip(t *testing.T) {
	for _, prefix := range []string{"", "demo", "my_app_live"} {
		g, err := Generate(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if len(g.KeyID) != KeyIDBytes*2 {
			t.Fatalf("key id length %d", len(g.KeyID))
		}
		p, err := Parse(g.Plaintext)
		if err != nil {
			t.Fatalf("Parse(%q): %v", g.Plaintext, err)
		}
		if p.KeyID != g.KeyID || p.Prefix != prefix {
			t.Fatalf("parsed %+v from %q, want prefix %q id %q", p, g.Plaintext, prefix, g.KeyID)
		}
		if ok, legacy := Compare(g.Hash, g.Plaintext); !ok || legacy {
			t.Fatalf("Compare failed for fresh key")
		}
		if ok, _ := Compare(g.Hash, g.Plaintext+"x"); ok {
			t.Fatalf("Compare accepted a wrong key")
		}
	}
}

func TestGenerateIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		g, err := Generate("t")
		if err != nil {
			t.Fatal(err)
		}
		if seen[g.KeyID] {
			t.Fatalf("duplicate key id %s", g.KeyID)
		}
		seen[g.KeyID] = true
	}
}

func TestParseLegacyFormat(t *testing.T) {
	// Keys minted by the original version: "<prefix_>" + 8 hex + "_" + uuid.
	p, err := Parse("demo_4d83e91f_98d9c77a-b067-4723-9325-70f59dfd448b")
	if err != nil {
		t.Fatal(err)
	}
	if p.Prefix != "demo" || p.KeyID != "4d83e91f" {
		t.Fatalf("got %+v", p)
	}
	if !PrefixMatches(p.Prefix, "demo_") {
		t.Fatal("legacy stored prefix should match")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"", "nounderscore", "_", "abc_", "_abc", "demo_NOTHEX123_secret",
		"demo_abc_secret", strings.Repeat("a", MaxKeyLength) + "_deadbeef_x",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) should fail", in)
		}
	}
}

func TestCompareLegacyBcrypt(t *testing.T) {
	key := "demo_4d83e91f_98d9c77a-b067-4723-9325-70f59dfd448b"
	h, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ok, legacy := Compare(string(h), key)
	if !ok || !legacy {
		t.Fatalf("legacy compare: ok=%v legacy=%v", ok, legacy)
	}
	if ok, _ := Compare(string(h), key+"x"); ok {
		t.Fatal("legacy compare accepted wrong key")
	}
	if ok, _ := Compare("", key); ok {
		t.Fatal("empty hash must never match")
	}
}
