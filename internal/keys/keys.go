// Package keys generates, parses and hashes AuthCell API keys.
//
// Key format: <prefix>_<key_id>_<secret>
//
//   - prefix: optional, letters/digits with single underscores ("live", "my_app")
//   - key_id: 16 hex chars (64 bits), indexed for O(1) lookup
//   - secret: 48 hex chars (192 bits) from crypto/rand
//
// Keys without a prefix are just <key_id>_<secret>.
package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	KeyIDBytes     = 8
	SecretBytes    = 24
	MaxPrefixLen   = 32
	MaxKeyLength   = 256
	sha256HashPref = "sha256:"
)

var (
	ErrMalformed     = errors.New("malformed api key")
	ErrInvalidPrefix = errors.New("key_prefix may only contain letters, digits and single underscores, up to 32 characters")

	prefixPattern = regexp.MustCompile(`^[A-Za-z0-9]+(_[A-Za-z0-9]+)*$`)
	keyIDPattern  = regexp.MustCompile(`^[a-f0-9]{8,32}$`)
)

// Generated is a freshly minted key. Plaintext must be shown once and never stored.
type Generated struct {
	Plaintext string
	KeyID     string
	Prefix    string
	Hash      string
}

// NormalizePrefix trims whitespace and trailing underscores ("demo_" -> "demo")
// and validates the remaining characters.
func NormalizePrefix(p string) (string, error) {
	p = strings.TrimRight(strings.TrimSpace(p), "_")
	if p == "" {
		return "", nil
	}
	if len(p) > MaxPrefixLen || !prefixPattern.MatchString(p) {
		return "", ErrInvalidPrefix
	}
	return p, nil
}

// Generate creates a new key with the given (already normalized) prefix.
func Generate(prefix string) (Generated, error) {
	keyID, err := randomHex(KeyIDBytes)
	if err != nil {
		return Generated{}, err
	}
	secret, err := randomHex(SecretBytes)
	if err != nil {
		return Generated{}, err
	}
	plain := keyID + "_" + secret
	if prefix != "" {
		plain = prefix + "_" + plain
	}
	return Generated{Plaintext: plain, KeyID: keyID, Prefix: prefix, Hash: Hash(plain)}, nil
}

// Parsed holds the public parts of a presented key.
type Parsed struct {
	Prefix string
	KeyID  string
}

// Parse splits a presented key. The secret is the last segment and the key_id
// the one before it, so prefixes may contain underscores. Legacy keys
// (prefix + 8-char id + UUID) parse the same way.
func Parse(key string) (Parsed, error) {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > MaxKeyLength {
		return Parsed{}, ErrMalformed
	}
	last := strings.LastIndexByte(key, '_')
	if last <= 0 || last == len(key)-1 {
		return Parsed{}, ErrMalformed
	}
	head := key[:last]
	var p Parsed
	if i := strings.LastIndexByte(head, '_'); i >= 0 {
		p.Prefix, p.KeyID = head[:i], head[i+1:]
	} else {
		p.KeyID = head
	}
	if !keyIDPattern.MatchString(p.KeyID) {
		return Parsed{}, ErrMalformed
	}
	return p, nil
}

// PrefixMatches compares a parsed prefix with a stored one. Older versions stored
// prefixes with a trailing underscore ("demo_"), so both sides are normalized.
func PrefixMatches(presented, stored string) bool {
	return strings.TrimRight(presented, "_") == strings.TrimRight(stored, "_")
}

// Hash returns the storage form of a key. API keys carry 192 bits of entropy,
// so a fast SHA-256 digest is safe and avoids bcrypt's per-request CPU cost
// (and its silent 72-byte input limit).
func Hash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return sha256HashPref + hex.EncodeToString(sum[:])
}

// Compare checks a presented key against a stored hash in constant time.
// legacy is true when the stored hash is bcrypt and should be upgraded.
func Compare(storedHash, plain string) (ok bool, legacy bool) {
	if strings.HasPrefix(storedHash, sha256HashPref) {
		want := []byte(storedHash)
		got := []byte(Hash(plain))
		return subtle.ConstantTimeCompare(want, got) == 1, false
	}
	if strings.HasPrefix(storedHash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(plain)) == nil, true
	}
	return false, false
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
