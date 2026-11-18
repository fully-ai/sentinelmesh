package crypto

import (
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("expected error for short password")
	}
	hash, err := HashPassword("Sup3rS3cret!Pass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword("Sup3rS3cret!Pass", hash) {
		t.Fatal("expected password to verify")
	}
	if VerifyPassword("wrong-password", hash) {
		t.Fatal("expected wrong password to fail")
	}
}

func TestTokenSignAndVerify(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now().UTC()
	tok, err := SignToken(secret, TokenClaims{
		UserID:    "u1",
		Username:  "alice",
		Role:      "analyst",
		TenantID:  "acme",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	claims, err := VerifyToken(secret, tok, now)
	if err != nil || claims.Username != "alice" || claims.TenantID != "acme" {
		t.Fatalf("VerifyToken failed: err=%v claims=%+v", err, claims)
	}
	if _, err := VerifyToken(secret, tok+"x", now); err == nil {
		t.Fatal("expected tampered token rejection")
	}
	if _, err := VerifyToken(secret, tok, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expected expired token rejection")
	}
}

func TestAgentHMACAndReplayProtection(t *testing.T) {
	secret := "agent-shared-secret-value"
	now := time.Now().UTC()
	ts := "1700000000"
	nowFixed := time.Unix(1700000005, 0).UTC()
	body := []byte(`{"events":[]}`)
	sig := SignAgentRequest(secret, http.MethodPost, "/api/v1/ingest", ts, "nonce-1", body)
	cache := NewNonceCache(5*time.Minute, 100)

	if err := VerifyAgentRequest(secret, http.MethodPost, "/api/v1/ingest", ts, "nonce-1", sig, body, nowFixed, cache); err != nil {
		t.Fatalf("expected valid HMAC signature: %v", err)
	}
	if err := VerifyAgentRequest(secret, http.MethodPost, "/api/v1/ingest", ts, "nonce-1", sig, body, nowFixed, cache); err == nil {
		t.Fatal("expected replayed nonce to fail")
	}
	if err := VerifyAgentRequest(secret, http.MethodPost, "/api/v1/ingest", "1699000000", "nonce-2", sig, body, now, cache); err == nil {
		t.Fatal("expected stale timestamp to fail")
	}
}

func TestEd25519UpdateManifestVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified-agent-binary-contents")
	m := UpdateManifest{
		Version:   "0.1.0",
		OS:        "linux",
		Arch:      "amd64",
		SHA256:    SHA256Hex(payload),
		Download:  "https://example.invalid/agent",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	signed, err := SignUpdateManifest(priv, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyUpdateManifest(pub, signed, payload); err != nil {
		t.Fatalf("VerifyUpdateManifest: %v", err)
	}
	if err := VerifyUpdateManifest(pub, signed, []byte("tampered")); err == nil {
		t.Fatal("expected tampered payload to fail SHA-256 verification")
	}
}
