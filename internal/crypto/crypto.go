package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// GenerateRandomHex returns n cryptographically random bytes encoded as hex.
func GenerateRandomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// HashPassword hashes a plaintext password with Argon2id and a unique random salt.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword compares a plaintext password against an Argon2id encoded hash.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var mem uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(expected)))
	return subtle.ConstantTimeCompare(got, expected) == 1
}

// TokenClaims stores signed operator session claims.
type TokenClaims struct {
	UserID    string `json:"sub"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TenantID  string `json:"tenant_id"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	JTI       string `json:"jti"`
}

// SignToken creates a compact HMAC-SHA256 signed JWT-compatible session token.
func SignToken(secret []byte, claims TokenClaims) (string, error) {
	if len(secret) < 16 {
		return "", errors.New("signing secret too short")
	}
	if claims.JTI == "" {
		jti, err := GenerateRandomHex(12)
		if err != nil {
			return "", err
		}
		claims.JTI = jti
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

// VerifyToken validates signature and expiry and returns parsed claims.
func VerifyToken(secret []byte, token string, now time.Time) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || subtle.ConstantTimeCompare(gotSig, expectedSig) != 1 {
		return nil, errors.New("invalid token signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid token payload")
	}
	var claims TokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("corrupt token claims")
	}
	if now.Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

// SHA256Hex returns lowercase hex SHA-256 of input bytes.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SignAgentRequest computes HMAC-SHA256 over method, path, unix timestamp, nonce, and body SHA-256.
func SignAgentRequest(secret, method, path, timestamp, nonce string, body []byte) string {
	bodyHash := SHA256Hex(body)
	canonical := strings.Join([]string{strings.ToUpper(method), path, timestamp, nonce, bodyHash}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAgentRequest verifies timestamp skew, signature, and nonce uniqueness.
func VerifyAgentRequest(secret, method, path, timestamp, nonce, signature string, body []byte, now time.Time, nonces *NonceCache) error {
	if secret == "" || timestamp == "" || nonce == "" || signature == "" {
		return errors.New("missing agent authentication headers")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp header")
	}
	skew := now.Unix() - ts
	if skew < -300 || skew > 300 {
		return errors.New("agent timestamp outside +/-300s window")
	}
	expected := SignAgentRequest(secret, method, path, timestamp, nonce, body)
	if !hmac.Equal([]byte(strings.ToLower(signature)), []byte(expected)) {
		return errors.New("invalid agent request signature")
	}
	if nonces != nil && !nonces.AddIfFresh(nonce, now) {
		return errors.New("replayed request nonce")
	}
	return nil
}

// NonceCache tracks recently seen request nonces to defeat replay attacks.
type NonceCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxSize int
	seen    map[string]time.Time
}

// NewNonceCache constructs a bounded nonce cache with TTL expiration.
func NewNonceCache(ttl time.Duration, maxSize int) *NonceCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if maxSize <= 0 {
		maxSize = 50000
	}
	return &NonceCache{
		ttl:     ttl,
		maxSize: maxSize,
		seen:    make(map[string]time.Time),
	}
}

// AddIfFresh inserts nonce and returns true only if unseen within TTL.
func (c *NonceCache) AddIfFresh(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.seen) >= c.maxSize {
		for k, exp := range c.seen {
			if now.After(exp) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.maxSize {
			c.seen = make(map[string]time.Time)
		}
	}
	if exp, exists := c.seen[nonce]; exists && now.Before(exp) {
		return false
	}
	c.seen[nonce] = now.Add(c.ttl)
	return true
}

// UpdateManifest describes a signed agent release artifact.
type UpdateManifest struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Download  string `json:"download"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"` // base64 Ed25519 signature over canonical fields
}

func manifestCanonical(m UpdateManifest) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s", m.Version, m.OS, m.Arch, m.SHA256, m.Download, m.Timestamp))
}

// SignUpdateManifest signs a release manifest using an Ed25519 private key.
func SignUpdateManifest(priv ed25519.PrivateKey, m UpdateManifest) (UpdateManifest, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return m, errors.New("invalid ed25519 private key")
	}
	sig := ed25519.Sign(priv, manifestCanonical(m))
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return m, nil
}

// VerifyUpdateManifest verifies a release manifest and binary payload SHA-256 against a trusted Ed25519 public key.
func VerifyUpdateManifest(pub ed25519.PublicKey, m UpdateManifest, payload []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("decode manifest signature: %w", err)
	}
	if !ed25519.Verify(pub, manifestCanonical(m), sig) {
		return errors.New("manifest ed25519 signature verification failed")
	}
	if payload != nil {
		actual := SHA256Hex(payload)
		if subtle.ConstantTimeCompare([]byte(actual), []byte(strings.ToLower(m.SHA256))) != 1 {
			return fmt.Errorf("payload sha256 mismatch: expected %s got %s", m.SHA256, actual)
		}
	}
	return nil
}

// BuildServerTLSConfig loads server cert/key and optional client CA for mutual TLS.
func BuildServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if clientCAFile != "" {
		caPEM, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("failed to parse client CA PEM")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
