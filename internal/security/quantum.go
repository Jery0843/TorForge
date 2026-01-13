// Package security provides defense-in-depth features for TorForge.
//
// This package addresses threats that Tor itself doesn't cover:
//   - Post-quantum encryption: Protects locally stored data (exit IPs, ML weights)
//     against future quantum attacks using CRYSTALS-Kyber768 (NIST Level 3).
//   - Dead man's switch: Emergency shutdown clears traces when physical security
//     is compromised.
//   - Decoy traffic: Frustrates traffic analysis by injecting fake requests.
//
// Note: None of these protect network traffic—Tor handles that. These protect
// the local system state and frustrate forensic analysis.
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/jery0843/torforge/pkg/logger"
	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for password-based key derivation.
// Why these values? Balance between resistance to GPU/ASIC attacks and UX:
//   - 64MB memory: Makes parallel cracking expensive on GPUs
//   - 3 iterations: ~500ms on commodity hardware (acceptable for interactive use)
//   - 4 threads: Utilizes multi-core without monopolizing system
//
// Based on OWASP recommendations for password hashing.
const (
	argon2Time    = 3         // Number of iterations
	argon2Memory  = 64 * 1024 // 64 MB memory
	argon2Threads = 4         // Parallelism
	argon2KeyLen  = 32        // 256-bit key
	saltSize      = 16        // 128-bit salt
)

// PostQuantumConfig configures the post-quantum encryption layer
type PostQuantumConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Algorithm string `yaml:"algorithm"` // "kyber768"
	Password  string `yaml:"password"`  // Password for persistent file encryption
}

// QuantumResistantLayer provides an additional encryption layer
// that is resistant to quantum computer attacks using CRYSTALS-Kyber
type QuantumResistantLayer struct {
	mu        sync.RWMutex
	enabled   bool
	algorithm string

	// Kyber key pair (using real Kyber768)
	publicKey  *kyber768.PublicKey
	privateKey *kyber768.PrivateKey

	// Ciphertext from key encapsulation
	ciphertext []byte

	// Shared secret for symmetric encryption
	sharedSecret []byte
	cipher       cipher.AEAD

	// Password-derived cipher for persistent file encryption
	passwordSet    bool
	passwordSalt   []byte // Random salt for Argon2id
	passwordRaw    string // Raw password for key re-derivation on decrypt
	passwordCipher cipher.AEAD
}

// NewQuantumResistantLayer creates a new post-quantum encryption layer
func NewQuantumResistantLayer(cfg *PostQuantumConfig) (*QuantumResistantLayer, error) {
	log := logger.WithComponent("quantum")

	if cfg == nil || !cfg.Enabled {
		return &QuantumResistantLayer{enabled: false}, nil
	}

	q := &QuantumResistantLayer{
		enabled:   true,
		algorithm: "CRYSTALS-Kyber768",
	}

	// Generate Kyber key pair
	if err := q.generateKyberKeyPair(); err != nil {
		return nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
	}

	log.Info().
		Str("algorithm", q.algorithm).
		Msg("🔐 Post-quantum encryption layer initialized with REAL CRYSTALS-Kyber768")

	return q, nil
}

// generateKyberKeyPair generates a real CRYSTALS-Kyber768 key pair
func (q *QuantumResistantLayer) generateKyberKeyPair() error {
	// Generate Kyber768 key pair (NIST Level 3 security)
	pub, priv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return err
	}

	q.publicKey = pub
	q.privateKey = priv

	// Perform key encapsulation to derive shared secret
	// EncapsulateTo fills ciphertext and shared secret
	ct := make([]byte, kyber768.CiphertextSize)
	ss := make([]byte, kyber768.SharedKeySize)

	pub.EncapsulateTo(ct, ss, nil)

	// Store ciphertext
	q.ciphertext = ct

	// Verify we can decapsulate
	ssCheck := make([]byte, kyber768.SharedKeySize)
	priv.DecapsulateTo(ssCheck, ct)

	// Compare shared secrets
	if !compareBytes(ss, ssCheck) {
		return fmt.Errorf("kyber key exchange verification failed")
	}

	q.sharedSecret = ss

	// Create AES-256-GCM cipher using the Kyber-derived shared secret
	block, err := aes.NewCipher(q.sharedSecret)
	if err != nil {
		return err
	}

	q.cipher, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	return nil
}

// SetPassword sets a password for persistent file encryption
// This allows encrypted files to be decrypted later with the same password
// Uses Argon2id (OWASP recommended) for key derivation
func (q *QuantumResistantLayer) SetPassword(password string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if password == "" {
		q.passwordSet = false
		q.passwordSalt = nil
		q.passwordCipher = nil
		return nil
	}

	log := logger.WithComponent("quantum")

	// Generate random salt for Argon2id
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive 256-bit key using Argon2id (memory-hard, resistant to GPU/ASIC attacks)
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	q.passwordCipher, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	q.passwordSalt = salt
	q.passwordRaw = password
	q.passwordSet = true

	log.Info().
		Int("memory_mb", argon2Memory/1024).
		Int("iterations", argon2Time).
		Msg("🔑 Argon2id password encryption enabled for persistent files")

	return nil
}

// deriveKeyFromPassword derives AES key from password using stored salt
func deriveKeyFromPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// EncryptWithPassword encrypts data using the password-derived key
// Format: [16-byte salt][12-byte nonce][ciphertext+tag]
func (q *QuantumResistantLayer) EncryptWithPassword(plaintext []byte) ([]byte, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if !q.passwordSet || q.passwordCipher == nil || q.passwordSalt == nil {
		// Fall back to Kyber encryption if no password set
		return q.Encrypt(plaintext)
	}

	nonce := make([]byte, q.passwordCipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend salt so decryption can re-derive the key
	ciphertext := q.passwordCipher.Seal(nonce, nonce, plaintext, nil)
	result := make([]byte, 0, len(q.passwordSalt)+len(ciphertext))
	result = append(result, q.passwordSalt...)
	result = append(result, ciphertext...)
	return result, nil
}

// DecryptWithPassword decrypts data using the password-derived key
// Expects format: [16-byte salt][12-byte nonce][ciphertext+tag]
func (q *QuantumResistantLayer) DecryptWithPassword(data []byte) ([]byte, error) {
	q.mu.RLock()
	password := q.passwordSet
	q.mu.RUnlock()

	if !password {
		return nil, fmt.Errorf("password not set - cannot decrypt")
	}

	// Extract salt from beginning of data
	if len(data) < saltSize {
		return nil, fmt.Errorf("data too short: missing salt")
	}
	salt := data[:saltSize]
	ciphertext := data[saltSize:]

	// Re-derive key from password and extracted salt
	key := deriveKeyFromPassword(q.getPasswordForDecrypt(), salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aesgcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short: missing nonce")
	}

	nonce := ciphertext[:aesgcm.NonceSize()]
	encrypted := ciphertext[aesgcm.NonceSize():]

	plaintext, err := aesgcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// getPasswordForDecrypt returns the stored password for key re-derivation
func (q *QuantumResistantLayer) getPasswordForDecrypt() string {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.passwordRaw
}

// HasPassword returns whether a password is set
func (q *QuantumResistantLayer) HasPassword() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.passwordSet
}

// compareBytes compares two byte slices in constant time
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// Encrypt encrypts data with the quantum-resistant layer
func (q *QuantumResistantLayer) Encrypt(plaintext []byte) ([]byte, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if !q.enabled {
		return plaintext, nil
	}

	if q.cipher == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	nonce := make([]byte, q.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := q.cipher.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data with the quantum-resistant layer
func (q *QuantumResistantLayer) Decrypt(ciphertext []byte) ([]byte, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if !q.enabled {
		return ciphertext, nil
	}

	if q.cipher == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	if len(ciphertext) < q.cipher.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:q.cipher.NonceSize()]
	encrypted := ciphertext[q.cipher.NonceSize():]

	plaintext, err := q.cipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// RotateKeys rotates the Kyber keys
func (q *QuantumResistantLayer) RotateKeys() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.generateKyberKeyPair()
}

// GetStatus returns the current status
func (q *QuantumResistantLayer) GetStatus() map[string]interface{} {
	q.mu.RLock()
	defer q.mu.RUnlock()

	keyID := "none"
	if len(q.sharedSecret) >= 8 {
		keyID = hex.EncodeToString(q.sharedSecret[:8])
	}

	return map[string]interface{}{
		"enabled":    q.enabled,
		"algorithm":  q.algorithm,
		"key_id":     keyID,
		"nist_level": 3,
		"security":   "192-bit quantum resistant",
	}
}

// IsEnabled returns whether the quantum layer is enabled
func (q *QuantumResistantLayer) IsEnabled() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.enabled
}

// TestEncryption performs a self-test
func (q *QuantumResistantLayer) TestEncryption() (bool, error) {
	testData := []byte("TorForge Post-Quantum Encryption Test - CRYSTALS-Kyber768")

	encrypted, err := q.Encrypt(testData)
	if err != nil {
		return false, err
	}

	decrypted, err := q.Decrypt(encrypted)
	if err != nil {
		return false, err
	}

	if !compareBytes(testData, decrypted) {
		return false, fmt.Errorf("decrypted data does not match original")
	}

	return true, nil
}

// DecryptFileWithPassword decrypts data that was encrypted with EncryptWithPassword
// This is a standalone function for CLI usage - doesn't require an existing QuantumResistantLayer
func DecryptFileWithPassword(data []byte, password string) ([]byte, error) {
	if len(data) < saltSize+12+16 {
		return nil, fmt.Errorf("data too short: expected at least %d bytes", saltSize+12+16)
	}

	// Extract salt
	salt := data[:saltSize]
	ciphertext := data[saltSize:]

	// Derive key using Argon2id
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < aesgcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short for nonce")
	}

	nonce := ciphertext[:aesgcm.NonceSize()]
	encrypted := ciphertext[aesgcm.NonceSize():]

	plaintext, err := aesgcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	return plaintext, nil
}
