// Package crypto provides secure cryptographic operations for TinyVault.
// It implements AES-256-GCM for symmetric encryption and Argon2id for key derivation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// KeySize is the size of AES-256 keys in bytes.
	KeySize = 32

	// NonceSize is the size of GCM nonces in bytes.
	NonceSize = 12

	// TagSize is the size of GCM authentication tags in bytes.
	TagSize = 16

	// SaltSize is the size of salts for key derivation in bytes.
	SaltSize = 16

	// Argon2Time is the time parameter for Argon2id.
	Argon2Time = 3

	// Argon2Memory is the memory parameter for Argon2id in KiB.
	Argon2Memory = 64 * 1024

	// Argon2Threads is the parallelism parameter for Argon2id.
	Argon2Threads = 4
)

var (
	// ErrInvalidKeySize is returned when a key has an incorrect size.
	ErrInvalidKeySize = errors.New("key must be 32 bytes")

	// ErrInvalidCiphertext is returned when ciphertext is malformed.
	ErrInvalidCiphertext = errors.New("ciphertext too short")

	// ErrDecryptionFailed is returned when decryption fails (authentication error).
	ErrDecryptionFailed = errors.New("decryption failed: authentication error")

	// ErrInvalidSaltSize is returned when a salt has an incorrect size.
	ErrInvalidSaltSize = errors.New("salt must be 16 bytes")
)

// Encrypt encrypts plaintext using AES-256-GCM.
// It generates a random nonce and prepends it to the ciphertext.
// The result is: nonce (12 bytes) + ciphertext + tag (16 bytes).
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal prepends nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
// It expects the nonce to be prepended to the ciphertext.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// Minimum length: nonce + tag
	if len(ciphertext) < NonceSize+TagSize {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := ciphertext[:NonceSize]
	ciphertext = ciphertext[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// GenerateKey generates a cryptographically secure random 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// GenerateSalt generates a cryptographically secure random 16-byte salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a 32-byte key from a password using Argon2id.
// The salt must be 16 bytes.
func DeriveKey(password, salt []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, ErrInvalidSaltSize
	}

	key := argon2.IDKey(password, salt, Argon2Time, Argon2Memory, Argon2Threads, KeySize)
	return key, nil
}

// HashToken creates a SHA-256 hash of a token.
// Use this to hash tokens before storing them in the database.
func HashToken(token []byte) []byte {
	hash := sha256.Sum256(token)
	return hash[:]
}

// HashTokenString is a convenience function that hashes a string token.
func HashTokenString(token string) []byte {
	return HashToken([]byte(token))
}

// CompareTokens compares two token hashes in constant time.
// Returns true if they are equal, false otherwise.
func CompareTokens(hash1, hash2 []byte) bool {
	return subtle.ConstantTimeCompare(hash1, hash2) == 1
}

// GenerateToken generates a random token of the specified length in bytes.
// Returns the raw bytes.
func GenerateToken(length int) ([]byte, error) {
	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	return token, nil
}

// GenerateTokenString generates a random token and returns it as a base64 string.
func GenerateTokenString(length int) (string, error) {
	token, err := GenerateToken(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

// EncryptString encrypts a string and returns base64-encoded ciphertext.
func EncryptString(key []byte, plaintext string) (string, error) {
	ciphertext, err := Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts base64-encoded ciphertext and returns the plaintext string.
func DecryptString(key []byte, ciphertextB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// EncodeKey encodes a key to base64 for storage/transmission.
func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodeKey decodes a base64-encoded key.
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	return key, nil
}

// ZeroBytes securely zeros a byte slice.
// Use this to clear sensitive data from memory when done.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// PasswordHashSize is the size of the derived key for password hashing.
const PasswordHashSize = 32

// HashPassword hashes a password using Argon2id and returns a base64-encoded string.
// The format is: base64(salt || hash) where salt is 16 bytes and hash is 32 bytes.
func HashPassword(password string) (string, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, PasswordHashSize)

	// Combine salt and hash
	combined := make([]byte, SaltSize+PasswordHashSize)
	copy(combined[:SaltSize], salt)
	copy(combined[SaltSize:], hash)

	return base64.StdEncoding.EncodeToString(combined), nil
}

// VerifyPassword verifies a password against a hash created by HashPassword.
// Returns true if the password matches, false otherwise.
func VerifyPassword(password, encodedHash string) bool {
	combined, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil {
		return false
	}

	if len(combined) != SaltSize+PasswordHashSize {
		return false
	}

	salt := combined[:SaltSize]
	storedHash := combined[SaltSize:]

	// Derive key from provided password
	computedHash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, PasswordHashSize)

	// Constant-time comparison
	return subtle.ConstantTimeCompare(storedHash, computedHash) == 1
}
