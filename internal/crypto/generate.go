package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	charsetAlphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetASCII        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// MaxGeneratedSecretLength is the maximum length GenerateRandomString accepts.
const MaxGeneratedSecretLength = 256

// GenerateRandomString returns a cryptographically random string of the given
// length using charset: alphanumeric, hex, base64, or ascii.
func GenerateRandomString(length int, charset string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	if length > MaxGeneratedSecretLength {
		return "", fmt.Errorf("length must be at most %d", MaxGeneratedSecretLength)
	}
	switch charset {
	case "hex":
		b := make([]byte, (length+1)/2)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b)[:length], nil
	case "base64":
		b := make([]byte, length)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		encoded := base64.URLEncoding.EncodeToString(b)
		if len(encoded) > length {
			encoded = encoded[:length]
		}
		return encoded, nil
	case "alphanumeric":
		return randomFromCharset(length, charsetAlphanumeric)
	case "ascii":
		return randomFromCharset(length, charsetASCII)
	default:
		return "", fmt.Errorf("unsupported charset %q (use alphanumeric, hex, base64, or ascii)", charset)
	}
}

func randomFromCharset(length int, charset string) (string, error) {
	charsetLen := big.NewInt(int64(len(charset)))
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}
