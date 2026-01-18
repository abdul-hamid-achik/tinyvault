package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if len(key) != KeySize {
		t.Errorf("GenerateKey() returned key of length %d, want %d", len(key), KeySize)
	}

	// Verify keys are random (generate two and compare)
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() second call error = %v", err)
	}
	if bytes.Equal(key, key2) {
		t.Error("GenerateKey() returned identical keys")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	if len(salt) != SaltSize {
		t.Errorf("GenerateSalt() returned salt of length %d, want %d", len(salt), SaltSize)
	}

	// Verify salts are random
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() second call error = %v", err)
	}
	if bytes.Equal(salt, salt2) {
		t.Error("GenerateSalt() returned identical salts")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"medium", []byte("The quick brown fox jumps over the lazy dog")},
		{"long", bytes.Repeat([]byte("x"), 10000)},
		{"unicode", []byte("Hello World")},
		{"binary", []byte{0x00, 0xFF, 0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF}},
		{"null_bytes", []byte("hello\x00world\x00")},
		{"all_zeros", make([]byte, 100)},
		{"all_ones", bytes.Repeat([]byte{0xFF}, 100)},
	}

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := Encrypt(key, tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Verify ciphertext is longer than plaintext (nonce + tag)
			minLen := len(tt.plaintext) + NonceSize + TagSize
			if len(ciphertext) < minLen {
				t.Errorf("Encrypt() ciphertext too short: got %d, want >= %d", len(ciphertext), minLen)
			}

			// Decrypt and verify
			decrypted, err := Decrypt(key, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("same plaintext")

	// Encrypt same plaintext twice
	ciphertext1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() first call error = %v", err)
	}

	ciphertext2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() second call error = %v", err)
	}

	// Ciphertexts should be different (different nonces)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Encrypt() produced identical ciphertexts for same plaintext (nonce reuse)")
	}

	// Both should decrypt correctly
	dec1, _ := Decrypt(key, ciphertext1)
	dec2, _ := Decrypt(key, ciphertext2)

	if !bytes.Equal(dec1, plaintext) || !bytes.Equal(dec2, plaintext) {
		t.Error("Different encryptions didn't decrypt to same plaintext")
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr error
	}{
		{"empty_key", 0, ErrInvalidKeySize},
		{"short_key", 16, ErrInvalidKeySize},
		{"long_key", 64, ErrInvalidKeySize},
		{"off_by_one_short", 31, ErrInvalidKeySize},
		{"off_by_one_long", 33, ErrInvalidKeySize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := Encrypt(key, []byte("test"))
			if err != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecrypt_InvalidKeySize(t *testing.T) {
	// First create valid ciphertext
	validKey, _ := GenerateKey()
	ciphertext, _ := Encrypt(validKey, []byte("test"))

	tests := []struct {
		name    string
		keyLen  int
		wantErr error
	}{
		{"empty_key", 0, ErrInvalidKeySize},
		{"short_key", 16, ErrInvalidKeySize},
		{"long_key", 64, ErrInvalidKeySize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := Decrypt(key, ciphertext)
			if err != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	key, _ := GenerateKey()

	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    error
	}{
		{"empty", []byte{}, ErrInvalidCiphertext},
		{"too_short", make([]byte, NonceSize+TagSize-1), ErrInvalidCiphertext},
		{"just_nonce", make([]byte, NonceSize), ErrInvalidCiphertext},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(key, tt.ciphertext)
			if err != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("secret message")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Tamper with different parts of the ciphertext
	tests := []struct {
		name       string
		tamperFunc func([]byte) []byte
	}{
		{
			"flip_first_byte",
			func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				tampered[0] ^= 0xFF
				return tampered
			},
		},
		{
			"flip_middle_byte",
			func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				tampered[len(ct)/2] ^= 0xFF
				return tampered
			},
		},
		{
			"flip_last_byte",
			func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				tampered[len(ct)-1] ^= 0xFF
				return tampered
			},
		},
		{
			"truncate_one_byte",
			func(ct []byte) []byte {
				return ct[:len(ct)-1]
			},
		},
		{
			"append_byte",
			func(ct []byte) []byte {
				return append(ct, 0x00)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := tt.tamperFunc(ciphertext)
			_, err := Decrypt(key, tampered)
			if err != ErrDecryptionFailed && err != ErrInvalidCiphertext {
				t.Errorf("Decrypt() with tampered ciphertext error = %v, want authentication error", err)
			}
		})
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	ciphertext, _ := Encrypt(key1, []byte("secret"))

	_, err := Decrypt(key2, ciphertext)
	if err != ErrDecryptionFailed {
		t.Errorf("Decrypt() with wrong key error = %v, want %v", err, ErrDecryptionFailed)
	}
}

func TestDeriveKey(t *testing.T) {
	password := []byte("my-secret-password")
	salt, _ := GenerateSalt()

	key, err := DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	if len(key) != KeySize {
		t.Errorf("DeriveKey() returned key of length %d, want %d", len(key), KeySize)
	}

	// Same password + salt should produce same key
	key2, _ := DeriveKey(password, salt)
	if !bytes.Equal(key, key2) {
		t.Error("DeriveKey() not deterministic")
	}

	// Different password should produce different key
	key3, _ := DeriveKey([]byte("different"), salt)
	if bytes.Equal(key, key3) {
		t.Error("DeriveKey() produced same key for different password")
	}

	// Different salt should produce different key
	salt2, _ := GenerateSalt()
	key4, _ := DeriveKey(password, salt2)
	if bytes.Equal(key, key4) {
		t.Error("DeriveKey() produced same key for different salt")
	}
}

func TestDeriveKey_InvalidSalt(t *testing.T) {
	password := []byte("password")

	tests := []struct {
		name    string
		saltLen int
	}{
		{"empty", 0},
		{"too_short", 15},
		{"too_long", 17},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt := make([]byte, tt.saltLen)
			_, err := DeriveKey(password, salt)
			if err != ErrInvalidSaltSize {
				t.Errorf("DeriveKey() error = %v, want %v", err, ErrInvalidSaltSize)
			}
		})
	}
}

func TestHashToken(t *testing.T) {
	token := []byte("my-api-token-12345")

	hash := HashToken(token)
	if len(hash) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("HashToken() returned hash of length %d, want 32", len(hash))
	}

	// Same token should produce same hash
	hash2 := HashToken(token)
	if !bytes.Equal(hash, hash2) {
		t.Error("HashToken() not deterministic")
	}

	// Different token should produce different hash
	hash3 := HashToken([]byte("different-token"))
	if bytes.Equal(hash, hash3) {
		t.Error("HashToken() produced same hash for different token")
	}
}

func TestHashTokenString(t *testing.T) {
	token := "my-api-token"
	hash := HashTokenString(token)

	// Should match HashToken with same input
	expected := HashToken([]byte(token))
	if !bytes.Equal(hash, expected) {
		t.Error("HashTokenString() doesn't match HashToken()")
	}
}

func TestCompareTokens(t *testing.T) {
	hash1 := HashToken([]byte("token1"))
	hash2 := HashToken([]byte("token1"))
	hash3 := HashToken([]byte("token2"))

	if !CompareTokens(hash1, hash2) {
		t.Error("CompareTokens() returned false for equal hashes")
	}

	if CompareTokens(hash1, hash3) {
		t.Error("CompareTokens() returned true for different hashes")
	}

	// Test with different lengths
	if CompareTokens(hash1, hash1[:16]) {
		t.Error("CompareTokens() returned true for different length hashes")
	}
}

func TestGenerateToken(t *testing.T) {
	lengths := []int{16, 32, 64, 128}

	for _, length := range lengths {
		t.Run("length_"+string(rune('0'+length)), func(t *testing.T) {
			token, err := GenerateToken(length)
			if err != nil {
				t.Fatalf("GenerateToken() error = %v", err)
			}
			if len(token) != length {
				t.Errorf("GenerateToken() returned token of length %d, want %d", len(token), length)
			}

			// Verify tokens are random
			token2, _ := GenerateToken(length)
			if bytes.Equal(token, token2) {
				t.Error("GenerateToken() returned identical tokens")
			}
		})
	}
}

func TestGenerateTokenString(t *testing.T) {
	tokenStr, err := GenerateTokenString(32)
	if err != nil {
		t.Fatalf("GenerateTokenString() error = %v", err)
	}

	// Should be valid base64
	decoded, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		t.Errorf("GenerateTokenString() returned invalid base64: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("GenerateTokenString() decoded length = %d, want 32", len(decoded))
	}
}

func TestEncryptString_DecryptString(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := "Hello, World! Special chars: @#$%^&*()"

	encrypted, err := EncryptString(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}

	// Should be valid base64
	_, err = base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Errorf("EncryptString() returned invalid base64: %v", err)
	}

	// Should decrypt correctly
	decrypted, err := DecryptString(key, encrypted)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("DecryptString() = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptString_InvalidBase64(t *testing.T) {
	key, _ := GenerateKey()

	_, err := DecryptString(key, "not-valid-base64!!!")
	if err == nil {
		t.Error("DecryptString() with invalid base64 should error")
	}
}

func TestEncodeKey_DecodeKey(t *testing.T) {
	key, _ := GenerateKey()

	encoded := EncodeKey(key)

	// Should be valid base64
	_, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Errorf("EncodeKey() returned invalid base64: %v", err)
	}

	// Should decode correctly
	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}

	if !bytes.Equal(decoded, key) {
		t.Error("DecodeKey() didn't return original key")
	}
}

func TestDecodeKey_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"invalid_base64", "not-valid!!!", true},
		{"wrong_length", base64.StdEncoding.EncodeToString(make([]byte, 16)), true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte{0xFF, 0xAA, 0x55, 0x00, 0x12, 0x34}
	original := make([]byte, len(data))
	copy(original, data)

	ZeroBytes(data)

	// All bytes should be zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("ZeroBytes() didn't zero byte at index %d: got %d", i, b)
		}
	}

	// Verify it actually changed
	if bytes.Equal(data, original) {
		t.Error("ZeroBytes() didn't modify the slice")
	}
}

func TestZeroBytes_Empty(t *testing.T) {
	data := []byte{}
	ZeroBytes(data) // Should not panic
}

// Benchmark tests
func BenchmarkEncrypt(b *testing.B) {
	key, _ := GenerateKey()
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(key, plaintext)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, _ := GenerateKey()
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)
	ciphertext, _ := Encrypt(key, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(key, ciphertext)
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	password := []byte("benchmark-password")
	salt, _ := GenerateSalt()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKey(password, salt)
	}
}

func BenchmarkHashToken(b *testing.B) {
	token := make([]byte, 64)
	rand.Read(token)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashToken(token)
	}
}
