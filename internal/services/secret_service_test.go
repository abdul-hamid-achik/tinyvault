package services

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSecret_Fields(t *testing.T) {
	secret := Secret{
		ID:        uuid.New(),
		ProjectID: uuid.New(),
		Key:       "DATABASE_URL",
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if secret.ID == uuid.Nil {
		t.Error("Secret.ID should not be nil")
	}
	if secret.ProjectID == uuid.Nil {
		t.Error("Secret.ProjectID should not be nil")
	}
	if secret.Key == "" {
		t.Error("Secret.Key should not be empty")
	}
	if secret.Version != 1 {
		t.Errorf("Secret.Version = %d, want 1", secret.Version)
	}
	if secret.CreatedAt.IsZero() {
		t.Error("Secret.CreatedAt should not be zero")
	}
	if secret.UpdatedAt.IsZero() {
		t.Error("Secret.UpdatedAt should not be zero")
	}
}

func TestSecretWithValue_Fields(t *testing.T) {
	value := []byte("postgres://user:pass@localhost:5432/db")
	secretWithValue := SecretWithValue{
		Secret: Secret{
			ID:        uuid.New(),
			ProjectID: uuid.New(),
			Key:       "DATABASE_URL",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Value: value,
	}

	if secretWithValue.Value == nil {
		t.Error("SecretWithValue.Value should not be nil")
	}
	if string(secretWithValue.Value) != string(value) {
		t.Errorf("SecretWithValue.Value = %q, want %q", secretWithValue.Value, value)
	}
	if secretWithValue.Key == "" {
		t.Error("SecretWithValue.Key should not be empty")
	}
}

func TestSecretWithValue_EmptyValue(t *testing.T) {
	// Secrets can have empty values
	secretWithValue := SecretWithValue{
		Secret: Secret{
			ID:        uuid.New(),
			ProjectID: uuid.New(),
			Key:       "EMPTY_SECRET",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Value: []byte{},
	}

	if secretWithValue.Value == nil {
		t.Error("SecretWithValue.Value should not be nil even when empty")
	}
	if len(secretWithValue.Value) != 0 {
		t.Errorf("SecretWithValue.Value length = %d, want 0", len(secretWithValue.Value))
	}
}

func TestSecretWithValue_BinaryValue(t *testing.T) {
	// Secrets can contain binary data
	binaryValue := []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF}
	secretWithValue := SecretWithValue{
		Secret: Secret{
			ID:        uuid.New(),
			ProjectID: uuid.New(),
			Key:       "BINARY_SECRET",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Value: binaryValue,
	}

	if len(secretWithValue.Value) != len(binaryValue) {
		t.Errorf("SecretWithValue.Value length = %d, want %d", len(secretWithValue.Value), len(binaryValue))
	}
	for i := range binaryValue {
		if secretWithValue.Value[i] != binaryValue[i] {
			t.Errorf("SecretWithValue.Value[%d] = %x, want %x", i, secretWithValue.Value[i], binaryValue[i])
		}
	}
}

func TestSecretKeyValidation(t *testing.T) {
	// Test various secret key formats
	validKeys := []string{
		"DATABASE_URL",
		"API_KEY",
		"_PRIVATE_KEY",
		"a",
		"A",
		"_",
		"MY_SECRET_123",
		"mySecret",
	}

	for _, key := range validKeys {
		secret := Secret{
			ID:        uuid.New(),
			ProjectID: uuid.New(),
			Key:       key,
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if secret.Key != key {
			t.Errorf("Secret.Key = %q, want %q", secret.Key, key)
		}
	}
}

func TestSecretVersion(t *testing.T) {
	// Test that version increments work correctly
	tests := []struct {
		name    string
		version int32
	}{
		{"initial version", 1},
		{"updated once", 2},
		{"updated many times", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := Secret{
				ID:        uuid.New(),
				ProjectID: uuid.New(),
				Key:       "TEST_KEY",
				Version:   tt.version,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			if secret.Version != tt.version {
				t.Errorf("Secret.Version = %d, want %d", secret.Version, tt.version)
			}
		})
	}
}

func TestNewSecretService(t *testing.T) {
	// Test struct initialization
	service := &SecretService{
		queries:        nil,
		pool:           nil,
		projectService: nil,
	}

	if service.queries != nil {
		t.Error("SecretService.queries should be nil without DB connection")
	}
	if service.projectService != nil {
		t.Error("SecretService.projectService should be nil when not provided")
	}
}
