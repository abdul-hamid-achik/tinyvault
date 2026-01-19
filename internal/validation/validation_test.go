package validation

import (
	"strings"
	"testing"
)

func TestUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  error
	}{
		{
			name:     "valid username",
			username: "john_doe",
			wantErr:  nil,
		},
		{
			name:     "valid username with numbers",
			username: "user123",
			wantErr:  nil,
		},
		{
			name:     "valid minimum length",
			username: "abc",
			wantErr:  nil,
		},
		{
			name:     "too short",
			username: "ab",
			wantErr:  ErrUsernameTooShort,
		},
		{
			name:     "empty",
			username: "",
			wantErr:  ErrUsernameTooShort,
		},
		{
			name:     "too long",
			username: strings.Repeat("a", 51),
			wantErr:  ErrUsernameTooLong,
		},
		{
			name:     "max length valid",
			username: strings.Repeat("a", 50),
			wantErr:  nil,
		},
		{
			name:     "invalid characters - hyphen",
			username: "john-doe",
			wantErr:  ErrUsernameInvalidChars,
		},
		{
			name:     "invalid characters - space",
			username: "john doe",
			wantErr:  ErrUsernameInvalidChars,
		},
		{
			name:     "invalid characters - special",
			username: "john@doe",
			wantErr:  ErrUsernameInvalidChars,
		},
		{
			name:     "whitespace is trimmed",
			username: "  john_doe  ",
			wantErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Username(tt.username)
			if err != tt.wantErr {
				t.Errorf("Username(%q) = %v, want %v", tt.username, err, tt.wantErr)
			}
		})
	}
}

func TestEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr error
	}{
		{
			name:    "valid email",
			email:   "user@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with subdomain",
			email:   "user@mail.example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with plus",
			email:   "user+tag@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with dots",
			email:   "first.last@example.com",
			wantErr: nil,
		},
		{
			name:    "empty",
			email:   "",
			wantErr: ErrEmailEmpty,
		},
		{
			name:    "whitespace only",
			email:   "   ",
			wantErr: ErrEmailEmpty,
		},
		{
			name:    "missing @",
			email:   "userexample.com",
			wantErr: ErrEmailInvalidFormat,
		},
		{
			name:    "missing domain",
			email:   "user@",
			wantErr: ErrEmailInvalidFormat,
		},
		{
			name:    "missing local part",
			email:   "@example.com",
			wantErr: ErrEmailInvalidFormat,
		},
		{
			name:    "invalid characters",
			email:   "user name@example.com",
			wantErr: ErrEmailInvalidFormat,
		},
		{
			name:    "too long",
			email:   strings.Repeat("a", 250) + "@b.co",
			wantErr: ErrEmailInvalidFormat,
		},
		{
			name:    "whitespace is trimmed",
			email:   "  user@example.com  ",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Email(tt.email)
			if err != tt.wantErr {
				t.Errorf("Email(%q) = %v, want %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestProjectName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "valid name",
			input:   "my-project",
			wantErr: nil,
		},
		{
			name:    "valid single char",
			input:   "a",
			wantErr: nil,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: ErrProjectNameEmpty,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: ErrProjectNameEmpty,
		},
		{
			name:    "too long",
			input:   strings.Repeat("a", 101),
			wantErr: ErrProjectNameTooLong,
		},
		{
			name:    "max length valid",
			input:   strings.Repeat("a", 100),
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProjectName(tt.input)
			if err != tt.wantErr {
				t.Errorf("ProjectName(%q) = %v, want %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestProjectDescription(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "valid description",
			input:   "This is a project description",
			wantErr: nil,
		},
		{
			name:    "empty is valid",
			input:   "",
			wantErr: nil,
		},
		{
			name:    "max length valid",
			input:   strings.Repeat("a", 500),
			wantErr: nil,
		},
		{
			name:    "too long",
			input:   strings.Repeat("a", 501),
			wantErr: ErrDescriptionTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProjectDescription(tt.input)
			if err != tt.wantErr {
				t.Errorf("ProjectDescription(%q) = %v, want %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestSecretKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr error
	}{
		{
			name:    "valid env var",
			key:     "DATABASE_URL",
			wantErr: nil,
		},
		{
			name:    "valid with underscore prefix",
			key:     "_PRIVATE_KEY",
			wantErr: nil,
		},
		{
			name:    "valid lowercase",
			key:     "api_key",
			wantErr: nil,
		},
		{
			name:    "valid mixed case",
			key:     "MySecret123",
			wantErr: nil,
		},
		{
			name:    "valid single char",
			key:     "A",
			wantErr: nil,
		},
		{
			name:    "valid underscore only",
			key:     "_",
			wantErr: nil,
		},
		{
			name:    "empty",
			key:     "",
			wantErr: ErrSecretKeyEmpty,
		},
		{
			name:    "too long",
			key:     strings.Repeat("A", 256),
			wantErr: ErrSecretKeyTooLong,
		},
		{
			name:    "max length valid",
			key:     strings.Repeat("A", 255),
			wantErr: nil,
		},
		{
			name:    "starts with number",
			key:     "1_SECRET",
			wantErr: ErrSecretKeyInvalidFormat,
		},
		{
			name:    "contains hyphen",
			key:     "SECRET-KEY",
			wantErr: ErrSecretKeyInvalidFormat,
		},
		{
			name:    "contains space",
			key:     "SECRET KEY",
			wantErr: ErrSecretKeyInvalidFormat,
		},
		{
			name:    "contains dot",
			key:     "SECRET.KEY",
			wantErr: ErrSecretKeyInvalidFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SecretKey(tt.key)
			if err != tt.wantErr {
				t.Errorf("SecretKey(%q) = %v, want %v", tt.key, err, tt.wantErr)
			}
		})
	}
}
