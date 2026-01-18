// Package validation provides input validation functions.
package validation

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrUsernameTooShort is returned when username is less than 3 characters.
	ErrUsernameTooShort = errors.New("username must be at least 3 characters")
	// ErrUsernameTooLong is returned when username exceeds 50 characters.
	ErrUsernameTooLong = errors.New("username must be at most 50 characters")
	// ErrUsernameInvalidChars is returned when username contains invalid characters.
	ErrUsernameInvalidChars = errors.New("username can only contain letters, numbers, and underscores")

	// ErrProjectNameEmpty is returned when project name is empty.
	ErrProjectNameEmpty = errors.New("project name is required")
	// ErrProjectNameTooLong is returned when project name exceeds 100 characters.
	ErrProjectNameTooLong = errors.New("project name must be at most 100 characters")

	// ErrSecretKeyEmpty is returned when secret key is empty.
	ErrSecretKeyEmpty = errors.New("secret key is required")
	// ErrSecretKeyTooLong is returned when secret key exceeds 255 characters.
	ErrSecretKeyTooLong = errors.New("secret key must be at most 255 characters")
	// ErrSecretKeyInvalidFormat is returned when secret key is not a valid env var name.
	ErrSecretKeyInvalidFormat = errors.New("secret key must be a valid environment variable name (start with letter or underscore, contain only letters, numbers, and underscores)")

	// ErrDescriptionTooLong is returned when description exceeds 500 characters.
	ErrDescriptionTooLong = errors.New("description must be at most 500 characters")
)

var (
	usernameRegex  = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	secretKeyRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// Username validates a username.
// Rules: 3-50 characters, alphanumeric and underscores only.
func Username(username string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return ErrUsernameTooShort
	}
	if len(username) > 50 {
		return ErrUsernameTooLong
	}
	if !usernameRegex.MatchString(username) {
		return ErrUsernameInvalidChars
	}
	return nil
}

// ProjectName validates a project name.
// Rules: 1-100 characters.
func ProjectName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrProjectNameEmpty
	}
	if len(name) > 100 {
		return ErrProjectNameTooLong
	}
	return nil
}

// ProjectDescription validates a project description.
// Rules: 0-500 characters.
func ProjectDescription(desc string) error {
	if len(desc) > 500 {
		return ErrDescriptionTooLong
	}
	return nil
}

// SecretKey validates a secret key.
// Rules: 1-255 characters, valid environment variable name format.
func SecretKey(key string) error {
	if key == "" {
		return ErrSecretKeyEmpty
	}
	if len(key) > 255 {
		return ErrSecretKeyTooLong
	}
	if !secretKeyRegex.MatchString(key) {
		return ErrSecretKeyInvalidFormat
	}
	return nil
}
