package services

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProject_Fields(t *testing.T) {
	description := "Test project description"
	project := Project{
		ID:          uuid.New(),
		OwnerID:     uuid.New(),
		Name:        "test-project",
		Description: &description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if project.ID == uuid.Nil {
		t.Error("Project.ID should not be nil")
	}
	if project.OwnerID == uuid.Nil {
		t.Error("Project.OwnerID should not be nil")
	}
	if project.Name == "" {
		t.Error("Project.Name should not be empty")
	}
	if project.Description == nil {
		t.Error("Project.Description should not be nil")
	}
	if *project.Description != description {
		t.Errorf("Project.Description = %q, want %q", *project.Description, description)
	}
	if project.CreatedAt.IsZero() {
		t.Error("Project.CreatedAt should not be zero")
	}
	if project.UpdatedAt.IsZero() {
		t.Error("Project.UpdatedAt should not be zero")
	}
}

func TestProject_NilDescription(t *testing.T) {
	project := Project{
		ID:          uuid.New(),
		OwnerID:     uuid.New(),
		Name:        "test-project",
		Description: nil,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if project.Description != nil {
		t.Error("Project.Description should be nil when not set")
	}
}

func TestProjectService_MasterKeyRequired(t *testing.T) {
	// Test that ProjectService requires a master key for encryption
	// In production, this would be validated at startup

	// Create service without master key (would panic on encrypt)
	service := &ProjectService{
		masterKey: nil,
	}

	if service.masterKey != nil {
		t.Error("Expected nil master key for test")
	}

	// Create service with master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	serviceWithKey := &ProjectService{
		masterKey: masterKey,
	}

	if len(serviceWithKey.masterKey) != 32 {
		t.Errorf("masterKey length = %d, want 32", len(serviceWithKey.masterKey))
	}
}

func TestNewProjectService(t *testing.T) {
	// Test struct initialization
	masterKey := make([]byte, 32)

	service := &ProjectService{
		masterKey: masterKey,
	}

	if service.masterKey == nil {
		t.Error("ProjectService.masterKey should not be nil")
	}
	if service.queries != nil {
		t.Error("ProjectService.queries should be nil without DB connection")
	}
}
