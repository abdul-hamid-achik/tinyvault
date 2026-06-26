package studio

import (
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func TestLoadStatus(t *testing.T) {
	v := newScratchVault(t)
	st := loadStatus(v)
	if !st.unlocked {
		t.Error("freshly created vault should report unlocked")
	}
	if st.currentProject != "webapp" {
		t.Errorf("currentProject = %q, want webapp", st.currentProject)
	}
	if st.projectCount != 3 { // default + webapp + api
		t.Errorf("projectCount = %d, want 3", st.projectCount)
	}
	if st.vaultID == "" {
		t.Error("vaultID should be set")
	}
	// No env group configured → envGroup should be empty.
	if st.envGroup != "" {
		t.Errorf("envGroup = %q, want empty", st.envGroup)
	}

	v.Lock()
	if loadStatus(v).unlocked {
		t.Error("locked vault should report locked")
	}
}

func TestLoadStatus_WithEnvGroup(t *testing.T) {
	v := newScratchVault(t)

	// Create a second project and link both into a group.
	if _, err := v.CreateProject("webapp-preview", ""); err != nil {
		t.Fatalf("create webapp-preview: %v", err)
	}
	_, err := v.CreateEnvGroup("webapp", "WebApp envs", []vault.EnvGroupEntry{
		{Name: "production", Project: "webapp"},
		{Name: "preview", Project: "webapp-preview"},
	}, false)
	if err != nil {
		t.Fatalf("create env group: %v", err)
	}

	// Set up inheritance.
	if _, err := v.SetInheritance("webapp", "preview", "production"); err != nil {
		t.Fatalf("set inheritance: %v", err)
	}

	// Switch to the preview project.
	if err := v.SetCurrentProject("webapp-preview"); err != nil {
		t.Fatalf("set current: %v", err)
	}

	st := loadStatus(v)
	if st.envGroup != "webapp" {
		t.Errorf("envGroup = %q, want webapp", st.envGroup)
	}
	if st.envName != "preview" {
		t.Errorf("envName = %q, want preview", st.envName)
	}
	if st.envInheritsFrom != "production" {
		t.Errorf("envInheritsFrom = %q, want production", st.envInheritsFrom)
	}
}

func TestLoadProjects(t *testing.T) {
	v := newScratchVault(t)
	projects, err := loadProjects(v)
	if err != nil {
		t.Fatalf("loadProjects: %v", err)
	}
	if len(projects) != 3 {
		t.Fatalf("got %d projects, want 3", len(projects))
	}
	counts := map[string]int{}
	for _, p := range projects {
		counts[p.Name] = p.SecretCount
	}
	if counts["webapp"] != 3 {
		t.Errorf("webapp secret count = %d, want 3", counts["webapp"])
	}
	if counts["api"] != 1 {
		t.Errorf("api secret count = %d, want 1", counts["api"])
	}
}

func TestLoadSecrets(t *testing.T) {
	v := newScratchVault(t)
	refs, err := loadSecrets(v, "webapp")
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("got %d secrets, want 3", len(refs))
	}
	for _, r := range refs {
		if r.Project != "webapp" {
			t.Errorf("ref project = %q, want webapp", r.Project)
		}
	}

	// Empty project name returns no refs, no error.
	none, err := loadSecrets(v, "")
	if err != nil || none != nil {
		t.Errorf("loadSecrets(\"\") = %v, %v; want nil, nil", none, err)
	}
}

func TestLoadSecretsMetadataOnlyWhenLocked(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	// Search reads metadata only, so it works even when locked.
	refs, err := loadSecrets(v, "webapp")
	if err != nil {
		t.Fatalf("loadSecrets while locked: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("locked metadata read got %d, want 3", len(refs))
	}
}

func TestLoadAudit(t *testing.T) {
	v := newScratchVault(t)
	entries, err := loadAudit(v, 100)
	if err != nil {
		t.Fatalf("loadAudit: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("got %d audit entries, want >= 2", len(entries))
	}
}

func TestRevealSecret(t *testing.T) {
	v := newScratchVault(t)
	val, err := revealSecret(v, "webapp", "STRIPE_KEY")
	if err != nil {
		t.Fatalf("revealSecret: %v", err)
	}
	if val != "sk_live_abc123" {
		t.Errorf("revealed value = %q, want sk_live_abc123", val)
	}

	v.Lock()
	if _, err := revealSecret(v, "webapp", "STRIPE_KEY"); err == nil {
		t.Error("revealSecret on a locked vault should error")
	}
}

func TestRevealCmdProducesError(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	msg := revealCmd(v, "webapp", "STRIPE_KEY", 0)()
	if _, ok := msg.(errMsg); !ok {
		t.Errorf("locked reveal cmd produced %T, want errMsg", msg)
	}
}

func TestRevealIsAudited(t *testing.T) {
	v := newScratchVault(t)
	if _, err := revealSecret(v, "webapp", "STRIPE_KEY"); err != nil {
		t.Fatalf("revealSecret: %v", err)
	}
	entries, err := loadAudit(v, 100)
	if err != nil {
		t.Fatalf("loadAudit: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "secret.read" && e.ResourceName == "STRIPE_KEY" {
			found = true
		}
	}
	if !found {
		t.Error("a TUI reveal should write a secret.read audit entry")
	}
}
