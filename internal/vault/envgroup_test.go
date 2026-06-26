package vault

import (
	"sort"
	"testing"
)

// --- EnvGroup CRUD ---

func TestCreateEnvGroup(t *testing.T) {
	v := createTestVault(t)

	// Create projects first.
	if _, err := v.CreateProject("liftclub", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("liftclub-preview", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	envs := []EnvGroupEntry{
		{Name: "production", Project: "liftclub"},
		{Name: "preview", Project: "liftclub-preview"},
	}
	group, err := v.CreateEnvGroup("liftclub", "LIFT Club environments", envs, false)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if group.Name != "liftclub" {
		t.Errorf("name = %q, want %q", group.Name, "liftclub")
	}
	if len(group.Environments) != 2 {
		t.Fatalf("env count = %d, want 2", len(group.Environments))
	}
	if group.Environments[0].Name != "production" {
		t.Errorf("env[0].name = %q, want %q", group.Environments[0].Name, "production")
	}
	if group.Environments[1].Project != "liftclub-preview" {
		t.Errorf("env[1].project = %q, want %q", group.Environments[1].Project, "liftclub-preview")
	}
}

func TestCreateEnvGroup_DuplicateEnvName(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	envs := []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "production", Project: "p1"}, // duplicate
	}
	_, err := v.CreateEnvGroup("g1", "", envs, false)
	if err == nil {
		t.Fatal("expected error for duplicate env name")
	}
}

func TestCreateEnvGroup_NonexistentProject(t *testing.T) {
	v := createTestVault(t)

	envs := []EnvGroupEntry{
		{Name: "production", Project: "nonexistent"},
	}
	_, err := v.CreateEnvGroup("g1", "", envs, false)
	if err == nil {
		t.Fatal("expected error for nonexistent project")
	}
}

func TestCreateEnvGroup_ProjectInAnotherGroup(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	envs1 := []EnvGroupEntry{{Name: "production", Project: "p1"}}
	if _, err := v.CreateEnvGroup("g1", "", envs1, false); err != nil {
		t.Fatalf("create group g1: %v", err)
	}

	// Try to use p1 in another group without force.
	envs2 := []EnvGroupEntry{{Name: "production", Project: "p1"}}
	_, err := v.CreateEnvGroup("g2", "", envs2, false)
	if err == nil {
		t.Fatal("expected error for project already in another group")
	}

	// With force, should succeed.
	_, err = v.CreateEnvGroup("g2", "", envs2, true)
	if err != nil {
		t.Fatalf("create group with force: %v", err)
	}
}

func TestGetEnvGroup(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	envs := []EnvGroupEntry{{Name: "production", Project: "p1"}}
	if _, err := v.CreateEnvGroup("g1", "desc", envs, false); err != nil {
		t.Fatalf("create group: %v", err)
	}

	group, err := v.GetEnvGroup("g1")
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	if group.Name != "g1" {
		t.Errorf("name = %q", group.Name)
	}
	if group.Description != "desc" {
		t.Errorf("description = %q", group.Description)
	}
}

func TestGetEnvGroup_NotFound(t *testing.T) {
	v := createTestVault(t)
	_, err := v.GetEnvGroup("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent group")
	}
}

func TestListEnvGroups(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{{Name: "production", Project: "p1"}}, false)
	_, _ = v.CreateEnvGroup("g2", "", []EnvGroupEntry{{Name: "production", Project: "p2"}}, false)

	groups, err := v.ListEnvGroups()
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("group count = %d, want 2", len(groups))
	}
}

func TestListEnvGroups_Empty(t *testing.T) {
	v := createTestVault(t)
	groups, err := v.ListEnvGroups()
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("group count = %d, want 0", len(groups))
	}
}

func TestAddEnvGroupEnvironment(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{{Name: "production", Project: "p1"}}, false)

	group, err := v.AddEnvGroupEnvironment("g1", "preview", "p2")
	if err != nil {
		t.Fatalf("add env: %v", err)
	}
	if len(group.Environments) != 2 {
		t.Fatalf("env count = %d, want 2", len(group.Environments))
	}
}

func TestRemoveEnvGroupEnvironment(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	group, err := v.RemoveEnvGroupEnvironment("g1", "preview")
	if err != nil {
		t.Fatalf("remove env: %v", err)
	}
	if len(group.Environments) != 1 {
		t.Fatalf("env count = %d, want 1", len(group.Environments))
	}
	if group.Environments[0].Name != "production" {
		t.Errorf("remaining env = %q", group.Environments[0].Name)
	}
}

func TestDeleteEnvGroup(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{{Name: "production", Project: "p1"}}, false)

	if err := v.DeleteEnvGroup("g1"); err != nil {
		t.Fatalf("delete group: %v", err)
	}

	_, err := v.GetEnvGroup("g1")
	if err == nil {
		t.Fatal("expected error after delete")
	}

	// Project should still exist.
	_, err = v.GetProject("p1")
	if err != nil {
		t.Fatalf("project should still exist: %v", err)
	}
}

// --- DiffEnvironments ---

func TestDiffEnvironments_NoDrift(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	// Same keys in both.
	_ = v.SetSecret("p1", "KEY_A", "val1")
	_ = v.SetSecret("p1", "KEY_B", "val2")
	_ = v.SetSecret("p2", "KEY_A", "val1-diff")
	_ = v.SetSecret("p2", "KEY_B", "val2-diff")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	diff, err := v.DiffEnvironments("g1", false)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff.Status != "ok" {
		t.Errorf("status = %q, want %q", diff.Status, "ok")
	}
	if len(diff.Keys) != 2 {
		t.Fatalf("key count = %d, want 2", len(diff.Keys))
	}
}

func TestDiffEnvironments_DriftMissingKey(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p1", "KEY_A", "val1")
	_ = v.SetSecret("p1", "KEY_B", "val2") // missing in preview
	_ = v.SetSecret("p2", "KEY_A", "val1-diff")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	diff, err := v.DiffEnvironments("g1", false)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff.Status != "drift" {
		t.Errorf("status = %q, want %q", diff.Status, "drift")
	}

	// Find KEY_B which should be missing in preview.
	var keyB *EnvDiffKey
	for i := range diff.Keys {
		if diff.Keys[i].Key == "KEY_B" {
			keyB = &diff.Keys[i]
			break
		}
	}
	if keyB == nil {
		t.Fatal("KEY_B not found in diff")
	}
	if keyB.Environments[1].Present {
		t.Error("KEY_B should not be present in preview")
	}
	if keyB.Environments[1].Status != "missing" {
		t.Errorf("KEY_B preview status = %q, want %q", keyB.Environments[1].Status, "missing")
	}
}

func TestDiffEnvironments_WithValues(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p1", "KEY_A", "same-value")
	_ = v.SetSecret("p1", "KEY_B", "prod-only")
	_ = v.SetSecret("p2", "KEY_A", "same-value")
	_ = v.SetSecret("p2", "KEY_B", "preview-only")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	diff, err := v.DiffEnvironments("g1", true)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff.Status != "drift" {
		t.Errorf("status = %q, want %q", diff.Status, "drift")
	}

	// KEY_A should be "same", KEY_B should be "different".
	for _, k := range diff.Keys {
		if k.Key == "KEY_A" {
			if k.Environments[0].Status != "same" || k.Environments[1].Status != "same" {
				t.Errorf("KEY_A statuses = %q/%q, want same/same", k.Environments[0].Status, k.Environments[1].Status)
			}
		}
		if k.Key == "KEY_B" {
			if k.Environments[0].Status != "different" || k.Environments[1].Status != "different" {
				t.Errorf("KEY_B statuses = %q/%q, want different/different", k.Environments[0].Status, k.Environments[1].Status)
			}
		}
	}
}

// --- Promote ---

func TestPromote_SingleKey(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p1", "KEY_A", "prod-value")
	_ = v.SetSecret("p2", "KEY_A", "preview-value")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	result, err := v.Promote("g1", "preview", "production", []string{"KEY_A"}, false, false)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if len(result.Promoted) != 1 {
		t.Fatalf("promoted = %d, want 1", len(result.Promoted))
	}
	if result.Promoted[0].Key != "KEY_A" {
		t.Errorf("promoted key = %q, want %q", result.Promoted[0].Key, "KEY_A")
	}

	// Verify the value was promoted.
	val, err := v.GetSecret("p1", "KEY_A")
	if err != nil {
		t.Fatalf("get promoted: %v", err)
	}
	if val != "preview-value" {
		t.Errorf("promoted value = %q, want %q", val, "preview-value")
	}
}

func TestPromote_DryRun(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p1", "KEY_A", "prod-value")
	_ = v.SetSecret("p2", "KEY_A", "preview-value")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	result, err := v.Promote("g1", "preview", "production", []string{"KEY_A"}, false, true)
	if err != nil {
		t.Fatalf("promote dry-run: %v", err)
	}
	if len(result.Promoted) != 1 {
		t.Fatalf("promoted = %d, want 1", len(result.Promoted))
	}

	// Value should NOT have changed.
	val, err := v.GetSecret("p1", "KEY_A")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if val != "prod-value" {
		t.Errorf("value after dry-run = %q, want %q (should not change)", val, "prod-value")
	}
}

func TestPromote_All(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p2", "KEY_A", "val-a")
	_ = v.SetSecret("p2", "KEY_B", "val-b")
	_ = v.SetSecret("p1", "KEY_A", "old-a")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	result, err := v.Promote("g1", "preview", "production", nil, true, false)
	if err != nil {
		t.Fatalf("promote all: %v", err)
	}
	if len(result.Promoted) != 2 {
		t.Fatalf("promoted = %d, want 2", len(result.Promoted))
	}

	// Verify both values.
	valA, _ := v.GetSecret("p1", "KEY_A")
	if valA != "val-a" {
		t.Errorf("KEY_A = %q, want %q", valA, "val-a")
	}
	valB, _ := v.GetSecret("p1", "KEY_B")
	if valB != "val-b" {
		t.Errorf("KEY_B = %q, want %q", valB, "val-b")
	}
}

func TestPromote_KeyNotFoundInSource(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	result, err := v.Promote("g1", "preview", "production", []string{"NONEXISTENT"}, false, false)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if len(result.Promoted) != 0 {
		t.Fatalf("promoted = %d, want 0", len(result.Promoted))
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("skipped = %d, want 1", len(result.Skipped))
	}
}

func TestPromote_SameProject(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p1"}, // same project!
	}, false)

	_, err := v.Promote("g1", "preview", "production", []string{"KEY_A"}, false, false)
	if err == nil {
		t.Fatal("expected error for same project")
	}
}

// --- Inheritance ---

func TestSetInheritance(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)

	group, err := v.SetInheritance("g1", "preview", "production")
	if err != nil {
		t.Fatalf("set inheritance: %v", err)
	}
	if group.Inheritance["preview"].From != "production" {
		t.Errorf("inheritance from = %q", group.Inheritance["preview"].From)
	}
}

func TestResolveKey_InheritedFromBase(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	// KEY_A only in production.
	_ = v.SetSecret("p1", "KEY_A", "prod-value")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)
	_, _ = v.SetInheritance("g1", "preview", "production")

	// KEY_A not in preview, should inherit from production.
	val, source, err := v.ResolveKey("g1", "preview", "KEY_A")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if val != "prod-value" {
		t.Errorf("value = %q, want %q", val, "prod-value")
	}
	if source != "production" {
		t.Errorf("source = %q, want %q", source, "production")
	}
}

func TestResolveKey_LocalValue(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p1", "KEY_A", "prod-value")
	_ = v.SetSecret("p2", "KEY_A", "preview-value") // local overrides

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)
	_, _ = v.SetInheritance("g1", "preview", "production")

	val, source, err := v.ResolveKey("g1", "preview", "KEY_A")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if val != "preview-value" {
		t.Errorf("value = %q, want %q", val, "preview-value")
	}
	if source != "preview" {
		t.Errorf("source = %q, want %q", source, "preview")
	}
}

func TestResolveKey_NotFound(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)
	_, _ = v.SetInheritance("g1", "preview", "production")

	_, _, err := v.ResolveKey("g1", "preview", "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestPinKey(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p1", "KEY_A", "prod-value")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)
	_, _ = v.SetInheritance("g1", "preview", "production")

	// Pin KEY_A into preview.
	if err := v.PinKey("g1", "preview", "KEY_A"); err != nil {
		t.Fatalf("pin: %v", err)
	}

	// KEY_A should now be local in preview.
	val, err := v.GetSecret("p2", "KEY_A")
	if err != nil {
		t.Fatalf("get pinned: %v", err)
	}
	if val != "prod-value" {
		t.Errorf("pinned value = %q, want %q", val, "prod-value")
	}
}

func TestUnpinKey(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p1", "KEY_A", "prod-value")
	_ = v.SetSecret("p2", "KEY_A", "pinned-value")

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)
	_, _ = v.SetInheritance("g1", "preview", "production")

	// Unpin KEY_A from preview.
	if err := v.UnpinKey("g1", "preview", "KEY_A"); err != nil {
		t.Fatalf("unpin: %v", err)
	}

	// KEY_A should no longer be in preview.
	_, err := v.GetSecret("p2", "KEY_A")
	if err == nil {
		t.Fatal("expected error after unpin (key should be deleted)")
	}
}

func TestListInherited(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("p1", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("p2", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_ = v.SetSecret("p1", "KEY_A", "prod-a")
	_ = v.SetSecret("p1", "KEY_B", "prod-b")
	_ = v.SetSecret("p2", "KEY_B", "preview-b") // pinned

	_, _ = v.CreateEnvGroup("g1", "", []EnvGroupEntry{
		{Name: "production", Project: "p1"},
		{Name: "preview", Project: "p2"},
	}, false)
	_, _ = v.SetInheritance("g1", "preview", "production")

	keys, err := v.ListInherited("g1", "preview")
	if err != nil {
		t.Fatalf("list inherited: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("key count = %d, want 2", len(keys))
	}

	// Sort for deterministic comparison.
	sort.Slice(keys, func(i, j int) bool { return keys[i].Key < keys[j].Key })

	if keys[0].Key != "KEY_A" {
		t.Errorf("keys[0] = %q", keys[0].Key)
	}
	if keys[0].Source != "inherited:production" {
		t.Errorf("keys[0].source = %q, want %q", keys[0].Source, "inherited:production")
	}
	if keys[0].Pinned {
		t.Error("KEY_A should not be pinned")
	}

	if keys[1].Key != "KEY_B" {
		t.Errorf("keys[1] = %q", keys[1].Key)
	}
	if keys[1].Source != "local" {
		t.Errorf("keys[1].source = %q, want %q", keys[1].Source, "local")
	}
	if !keys[1].Pinned {
		t.Error("KEY_B should be pinned")
	}
}

// --- Integration: create → drift → promote → re-diff ---

func TestEnvGroupIntegration_CreateDriftPromoteReDiff(t *testing.T) {
	v := createTestVault(t)
	if _, err := v.CreateProject("liftclub", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := v.CreateProject("liftclub-preview", ""); err != nil {
		t.Fatalf("create project: %v", err)
	}

	// Set up secrets — production has more keys (drift).
	_ = v.SetSecret("liftclub", "DATABASE_URL", "prod-db")
	_ = v.SetSecret("liftclub", "STRIPE_SECRET_KEY", "sk-prod")
	_ = v.SetSecret("liftclub", "STRIPE_WEBHOOK_SECRET", "wh-prod")
	_ = v.SetSecret("liftclub-preview", "DATABASE_URL", "preview-db")
	_ = v.SetSecret("liftclub-preview", "STRIPE_SECRET_KEY", "sk-preview")
	// STRIPE_WEBHOOK_SECRET missing in preview → drift

	_, _ = v.CreateEnvGroup("liftclub", "", []EnvGroupEntry{
		{Name: "production", Project: "liftclub"},
		{Name: "preview", Project: "liftclub-preview"},
	}, false)

	// 1. Diff should detect drift.
	diff, err := v.DiffEnvironments("liftclub", false)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff.Status != "drift" {
		t.Fatalf("initial diff status = %q, want %q", diff.Status, "drift")
	}

	// 2. Promote the missing key from production to preview.
	result, err := v.Promote("liftclub", "production", "preview", []string{"STRIPE_WEBHOOK_SECRET"}, false, false)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if len(result.Promoted) != 1 {
		t.Fatalf("promoted = %d, want 1", len(result.Promoted))
	}

	// 3. Re-diff should be clean.
	diff, err = v.DiffEnvironments("liftclub", false)
	if err != nil {
		t.Fatalf("re-diff: %v", err)
	}
	if diff.Status != "ok" {
		t.Errorf("re-diff status = %q, want %q", diff.Status, "ok")
	}

	// 4. Verify the promoted value.
	val, err := v.GetSecret("liftclub-preview", "STRIPE_WEBHOOK_SECRET")
	if err != nil {
		t.Fatalf("get promoted: %v", err)
	}
	if val != "wh-prod" {
		t.Errorf("promoted value = %q, want %q", val, "wh-prod")
	}
}
