package studio

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// newEnvGroupVault creates a scratch vault with two projects linked in an
// env group, with inheritance configured and some secrets. The current
// project is set to the preview env.
func newEnvGroupVault(t *testing.T) *vault.Vault {
	t.Helper()
	v := newScratchVault(t)

	// Create a preview project and seed it with a partial key set.
	if _, err := v.CreateProject("webapp-preview", ""); err != nil {
		t.Fatalf("create webapp-preview: %v", err)
	}
	if err := v.SetSecret("webapp-preview", "DB_URL", "postgres://preview"); err != nil {
		t.Fatalf("set DB_URL: %v", err)
	}
	// STRIPE_KEY is NOT set in preview — it will be inherited from production.

	// Link both into a group.
	_, err := v.CreateEnvGroup("webapp", "WebApp envs", []vault.EnvGroupEntry{
		{Name: "production", Project: "webapp"},
		{Name: "preview", Project: "webapp-preview"},
	}, false)
	if err != nil {
		t.Fatalf("create env group: %v", err)
	}

	// Configure inheritance: preview inherits from production.
	if _, err := v.SetInheritance("webapp", "preview", "production"); err != nil {
		t.Fatalf("set inheritance: %v", err)
	}

	// Switch to preview so the studio shows the child env.
	if err := v.SetCurrentProject("webapp-preview"); err != nil {
		t.Fatalf("set current: %v", err)
	}
	return v
}

// newEnvGroupReadyModel builds a ready model against an env-group vault,
// with all the async loads (status, projects, secrets, audit, env groups,
// inherited) simulated.
func newEnvGroupReadyModel(t *testing.T, v *vault.Vault, opts Options) Model {
	t.Helper()
	m := New(v, opts)
	m.anim = false
	m = update(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = update(t, m, statusLoadedMsg(loadStatus(v)))
	projects, err := loadProjects(v)
	if err != nil {
		t.Fatalf("load projects: %v", err)
	}
	m = update(t, m, projectsLoadedMsg{projects: projects})
	secs, err := loadSecrets(v, m.viewProject)
	if err != nil {
		t.Fatalf("load secrets: %v", err)
	}
	m = update(t, m, secretsLoadedMsg{project: m.viewProject, refs: secs})
	audit, err := loadAudit(v, 100)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	m = update(t, m, auditLoadedMsg{entries: audit})
	// Load env groups and inherited status.
	groups, err := loadEnvGroups(v)
	if err != nil {
		t.Fatalf("load env groups: %v", err)
	}
	m = update(t, m, envGroupsLoadedMsg{groups: groups})
	// The envGroupsLoadedMsg handler calls loadInheritedForCurrent, but the
	// returned cmd runs async; simulate it for the test.
	if m.status.envGroup != "" && m.status.envName != "" {
		inherited, err := loadInherited(v, m.status.envGroup, m.status.envName)
		if err == nil {
			m = update(t, m, inheritedLoadedMsg{
				group:     m.status.envGroup,
				env:       m.status.envName,
				inherited: inherited,
			})
		}
	}
	return m
}

// --- projects pane annotations ---

func TestProjectsPaneShowsEnvName(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	m = update(t, m, keyPress("2")) // focus projects pane
	out := m.View().Content
	// The projects pane should show the env name annotation.
	if !strings.Contains(out, "production") {
		t.Errorf("projects pane should show env name 'production':\n%s", stripANSIForTest(out))
	}
}

func TestProjectsPaneShowsEnvNameForPreview(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	m = update(t, m, keyPress("2"))
	out := m.View().Content
	if !strings.Contains(out, "preview") {
		t.Errorf("projects pane should show env name 'preview':\n%s", stripANSIForTest(out))
	}
}

// --- cycle env (g key) ---

func TestCycleEnvSwitchesToNextEnv(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	// Current view project should be webapp-preview (preview env).
	if m.viewProject != "webapp-preview" {
		t.Fatalf("setup: viewProject = %q, want webapp-preview", m.viewProject)
	}
	// Press g to cycle to the next env (production → webapp).
	m = update(t, m, keyPress("g"))
	if m.viewProject != "webapp" {
		t.Errorf("after g: viewProject = %q, want webapp", m.viewProject)
	}
	if !strings.Contains(m.statusLine, "production") {
		t.Errorf("statusLine should mention production env: %q", m.statusLine)
	}
}

func TestCycleEnvWrapsAround(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	// Cycle once: preview → production.
	m = update(t, m, keyPress("g"))
	if m.viewProject != "webapp" {
		t.Fatalf("after first g: viewProject = %q, want webapp", m.viewProject)
	}
	// Simulate the secrets load for the new project.
	m = update(t, m, secretsLoadedMsg{project: "webapp", refs: mustLoadSecrets(t, v, "webapp")})
	// Cycle again: production → preview (wraps around).
	m = update(t, m, keyPress("g"))
	if m.viewProject != "webapp-preview" {
		t.Errorf("after second g: viewProject = %q, want webapp-preview", m.viewProject)
	}
}

func TestCycleEnvNoGroup(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("g"))
	if !strings.Contains(m.statusLine, "not in an env group") {
		t.Errorf("g on a non-group project should warn: %q", m.statusLine)
	}
}

// --- inherited key indicator ---

func TestInheritedKeyIndicatorShowsArrow(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	m = update(t, m, keyPress("3")) // focus secrets pane
	out := m.View().Content
	// The preview project has DB_URL locally and inherits STRIPE_KEY.
	// STRIPE_KEY should have the ← inherited marker.
	// We check the plain text rendering for the arrow.
	plain := stripANSIForTest(out)
	if !strings.Contains(plain, "←") {
		t.Errorf("secrets pane should show inherited marker ←:\n%s", plain)
	}
}

func TestInheritedKeyIndicatorNoGroup(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	// No env group → no inherited map → no markers in the secrets pane.
	out := m.View().Content
	plain := stripANSIForTest(out)
	if strings.Contains(plain, "←") {
		t.Errorf("secrets pane should NOT show inherited marker without env group:\n%s", plain)
	}
}

// --- drift overlay (D key) ---

func TestDriftOverlayLoadsAndShows(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	// Press D to open the drift overlay.
	m = update(t, m, keyPress("D"))
	// The D key triggers a diffCmd which returns a diffLoadedMsg;
	// simulate the async result.
	diff, err := loadDiff(v, "webapp")
	if err != nil {
		t.Fatalf("loadDiff: %v", err)
	}
	m = update(t, m, diffLoadedMsg{diff: diff})
	if m.mode != modeDrift {
		t.Fatalf("mode = %v, want modeDrift", m.mode)
	}
	out := m.View().Content
	plain := stripANSIForTest(out)
	if !strings.Contains(plain, "Env drift") {
		t.Errorf("drift overlay should show title:\n%s", plain)
	}
	if !strings.Contains(plain, "webapp") {
		t.Errorf("drift overlay should show group name:\n%s", plain)
	}
}

func TestDriftOverlayClosesOnEsc(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	m = update(t, m, keyPress("D"))
	diff, _ := loadDiff(v, "webapp")
	m = update(t, m, diffLoadedMsg{diff: diff})
	if m.mode != modeDrift {
		t.Fatalf("setup: expected modeDrift")
	}
	m = update(t, m, keyPress("esc"))
	if m.mode != modeNormal {
		t.Errorf("esc should close drift overlay: mode = %v", m.mode)
	}
}

func TestDriftOverlayNoGroup(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	m = update(t, m, keyPress("D"))
	if !strings.Contains(m.statusLine, "not in an env group") {
		t.Errorf("D on a non-group project should warn: %q", m.statusLine)
	}
}

// --- env groups overlay (G key) ---

func TestGroupsOverlayShowsAllGroups(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	m = update(t, m, keyPress("G"))
	if m.mode != modeGroups {
		t.Fatalf("mode = %v, want modeGroups", m.mode)
	}
	out := m.View().Content
	plain := stripANSIForTest(out)
	if !strings.Contains(plain, "Environment groups") {
		t.Errorf("groups overlay should show title:\n%s", plain)
	}
	if !strings.Contains(plain, "webapp") {
		t.Errorf("groups overlay should show group name:\n%s", plain)
	}
	if !strings.Contains(plain, "production") {
		t.Errorf("groups overlay should show env name:\n%s", plain)
	}
	if !strings.Contains(plain, "inherits") {
		t.Errorf("groups overlay should show inheritance:\n%s", plain)
	}
}

func TestGroupsOverlayClosesOnEsc(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})
	m = update(t, m, keyPress("G"))
	if m.mode != modeGroups {
		t.Fatalf("setup: expected modeGroups")
	}
	m = update(t, m, keyPress("esc"))
	if m.mode != modeNormal {
		t.Errorf("esc should close groups overlay: mode = %v", m.mode)
	}
}

func TestGroupsOverlayEmpty(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{})
	// Load env groups (empty) so the model has the data.
	groups, _ := loadEnvGroups(v)
	m = update(t, m, envGroupsLoadedMsg{groups: groups})
	m = update(t, m, keyPress("G"))
	if m.mode != modeGroups {
		t.Fatalf("mode = %v, want modeGroups", m.mode)
	}
	out := m.View().Content
	plain := stripANSIForTest(out)
	if !strings.Contains(plain, "no env groups") {
		t.Errorf("groups overlay should show empty state:\n%s", plain)
	}
}

// --- grid invariant for new overlays ---

func TestGridExactDriftOverlay(t *testing.T) {
	v := newEnvGroupVault(t)
	for _, sz := range [][2]int{{120, 40}, {100, 30}, {90, 24}, {160, 50}, {40, 10}, {50, 12}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(loadStatus(v)))
		groups, _ := loadEnvGroups(v)
		m = update(t, m, envGroupsLoadedMsg{groups: groups})
		m = update(t, m, keyPress("D"))
		diff, _ := loadDiff(v, "webapp")
		m = update(t, m, diffLoadedMsg{diff: diff})
		if m.mode != modeDrift {
			t.Fatalf("expected modeDrift at %dx%d", sz[0], sz[1])
		}
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

func TestGridExactGroupsOverlay(t *testing.T) {
	v := newEnvGroupVault(t)
	for _, sz := range [][2]int{{120, 40}, {100, 30}, {90, 24}, {160, 50}, {40, 10}, {50, 12}} {
		m := New(v, Options{})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(loadStatus(v)))
		groups, _ := loadEnvGroups(v)
		m = update(t, m, envGroupsLoadedMsg{groups: groups})
		m = update(t, m, keyPress("G"))
		if m.mode != modeGroups {
			t.Fatalf("expected modeGroups at %dx%d", sz[0], sz[1])
		}
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}

// --- buildProjGroupIndex ---

func TestBuildProjGroupIndex(t *testing.T) {
	v := newEnvGroupVault(t)
	m := newEnvGroupReadyModel(t, v, Options{})

	// webapp → production
	em, ok := m.envMembershipFor("webapp")
	if !ok {
		t.Fatal("webapp should be in the index")
	}
	if em.group != "webapp" || em.env != "production" {
		t.Errorf("webapp membership = %+v, want {webapp, production}", em)
	}

	// webapp-preview → preview
	em, ok = m.envMembershipFor("webapp-preview")
	if !ok {
		t.Fatal("webapp-preview should be in the index")
	}
	if em.group != "webapp" || em.env != "preview" {
		t.Errorf("webapp-preview membership = %+v, want {webapp, preview}", em)
	}

	// api → not in any group
	_, ok = m.envMembershipFor("api")
	if ok {
		t.Error("api should not be in any group")
	}
}

// mustLoadSecrets is a test helper that fails on error.
func mustLoadSecrets(t *testing.T, v *vault.Vault, project string) []vault.SecretRef {
	t.Helper()
	refs, err := loadSecrets(v, project)
	if err != nil {
		t.Fatalf("loadSecrets %s: %v", project, err)
	}
	return refs
}
