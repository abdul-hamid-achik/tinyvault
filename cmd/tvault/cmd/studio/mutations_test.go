package studio

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestMutationsRequireRW(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{}) // read-only
	m = update(t, m, keyPress("3"))
	m = update(t, m, keyPress("n"))
	if m.mode != modeNormal {
		t.Error("n without --rw must not enter an edit mode")
	}
	m = update(t, m, keyPress("d"))
	if m.mode != modeNormal {
		t.Error("d without --rw must not enter confirm")
	}
}

func TestNewSecretFlow(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{ReadWrite: true})
	m = update(t, m, keyPress("3"))
	m = update(t, m, keyPress("n"))
	if m.mode != modeNewKey {
		t.Fatalf("n should enter modeNewKey, got %d", m.mode)
	}
	for _, r := range "NEWKEY" {
		m = update(t, m, keyPress(string(r)))
	}
	m = update(t, m, keyPress("enter"))
	if m.mode != modeSetValue {
		t.Fatalf("enter on key should advance to modeSetValue, got %d", m.mode)
	}
	for _, r := range "newval" {
		m = update(t, m, keyPress(string(r)))
	}
	next, cmd := m.Update(keyPress("enter"))
	if cmd == nil {
		t.Fatal("enter on value should issue setSecretCmd")
	}
	if _, ok := cmd().(mutationDoneMsg); !ok {
		t.Fatalf("expected mutationDoneMsg")
	}
	if val, err := v.GetSecret("webapp", "NEWKEY"); err != nil || val != "newval" {
		t.Errorf("new secret not stored: %q (%v)", val, err)
	}
	_ = next
}

func TestEditSecretFlow(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{ReadWrite: true})
	m = update(t, m, keyPress("3"))
	ref, _ := m.currentSecret()
	m = update(t, m, keyPress("e"))
	if m.mode != modeSetValue {
		t.Fatalf("e should enter modeSetValue, got %d", m.mode)
	}
	m.edit.SetValue("editedvalue")
	next, cmd := m.Update(keyPress("enter"))
	if cmd == nil {
		t.Fatal("enter should issue setSecretCmd")
	}
	cmd()
	if val, _ := v.GetSecret("webapp", ref.Key); val != "editedvalue" {
		t.Errorf("edit not applied: %q", val)
	}
	_ = next
}

func TestDeleteSecretFlow(t *testing.T) {
	v := newScratchVault(t)
	m := newReadyModel(t, v, Options{ReadWrite: true})
	m = update(t, m, keyPress("3"))
	ref, _ := m.currentSecret()
	m = update(t, m, keyPress("d"))
	if m.mode != modeConfirmDel {
		t.Fatalf("d should enter modeConfirmDel, got %d", m.mode)
	}
	// 'n' cancels.
	cancel := update(t, m, keyPress("n"))
	if cancel.mode != modeNormal {
		t.Error("n should cancel the delete confirm")
	}
	// 'y' deletes.
	next, cmd := m.Update(keyPress("y"))
	if cmd == nil {
		t.Fatal("y should issue deleteSecretCmd")
	}
	if _, ok := cmd().(mutationDoneMsg); !ok {
		t.Fatal("expected mutationDoneMsg")
	}
	if _, err := v.GetSecret("webapp", ref.Key); err == nil {
		t.Error("secret should be deleted")
	}
	_ = next
}

func TestMutationRequiresUnlock(t *testing.T) {
	v := newScratchVault(t)
	v.Lock()
	m := newReadyModel(t, v, Options{ReadWrite: true})
	m = update(t, m, keyPress("3"))
	m = update(t, m, keyPress("n"))
	if m.mode != modeNormal {
		t.Error("new must be blocked when locked")
	}
	if !strings.Contains(m.statusLine, "locked") {
		t.Errorf("want a 'locked' hint, got %q", m.statusLine)
	}
}

func TestEditOverlaysGridExact(t *testing.T) {
	v := newScratchVault(t)
	for _, sz := range [][2]int{{120, 40}, {90, 24}, {50, 14}} {
		m := New(v, Options{ReadWrite: true})
		m.anim = false
		m = update(t, m, tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		m = update(t, m, statusLoadedMsg(loadStatus(v)))
		secs, _ := loadSecrets(v, m.viewProject)
		m = update(t, m, secretsLoadedMsg{project: m.viewProject, refs: secs})
		m = update(t, m, keyPress("3"))
		// new-key overlay
		m = update(t, m, keyPress("n"))
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
		// delete-confirm overlay
		m = update(t, m, keyPress("esc"))
		m = update(t, m, keyPress("d"))
		assertExactGrid(t, m.View().Content, sz[0], sz[1])
	}
}
