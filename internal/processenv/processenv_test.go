package processenv

import (
	"reflect"
	"testing"
)

func TestSanitizeRemovesControlCredentials(t *testing.T) {
	input := []string{
		"PATH=/usr/bin",
		"TVAULT_PASSPHRASE=master",
		"TVAULT_IDENTITY_KEY=private",
		"TVAULT_AGENT_TOKEN=capability",
		"TVAULT_PASSPHRASE=duplicate",
		"APP_TOKEN=keep-me",
	}
	want := []string{"PATH=/usr/bin", "APP_TOKEN=keep-me"}
	if got := Sanitize(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("Sanitize() = %#v, want %#v", got, want)
	}
}
