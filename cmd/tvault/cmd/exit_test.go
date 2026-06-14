package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

func TestExitCode(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, ExitOK},
		{errors.New("boom"), ExitError},
		{vault.ErrLocked, ExitLocked},
		{fmt.Errorf("failed to get secret: %w", vault.ErrSecretNotFound), ExitNotFound},
		{fmt.Errorf("wrap: %w", vault.ErrProjectNotFound), ExitNotFound},
		{vault.ErrNotInitialized, ExitNotInitialized},
		{vault.ErrWrongPassphrase, ExitWrongPassphrase},
	}
	for _, c := range cases {
		if got := ExitCode(c.err); got != c.want {
			t.Errorf("ExitCode(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}
