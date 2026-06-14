//go:build !unix

package agent

import "time"

// On non-unix platforms the agent is unsupported: Start and the client both
// fail closed with ErrUnsupportedPlatform, and CLI routing falls back to
// direct vault access.

// Supported reports whether the agent runs on this platform (false off unix).
func Supported() bool { return false }

// Start is unsupported off unix.
func Start(opts Options) error {
	_ = opts
	return ErrUnsupportedPlatform
}

// Client is a no-op on non-unix platforms.
type Client struct{}

// Dial always fails on non-unix platforms.
func Dial(_ string, _ time.Duration) (*Client, error) { return nil, ErrUnsupportedPlatform }

func (c *Client) Get(_, _ string) (string, error) { return "", ErrUnsupportedPlatform }
func (c *Client) GetAll(_ string) (map[string]string, string, error) {
	return nil, "", ErrUnsupportedPlatform
}
func (c *Client) Status() (*StatusInfo, error) { return nil, ErrUnsupportedPlatform }
func (c *Client) Stop() error                  { return ErrUnsupportedPlatform }
