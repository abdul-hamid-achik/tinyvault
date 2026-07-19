//go:build unix

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Client talks to a running agent, one request per connection.
type Client struct {
	dir     string
	timeout time.Duration
	token   string
}

// WithToken sets the capability token (TVAULT_AGENT_TOKEN) sent with each
// request, for agents started with --require-token.
func (c *Client) WithToken(token string) *Client {
	c.token = token
	return c
}

func dialUnix(path string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(context.Background(), "unix", path)
}

// Dial returns a client if an agent socket is reachable under dir, else an
// error (the caller falls back to direct vault access).
func Dial(dir string, timeout time.Duration) (*Client, error) {
	conn, err := dialUnix(socketPath(dir), timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.Close()
	return &Client{dir: dir, timeout: timeout}, nil
}

func (c *Client) roundTrip(req Request) (Response, error) {
	conn, err := dialUnix(socketPath(c.dir), c.timeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if derr := conn.SetDeadline(time.Now().Add(c.timeout)); derr != nil {
		return Response{}, derr
	}

	req.V = ProtocolVersion
	req.Token = c.token
	data, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return Response{}, err
	}

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), MaxResponseBytes)
	if !sc.Scan() {
		if serr := sc.Err(); serr != nil {
			return Response{}, serr
		}
		return Response{}, fmt.Errorf("no response from agent")
	}
	var resp Response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

// Get fetches one secret value via the agent.
func (c *Client) Get(project, key string) (string, error) {
	resp, err := c.roundTrip(Request{Op: OpGet, Project: project, Key: key})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", errors.New(resp.Error)
	}
	return resp.Value, nil
}

// GetAll fetches all of a project's secrets via the agent, returning the
// resolved project name (useful when project was empty = "current").
func (c *Client) GetAll(project string) (map[string]string, string, error) {
	resp, err := c.roundTrip(Request{Op: OpGetAll, Project: project})
	if err != nil {
		return nil, "", err
	}
	if !resp.OK {
		return nil, "", errors.New(resp.Error)
	}
	return resp.Secrets, resp.Project, nil
}

// Status queries the running agent.
func (c *Client) Status() (*StatusInfo, error) {
	return c.StatusForProject("")
}

// StatusForProject queries the running agent and verifies that this client is
// authorized to read project when the agent requires scoped tokens. It returns
// metadata only and never opens the vault or reads a secret.
func (c *Client) StatusForProject(project string) (*StatusInfo, error) {
	resp, err := c.roundTrip(Request{Op: OpStatus, Project: project})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	return resp.Status, nil
}

// Stop asks the running agent to shut down (and zero its KEK).
func (c *Client) Stop() error {
	resp, err := c.roundTrip(Request{Op: OpStop})
	if err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	return nil
}
