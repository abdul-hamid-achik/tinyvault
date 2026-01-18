package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the TinyVault API client.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	verbose    bool
}

// NewClient creates a new API client.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		verbose: isVerbose(),
	}
}

// User represents a TinyVault user.
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Name     string `json:"name,omitempty"`
}

// Project represents a TinyVault project.
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// Secret represents a TinyVault secret (without value).
type Secret struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// SecretValue represents a secret with its value.
type SecretValue struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Version int    `json:"version"`
}

// APIResponse wraps API responses.
type APIResponse struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error *APIError       `json:"error,omitempty"`
}

// APIError represents an API error.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// request makes an authenticated request to the API.
func (c *Client) request(method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	var jsonBody []byte
	if body != nil {
		var err error
		jsonBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tvault-cli/1.0")

	// Verbose logging: show request details
	if c.verbose {
		fmt.Printf("[DEBUG] %s %s%s\n", method, c.baseURL, path)
		if len(jsonBody) > 0 {
			fmt.Printf("[DEBUG] Request body: %s\n", string(jsonBody))
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Verbose logging: show response details
	if c.verbose {
		fmt.Printf("[DEBUG] Response status: %d\n", resp.StatusCode)
		if len(respBody) > 0 && len(respBody) < 1000 {
			fmt.Printf("[DEBUG] Response body: %s\n", string(respBody))
		} else if len(respBody) >= 1000 {
			fmt.Printf("[DEBUG] Response body: %s... (truncated)\n", string(respBody[:500]))
		}
	}

	if resp.StatusCode >= 400 {
		var apiResp APIResponse
		if err := json.Unmarshal(respBody, &apiResp); err == nil && apiResp.Error != nil {
			return nil, apiResp.Error
		}
		return nil, fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	return respBody, nil
}

// GetCurrentUser returns the current authenticated user.
func (c *Client) GetCurrentUser() (*User, error) {
	body, err := c.request("GET", "/api/v1/me", nil)
	if err != nil {
		return nil, err
	}

	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var user User
	if err := json.Unmarshal(resp.Data, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user: %w", err)
	}

	return &user, nil
}

// ListProjects returns all projects.
func (c *Client) ListProjects() ([]Project, error) {
	body, err := c.request("GET", "/api/v1/projects", nil)
	if err != nil {
		return nil, err
	}

	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var projects []Project
	if err := json.Unmarshal(resp.Data, &projects); err != nil {
		return nil, fmt.Errorf("failed to parse projects: %w", err)
	}

	return projects, nil
}

// CreateProject creates a new project.
func (c *Client) CreateProject(name, description string) (*Project, error) {
	body, err := c.request("POST", "/api/v1/projects", map[string]string{
		"name":        name,
		"description": description,
	})
	if err != nil {
		return nil, err
	}

	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var project Project
	if err := json.Unmarshal(resp.Data, &project); err != nil {
		return nil, fmt.Errorf("failed to parse project: %w", err)
	}

	return &project, nil
}

// GetProject returns a project by ID.
func (c *Client) GetProject(id string) (*Project, error) {
	body, err := c.request("GET", "/api/v1/projects/"+id, nil)
	if err != nil {
		return nil, err
	}

	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var project Project
	if err := json.Unmarshal(resp.Data, &project); err != nil {
		return nil, fmt.Errorf("failed to parse project: %w", err)
	}

	return &project, nil
}

// DeleteProject deletes a project.
func (c *Client) DeleteProject(id string) error {
	_, err := c.request("DELETE", "/api/v1/projects/"+id, nil)
	return err
}

// ListSecrets returns all secrets for a project.
func (c *Client) ListSecrets(projectID string) ([]Secret, error) {
	body, err := c.request("GET", "/api/v1/projects/"+projectID+"/secrets", nil)
	if err != nil {
		return nil, err
	}

	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var secrets []Secret
	if err := json.Unmarshal(resp.Data, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse secrets: %w", err)
	}

	return secrets, nil
}

// GetSecret returns a secret value.
func (c *Client) GetSecret(projectID, key string) (*SecretValue, error) {
	body, err := c.request("GET", "/api/v1/projects/"+projectID+"/secrets/"+key, nil)
	if err != nil {
		return nil, err
	}

	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var secret SecretValue
	if err := json.Unmarshal(resp.Data, &secret); err != nil {
		return nil, fmt.Errorf("failed to parse secret: %w", err)
	}

	return &secret, nil
}

// SetSecret creates or updates a secret.
func (c *Client) SetSecret(projectID, key, value string) error {
	_, err := c.request("PUT", "/api/v1/projects/"+projectID+"/secrets/"+key, map[string]string{
		"value": value,
	})
	return err
}

// DeleteSecret deletes a secret.
func (c *Client) DeleteSecret(projectID, key string) error {
	_, err := c.request("DELETE", "/api/v1/projects/"+projectID+"/secrets/"+key, nil)
	return err
}

// ExportSecrets returns all secrets with values.
func (c *Client) ExportSecrets(projectID string) (map[string]string, error) {
	body, err := c.request("GET", "/api/v1/projects/"+projectID+"/secrets/export", nil)
	if err != nil {
		return nil, err
	}

	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(resp.Data, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse secrets: %w", err)
	}

	return secrets, nil
}
