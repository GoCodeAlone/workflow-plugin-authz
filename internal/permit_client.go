package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// permitClient is an HTTP client for the Permit.io REST API and PDP API.
type permitClient struct {
	httpClient  *http.Client
	apiURL      string // e.g. "https://api.permit.io"
	pdpURL      string // e.g. "https://cloudpdp.api.permit.io"
	apiKey      string
	project     string
	environment string
}

// doAPI performs an authenticated request to the Permit.io management API.
// Returns the parsed JSON response body as map[string]any, or an error.
func (c *permitClient) doAPI(ctx context.Context, method, path string, body any) (map[string]any, error) {
	return c.doRequest(ctx, c.apiURL, method, path, body)
}

// doPDP performs an authenticated request to the Permit.io PDP (policy decision point) API.
func (c *permitClient) doPDP(ctx context.Context, method, path string, body any) (map[string]any, error) {
	return c.doRequest(ctx, c.pdpURL, method, path, body)
}

// doAPIList performs an authenticated request that returns an array response.
func (c *permitClient) doAPIList(ctx context.Context, method, path string, body any) ([]any, error) {
	return c.doRequestList(ctx, c.apiURL, method, path, body)
}

// doRequest is the shared HTTP request helper. baseURL + path form the full URL.
func (c *permitClient) doRequest(ctx context.Context, baseURL, method, path string, body any) (map[string]any, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("permit: marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	url := baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("permit: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("permit: %s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("permit: read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("permit: %s %s: status %d: %s", method, url, resp.StatusCode, string(respBytes))
	}

	if len(respBytes) == 0 {
		return map[string]any{}, nil
	}

	var result map[string]any
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("permit: decode response: %w", err)
	}
	return result, nil
}

// doRequestList performs a request that expects a JSON array response.
func (c *permitClient) doRequestList(ctx context.Context, baseURL, method, path string, body any) ([]any, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("permit: marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	url := baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("permit: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("permit: %s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("permit: read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("permit: %s %s: status %d: %s", method, url, resp.StatusCode, string(respBytes))
	}

	if len(respBytes) == 0 {
		return []any{}, nil
	}

	var result []any
	if err := json.Unmarshal(respBytes, &result); err != nil {
		// Try to decode as object with data field (paginated responses)
		var obj map[string]any
		if err2 := json.Unmarshal(respBytes, &obj); err2 == nil {
			if data, ok := obj["data"].([]any); ok {
				return data, nil
			}
			// Return as single-element list
			return []any{obj}, nil
		}
		return nil, fmt.Errorf("permit: decode list response: %w", err)
	}
	return result, nil
}

// resolvePermitValue resolves a config/current value by key, preferring current over config.
func resolvePermitValue(key string, current, config map[string]any) string {
	if v, ok := current[key].(string); ok && v != "" {
		return v
	}
	if v, ok := config[key].(string); ok && v != "" {
		return v
	}
	return ""
}

// permitFactsPath builds the base path for facts API calls.
func (c *permitClient) permitFactsPath(resource string) string {
	return fmt.Sprintf("/v2/facts/%s/%s/%s", c.project, c.environment, resource)
}

// permitSchemaPath builds the base path for schema API calls.
func (c *permitClient) permitSchemaPath(resource string) string {
	return fmt.Sprintf("/v2/schema/%s/%s/%s", c.project, c.environment, resource)
}
