package upstream

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	BaseURL           = "https://cli-chat-proxy.grok.com/v1"
	ClientVersion     = "1.0.40"
	ClientIdentifier  = "grok-shell"
	TokenAuth         = "xai-grok-cli"
	UserAgent         = "grok-shell/1.0.40"
	OAuthClientID     = "b1a00492-073a-47ea-816f-4c329264a828"
	OAuthScope        = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write"
	DeviceURL         = "https://auth.x.ai/oauth2/device/code"
	TokenURL          = "https://auth.x.ai/oauth2/token"
)

type Client struct {
	http    *http.Client
	agentID string
}

func NewClient() *Client {
	return &Client{
		http: &http.Client{
			Timeout: 120 * time.Second,
		},
		agentID: uuid.NewString(),
	}
}

type Credential struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Email        string
}

func (c *Client) applyHeaders(req *http.Request, cred Credential, model string, streaming bool) {
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("X-XAI-Token-Auth", TokenAuth)
	req.Header.Set("x-grok-client-version", ClientVersion)
	req.Header.Set("x-grok-client-identifier", ClientIdentifier)
	req.Header.Set("x-grok-client-mode", "headless")
	req.Header.Set("x-grok-agent-id", c.agentID)

	sessionID := uuid.NewString()
	req.Header.Set("x-grok-session-id", sessionID)
	req.Header.Set("x-grok-conv-id", sessionID)
	req.Header.Set("x-grok-conv-group-id", uuid.NewSHA1(uuid.NameSpaceOID, []byte("xai:grok-build:conversation-group:"+sessionID)).String())
	req.Header.Set("x-grok-req-id", uuid.NewString())

	if cred.UserID != "" {
		req.Header.Set("x-grok-user-id", cred.UserID)
	}
	if cred.Email != "" {
		req.Header.Set("x-email", cred.Email)
	}

	if streaming {
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Accept-Encoding", "identity")
	} else {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Encoding", "gzip")
	}
	req.Header.Set("User-Agent", UserAgent)
	if model != "" {
		req.Header.Set("x-grok-model-override", model)
	}
}

type ChatResult struct {
	StatusCode int
	Body       io.ReadCloser
	Header     http.Header
}

func (c *Client) PostResponses(ctx context.Context, cred Credential, model string, body []byte, streaming bool) (*ChatResult, error) {
	url := BaseURL + "/responses"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyHeaders(req, cred, model, streaming)

	proxyURL := NextProxy()
	transport := BuildTransport(proxyURL, 30*time.Second)
	client := &http.Client{Transport: transport, Timeout: 120 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// decompress gzip if needed
	if resp.Header.Get("Content-Encoding") == "gzip" && !streaming {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body = gz
	}

	return &ChatResult{StatusCode: resp.StatusCode, Body: resp.Body, Header: resp.Header}, nil
}

func (c *Client) ListModels(ctx context.Context, cred Credential) ([]string, error) {
	url := BaseURL + "/models"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.applyHeaders(req, cred, "", false)

	proxyURL := NextProxy()
	transport := BuildTransport(proxyURL, 30*time.Second)
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var bodyReader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		bodyReader = gz
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upstream /models returned %d", resp.StatusCode)
	}

	var payload struct {
		Data []json.RawMessage `json:"data"`
	}
	body, err := io.ReadAll(io.LimitReader(bodyReader, 4<<20))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	var models []string
	seen := map[string]bool{}
	for _, raw := range payload.Data {
		var item struct {
			ID    string `json:"id"`
			Model string `json:"model"`
		}
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		id := item.ID
		if id == "" {
			id = item.Model
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		models = append(models, id)
	}
	return models, nil
}

// --- OAuth ---

type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

func (c *Client) StartDeviceAuth(ctx context.Context) (*DeviceAuth, error) {
	form := strings.NewReader(fmt.Sprintf("client_id=%s&scope=%s&referrer=grok-build", OAuthClientID, OAuthScope))
	req, err := http.NewRequestWithContext(ctx, "POST", DeviceURL, form)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var da DeviceAuth
	if err := json.NewDecoder(resp.Body).Decode(&da); err != nil {
		return nil, err
	}
	return &da, nil
}

type TokenPayload struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (c *Client) PollDeviceAuth(ctx context.Context, deviceCode string) (*TokenPayload, error) {
	form := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&device_code=%s", OAuthClientID, deviceCode)
	req, err := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(form))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload TokenPayload
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("token poll failed: %s", string(body))
	}
	if payload.AccessToken == "" {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("oauth error: %s", errResp.Error)
	}
	return &payload, nil
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenPayload, error) {
	form := fmt.Sprintf("grant_type=refresh_token&client_id=%s&refresh_token=%s", OAuthClientID, refreshToken)
	req, err := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(form))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload TokenPayload
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("refresh failed: %s", string(body))
	}
	if payload.AccessToken == "" {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("refresh error: %s", errResp.Error)
	}
	return &payload, nil
}
