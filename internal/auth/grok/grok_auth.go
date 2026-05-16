package grok

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	AuthURL     = "https://auth.x.ai/oauth2/authorize"
	TokenURL    = "https://auth.x.ai/oauth2/token"
	ClientID    = "b1a00492-073a-47ea-816f-4c329264a828"
	RedirectURI = "http://127.0.0.1:14567/callback"
	Scopes      = "openid profile email offline_access grok-cli:access api:access"
)

// GrokAuth handles the xAI OAuth2 authentication flow for Grok Build CLI.
type GrokAuth struct {
	httpClient *http.Client
}

// NewGrokAuth creates a new GrokAuth service instance.
func NewGrokAuth(cfg *config.Config) *GrokAuth {
	return NewGrokAuthWithProxyURL(cfg, "")
}

// NewGrokAuthWithProxyURL creates a new GrokAuth with an explicit proxy URL override.
func NewGrokAuthWithProxyURL(cfg *config.Config, proxyURL string) *GrokAuth {
	effectiveProxyURL := strings.TrimSpace(proxyURL)
	var sdkCfg config.SDKConfig
	if cfg != nil {
		sdkCfg = cfg.SDKConfig
		if effectiveProxyURL == "" {
			effectiveProxyURL = strings.TrimSpace(cfg.ProxyURL)
		}
	}
	sdkCfg.ProxyURL = effectiveProxyURL
	return &GrokAuth{
		httpClient: util.SetProxy(&sdkCfg, &http.Client{}),
	}
}

// GenerateAuthURL creates the OAuth authorization URL with PKCE challenge.
func (g *GrokAuth) GenerateAuthURL(state string, pkceCodes *PKCECodes) (string, error) {
	if pkceCodes == nil {
		return "", fmt.Errorf("PKCE codes are required")
	}
	params := url.Values{
		"client_id":             {ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {RedirectURI},
		"scope":                 {Scopes},
		"state":                 {state},
		"code_challenge":        {pkceCodes.CodeChallenge},
		"code_challenge_method": {"S256"},
	}
	return fmt.Sprintf("%s?%s", AuthURL, params.Encode()), nil
}

// ExchangeCodeForTokens exchanges an authorization code for access and refresh tokens.
func (g *GrokAuth) ExchangeCodeForTokens(ctx context.Context, code string, pkceCodes *PKCECodes) (*GrokAuthBundle, error) {
	if pkceCodes == nil {
		return nil, fmt.Errorf("PKCE codes are required for token exchange")
	}

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {RedirectURI},
		"client_id":     {ClientID},
		"code_verifier": {pkceCodes.CodeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.ExpiresIn == 0 {
		tokenResp.ExpiresIn = 3600
	}

	tokenData := GrokTokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
		Expire:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}

	return &GrokAuthBundle{
		TokenData:   tokenData,
		LastRefresh: time.Now().Format(time.RFC3339),
	}, nil
}

// RefreshTokens refreshes an access token using a refresh token.
func (g *GrokAuth) RefreshTokens(ctx context.Context, refreshToken string) (*GrokTokenData, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	data := url.Values{
		"client_id":     {ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	if tokenResp.ExpiresIn == 0 {
		tokenResp.ExpiresIn = 3600
	}

	return &GrokTokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
		Expire:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}, nil
}

// RefreshTokensWithRetry refreshes tokens with exponential backoff retries.
func (g *GrokAuth) RefreshTokensWithRetry(ctx context.Context, refreshToken string, maxRetries int) (*GrokTokenData, error) {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		tokenData, err := g.RefreshTokens(ctx, refreshToken)
		if err == nil {
			return tokenData, nil
		}
		lastErr = err
		log.Warnf("Grok token refresh attempt %d failed: %v", attempt+1, err)
	}
	return nil, fmt.Errorf("token refresh failed after %d attempts: %w", maxRetries, lastErr)
}

// CreateTokenStorage creates a GrokTokenStorage from a GrokAuthBundle.
func (g *GrokAuth) CreateTokenStorage(bundle *GrokAuthBundle) *GrokTokenStorage {
	return &GrokTokenStorage{
		AccessToken:  bundle.TokenData.AccessToken,
		RefreshToken: bundle.TokenData.RefreshToken,
		LastRefresh:  bundle.LastRefresh,
		Expire:       bundle.TokenData.Expire,
	}
}

// UpdateTokenStorage updates an existing GrokTokenStorage with new token data.
func (g *GrokAuth) UpdateTokenStorage(storage *GrokTokenStorage, tokenData *GrokTokenData) {
	storage.AccessToken = tokenData.AccessToken
	storage.RefreshToken = tokenData.RefreshToken
	storage.LastRefresh = time.Now().Format(time.RFC3339)
	storage.Expire = tokenData.Expire
}
