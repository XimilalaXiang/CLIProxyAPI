package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/grok"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var grokRefreshLead = 5 * time.Minute

// GrokAuthenticator implements the OAuth PKCE login flow for xAI Grok Build CLI.
type GrokAuthenticator struct{}

// NewGrokAuthenticator constructs a new Grok authenticator.
func NewGrokAuthenticator() Authenticator {
	return &GrokAuthenticator{}
}

// Provider returns the provider key.
func (GrokAuthenticator) Provider() string {
	return "grok"
}

// RefreshLead returns the duration before token expiry when refresh should occur.
func (GrokAuthenticator) RefreshLead() *time.Duration {
	return &grokRefreshLead
}

// Login initiates the Grok Build PKCE authentication flow.
func (a GrokAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	authSvc := grok.NewGrokAuth(cfg)

	pkceCodes, err := grok.GeneratePKCECodes()
	if err != nil {
		return nil, fmt.Errorf("grok: failed to generate PKCE codes: %w", err)
	}

	state, err := misc.GenerateRandomState()
	if err != nil {
		return nil, fmt.Errorf("grok: failed to generate state: %w", err)
	}

	authURL, err := authSvc.GenerateAuthURL(state, pkceCodes)
	if err != nil {
		return nil, fmt.Errorf("grok: failed to generate authorization URL: %w", err)
	}

	fmt.Printf("\nTo authenticate, please visit:\n%s\n\n", authURL)

	if !opts.NoBrowser {
		if browser.IsAvailable() {
			if errOpen := browser.OpenURL(authURL); errOpen != nil {
				log.Warnf("Failed to open browser automatically: %v", errOpen)
			} else {
				fmt.Println("Browser opened automatically.")
			}
		}
	}

	fmt.Println("After authorizing, paste the authorization code here.")

	if opts.Prompt == nil {
		return nil, fmt.Errorf("grok: prompt function is required for interactive login")
	}

	code, err := opts.Prompt("Authorization code: ")
	if err != nil {
		return nil, fmt.Errorf("grok: failed to read authorization code: %w", err)
	}

	bundle, err := authSvc.ExchangeCodeForTokens(ctx, code, pkceCodes)
	if err != nil {
		return nil, fmt.Errorf("grok: failed to exchange code for tokens: %w", err)
	}

	tokenStorage := authSvc.CreateTokenStorage(bundle)

	metadata := map[string]any{
		"type":          "grok",
		"access_token":  bundle.TokenData.AccessToken,
		"refresh_token": bundle.TokenData.RefreshToken,
		"timestamp":     time.Now().UnixMilli(),
	}
	if bundle.TokenData.Expire != "" {
		metadata["expired"] = bundle.TokenData.Expire
	}

	fileName := fmt.Sprintf("grok-%d.json", time.Now().UnixMilli())

	fmt.Println("\nGrok Build authentication successful!")

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    "Grok Build User",
		Storage:  tokenStorage,
		Metadata: metadata,
	}, nil
}
