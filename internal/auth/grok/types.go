// Package grok provides authentication and token management for xAI's Grok Build CLI.
// It handles the OAuth2 PKCE flow for secure authentication with auth.x.ai.
package grok

// PKCECodes holds the verification codes for the OAuth2 PKCE (Proof Key for Code Exchange) flow.
type PKCECodes struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
}

// GrokTokenData holds the OAuth token information obtained from xAI.
type GrokTokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Email        string `json:"email"`
	Expire       string `json:"expired"`
	ExpiresIn    int    `json:"expires_in"`
}

// GrokAuthBundle aggregates authentication data after the OAuth flow completes.
type GrokAuthBundle struct {
	TokenData   GrokTokenData `json:"token_data"`
	LastRefresh string        `json:"last_refresh"`
}
