package grok

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GeneratePKCECodes generates a new pair of PKCE codes for the OAuth2 authorization code flow.
func GeneratePKCECodes() (*PKCECodes, error) {
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	codeChallenge := generateCodeChallenge(codeVerifier)
	return &PKCECodes{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}, nil
}

func generateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes), nil
}

func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
