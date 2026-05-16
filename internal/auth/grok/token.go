package grok

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// GrokTokenStorage stores OAuth2 token information for Grok Build CLI authentication.
type GrokTokenStorage struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	LastRefresh  string `json:"last_refresh"`
	Type         string `json:"type"`
	Expire       string `json:"expired"`

	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *GrokTokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

// SaveTokenToFile serializes the Grok token storage to a JSON file.
func (ts *GrokTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "grok"
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}

	if err = json.NewEncoder(f).Encode(data); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}

// CredentialFileName returns the filename used to persist Grok OAuth credentials.
func CredentialFileName(email string) string {
	if email == "" {
		email = "user"
	}
	return fmt.Sprintf("grok-%s.json", email)
}
