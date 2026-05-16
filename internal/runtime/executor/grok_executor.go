package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	grokauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/grok"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/sjson"
)

const (
	grokBuildAPIBase   = "https://cli-chat-proxy.grok.com/v1"
	grokCLIVersion     = "0.8.29"
	grokTokenAuthValue = "xai-grok-cli"
	grokModelOverride  = "grok-build"
)

// GrokExecutor is a stateless executor for the xAI Grok Build CLI API.
type GrokExecutor struct {
	cfg *config.Config
}

// NewGrokExecutor creates a new Grok Build executor.
func NewGrokExecutor(cfg *config.Config) *GrokExecutor { return &GrokExecutor{cfg: cfg} }

// Identifier returns the executor identifier.
func (e *GrokExecutor) Identifier() string { return "grok" }

// PrepareRequest injects Grok credentials and required headers into the outgoing HTTP request.
func (e *GrokExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	token := grokCreds(auth)
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects Grok credentials into the request and executes it.
func (e *GrokExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("grok executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

// Execute performs a non-streaming chat completion request to Grok Build.
func (e *GrokExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	from := opts.SourceFormat
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	token := grokCreds(auth)

	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	to := sdktranslator.FromString("openai")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := bytes.Clone(originalPayloadSource)
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, false)
	body := sdktranslator.TranslateRequest(from, to, baseModel, bytes.Clone(req.Payload), false)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), "grok", e.Identifier())
	if err != nil {
		return resp, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel, requestPath)

	url := grokBuildAPIBase + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return resp, err
	}
	applyGrokHeaders(httpReq, token, false)
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(httpReq, attrs)
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("grok executor: close response body error: %v", errClose)
		}
	}()
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return resp, err
	}
	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)
	reporter.Publish(ctx, helps.ParseOpenAIUsage(data))
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, opts.OriginalRequest, body, data, nil)
	resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
	return resp, nil
}

// ExecuteStream performs a streaming chat completion request to Grok Build.
func (e *GrokExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	from := opts.SourceFormat
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	token := grokCreds(auth)

	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	to := sdktranslator.FromString("openai")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := bytes.Clone(originalPayloadSource)
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, true)
	body := sdktranslator.TranslateRequest(from, to, baseModel, bytes.Clone(req.Payload), true)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), "grok", e.Identifier())
	if err != nil {
		return nil, err
	}

	body, err = sjson.SetBytes(body, "stream_options.include_usage", true)
	if err != nil {
		return nil, fmt.Errorf("grok executor: failed to set stream_options in payload: %w", err)
	}
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel, requestPath)

	url := grokBuildAPIBase + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	applyGrokHeaders(httpReq, token, true)
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(httpReq, attrs)
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("grok executor: close response body error: %v", errClose)
		}
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return nil, err
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("grok executor: close response body error: %v", errClose)
			}
		}()
		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 1_048_576)
		var param any
		for scanner.Scan() {
			line := scanner.Bytes()
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			if detail, ok := helps.ParseOpenAIStreamUsage(line); ok {
				reporter.Publish(ctx, detail)
			}
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, opts.OriginalRequest, body, bytes.Clone(line), &param)
			for i := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
				case <-ctx.Done():
					return
				}
			}
		}
		doneChunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, opts.OriginalRequest, body, []byte("[DONE]"), &param)
		for i := range doneChunks {
			select {
			case out <- cliproxyexecutor.StreamChunk{Payload: doneChunks[i]}:
			case <-ctx.Done():
				return
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx, errScan)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errScan}:
			case <-ctx.Done():
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

// Refresh attempts to refresh Grok Build credentials using the stored refresh token.
func (e *GrokExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("grok executor: refresh called")
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		return refreshed, err
	}
	if auth == nil {
		return nil, fmt.Errorf("grok executor: auth is nil")
	}
	var refreshToken string
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["refresh_token"].(string); ok && strings.TrimSpace(v) != "" {
			refreshToken = v
		}
	}
	if strings.TrimSpace(refreshToken) == "" {
		return auth, nil
	}

	grokAuthSvc := grokauth.NewGrokAuthWithProxyURL(e.cfg, auth.ProxyURL)
	td, err := grokAuthSvc.RefreshTokensWithRetry(ctx, refreshToken, 3)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = td.AccessToken
	if td.RefreshToken != "" {
		auth.Metadata["refresh_token"] = td.RefreshToken
	}
	if td.Expire != "" {
		auth.Metadata["expired"] = td.Expire
	}
	auth.Metadata["type"] = "grok"
	auth.Metadata["last_refresh"] = time.Now().Format(time.RFC3339)
	return auth, nil
}

// CountTokens is not natively supported by Grok Build; returns an unsupported error.
func (e *GrokExecutor) CountTokens(_ context.Context, _ *cliproxyauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, fmt.Errorf("grok executor: count tokens not supported")
}

// applyGrokHeaders sets the required headers for Grok Build CLI API requests.
func applyGrokHeaders(r *http.Request, token string, stream bool) {
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("User-Agent", "grok-cli/"+grokCLIVersion)
	r.Header.Set("X-Grok-Client-Version", grokCLIVersion)
	r.Header.Set("X-XAI-Token-Auth", grokTokenAuthValue)
	r.Header.Set("x-grok-model-override", grokModelOverride)
	if stream {
		r.Header.Set("Accept", "text/event-stream")
		return
	}
	r.Header.Set("Accept", "application/json")
}

// grokCreds extracts the access token from the auth entry.
func grokCreds(a *cliproxyauth.Auth) string {
	if a == nil {
		return ""
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	if a.Attributes != nil {
		if v := a.Attributes["access_token"]; v != "" {
			return v
		}
		if v := a.Attributes["api_key"]; v != "" {
			return v
		}
	}
	return ""
}
