package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog"

	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
)

// GuardProxy is an HTTP reverse proxy with DPI hooks.
type GuardProxy struct {
	pipe    *pipeline.Pipeline
	backend *url.URL
	proxy   *httputil.ReverseProxy
	logger  zerolog.Logger
}

// New creates a new GuardProxy.
func New(pipe *pipeline.Pipeline, backendURL string, logger zerolog.Logger) (*GuardProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}

	gp := &GuardProxy{
		pipe:    pipe,
		backend: target,
		logger:  logger,
	}

	gp.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
		},
	}

	return gp, nil
}

// ServeHTTP handles incoming requests.
func (gp *GuardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only inspect chat completion endpoints
	if !isChatCompletionEndpoint(r.URL.Path) {
		// Pass through non-chat requests directly
		gp.proxy.ServeHTTP(w, r)
		return
	}

	// Read the request body
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Parse the chat request
	chatReq, err := ParseChatRequest(bodyBytes)
	if err != nil {
		// Not a valid chat request, pass through
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
		gp.proxy.ServeHTTP(w, r)
		return
	}

	// Extract prompt text and run ingress DPI with declared headers
	promptText := ExtractPromptText(chatReq)
	result := gp.pipe.ProcessIngress(promptText, chatReq.AgentGuard)

	gp.logger.Info().
		Str("request_id", result.RequestID).
		Str("action", string(result.IngressResult.Action)).
		Str("rule", result.IngressResult.RuleName).
		Float64("risk_score", result.IngressMetadata.RiskScore).
		Str("intent", result.IngressMetadata.IntentCategory).
		Msg("ingress")

	// If blocked at ingress, return deny response with metadata
	if !result.ShouldForward() {
		gp.logger.Warn().
			Str("request_id", result.RequestID).
			Str("rule", result.IngressResult.RuleName).
			Str("deny_message", result.DenyMessage).
			Msg("blocked at ingress")

		headers := result.BuildResponseHeaders()
		denyResp := MakeDenyResponse(result.DenyMessage, chatReq.Model, headers)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(denyResp)
		return
	}

	// If HUMAN_REVIEW, block with review message and metadata
	if result.NeedsHumanReview() {
		gp.logger.Warn().
			Str("request_id", result.RequestID).
			Msg("requires human review")

		headers := result.BuildResponseHeaders()
		denyResp := MakeDenyResponse("[AGENT GUARD] Request requires human review before processing.", chatReq.Model, headers)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(denyResp)
		return
	}

	// Store the result in the request context for egress processing
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	// For streaming requests, pass through without egress inspection
	if chatReq.Stream {
		gp.proxy.ServeHTTP(w, r)
		return
	}

	// Use a response recorder to capture the backend response for egress DPI
	recorder := &responseRecorder{
		header: make(http.Header),
		body:   &bytes.Buffer{},
		code:   http.StatusOK,
	}

	gp.proxy.ServeHTTP(recorder, r)

	// Parse backend response for egress DPI
	respBody := recorder.body.Bytes()
	chatResp, err := ParseChatResponse(respBody)
	if err == nil && len(chatResp.Choices) > 0 {
		responseText := ExtractResponseText(chatResp)
		gp.pipe.ProcessEgress(result, responseText)

		if result.Blocked && result.BlockedAt == "egress" {
			gp.logger.Warn().
				Str("request_id", result.RequestID).
				Str("rule", result.EgressResult.RuleName).
				Str("deny_message", result.DenyMessage).
				Msg("blocked at egress")

			headers := result.BuildResponseHeaders()
			denyResp := MakeDenyResponse(result.DenyMessage, chatResp.Model, headers)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(denyResp)
			return
		}

		gp.logger.Info().
			Str("request_id", result.RequestID).
			Str("action", string(result.EgressResult.Action)).
			Str("rule", result.EgressResult.RuleName).
			Msg("egress")
	}

	// Inject _agentguard headers into the backend response
	headers := result.BuildResponseHeaders()
	injected, err := injectAgentGuardHeaders(respBody, headers)
	if err != nil {
		// Injection failed — forward the original response unchanged
		gp.logger.Warn().Err(err).Msg("failed to inject _agentguard headers")
		for k, v := range recorder.header {
			w.Header()[k] = v
		}
		w.WriteHeader(recorder.code)
		w.Write(respBody)
		return
	}

	// Forward the response with injected headers, updating Content-Length
	for k, v := range recorder.header {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(injected)))
	w.WriteHeader(recorder.code)
	w.Write(injected)
}

// Handler returns the proxy as an http.Handler.
func (gp *GuardProxy) Handler() http.Handler {
	return gp
}

// isChatCompletionEndpoint checks if the path matches known chat completion endpoints.
func isChatCompletionEndpoint(path string) bool {
	chatPaths := []string{
		"/v1/chat/completions",
		"/api/chat",
		"/api/generate",
		"/chat/completions",
	}
	for _, p := range chatPaths {
		if strings.HasSuffix(path, p) || path == p {
			return true
		}
	}
	return false
}

// responseRecorder captures an HTTP response for post-processing.
type responseRecorder struct {
	header http.Header
	body   *bytes.Buffer
	code   int
}

func (rr *responseRecorder) Header() http.Header {
	return rr.header
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	return rr.body.Write(b)
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.code = code
}

// BuildHandler creates a complete handler with the ingress/egress pipeline.
// This is the main entry point for setting up the proxy.
func BuildHandler(pol *policy.Policy, backendURL string, logger zerolog.Logger, auditLog *pipeline.Pipeline) (*GuardProxy, error) {
	return New(auditLog, backendURL, logger)
}
