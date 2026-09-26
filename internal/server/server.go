package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"context"
	"time"

	"grok2api-small/internal/converter"
	"grok2api-small/internal/crypto"
	"grok2api-small/internal/db"
	"grok2api-small/internal/recovery"
	"grok2api-small/internal/sync"
	"grok2api-small/internal/upstream"
)

type Server struct {
	db      *db.DB
	client  *upstream.Client
	cipher  *crypto.Cipher
	syncSvc *sync.SyncService
	recSvc  *recovery.Service
	logger  *slog.Logger
}

func New(database *db.DB, client *upstream.Client, cipher *crypto.Cipher, syncSvc *sync.SyncService, recSvc *recovery.Service) *Server {
	return &Server{db: database, client: client, cipher: cipher, syncSvc: syncSvc, recSvc: recSvc, logger: slog.Default()}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", s.authMiddleware(s.handleModels))
	mux.HandleFunc("/v1/chat/completions", s.authMiddleware(s.handleChat))
	mux.HandleFunc("/", s.handleWebUI)
	return mux
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, 401, "invalid_api_key", "Missing or invalid Authorization header")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		keys, err := s.db.ListClientKeys()
		if err != nil || len(keys) == 0 {
			writeError(w, 500, "server_error", "No client keys configured")
			return
		}
		matched := false
		var allowAliases bool
		for _, k := range keys {
			plain, err := s.cipher.Decrypt(k.EncryptedSecret)
			if err == nil && plain == token {
				matched = true
				allowAliases = k.AllowModelAliases
				break
			}
		}
		if !matched {
			writeError(w, 401, "invalid_api_key", "Invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), "allowAliases", allowAliases)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	routes, err := s.db.ListEnabledRoutes()
	if err != nil {
		writeError(w, 500, "model_list_failed", err.Error())
		return
	}
	allowAliases := false
	if v, ok := r.Context().Value("allowAliases").(bool); ok {
		allowAliases = v
	}
	var data []map[string]any
	seen := map[string]bool{}
	for _, route := range routes {
		if seen[route.PublicID] {
			continue
		}
		seen[route.PublicID] = true
		data = append(data, map[string]any{
			"id": route.PublicID, "object": "model", "created": 0, "owned_by": "grok2api-small",
		})
		// Expand reasoning effort aliases
		if allowAliases {
			for _, effort := range []string{"low", "medium", "high", "xhigh"} {
				alias := route.PublicID + "-" + effort
				if !seen[alias] {
					seen[alias] = true
					data = append(data, map[string]any{
						"id": alias, "object": "model", "created": 0, "owned_by": "grok2api-small",
					})
				}
			}
		}
	}
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"object": "list", "data": data})
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}

	var req struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}

	if req.Model == "" {
		writeError(w, 400, "invalid_request", "model is required")
		return
	}

	// resolve model: strip effort suffix for upstream
	upstreamModel := req.Model
	for _, suffix := range []string{"-low", "-medium", "-high", "-xhigh"} {
		if strings.HasSuffix(upstreamModel, suffix) {
			upstreamModel = strings.TrimSuffix(upstreamModel, suffix)
			break
		}
	}

	// convert request
	converted, err := converter.ConvertChatRequest(body, upstreamModel)
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}

	// failover: try accounts until one succeeds or all exhausted
	maxRetries := 5
	var lastErr error
	var lastCode int
	for attempt := 0; attempt < maxRetries; attempt++ {
		acct, err := s.db.GetHealthyAccountForModel(upstreamModel)
		if err != nil {
			break
		}

		accessToken, err := upstream.RefreshAndStore(r.Context(), s.client, s.db, s.cipher, acct.ID, acct.EncryptedAccessToken, acct.EncryptedRefreshToken)
		if err != nil {
			// Check if this is a permanent refresh failure (invalid_grant etc)
			errStr := err.Error()
			if strings.Contains(errStr, "invalid_grant") || strings.Contains(errStr, "refresh_denied") || strings.Contains(errStr, "missing_refresh_token") {
				s.db.SetAccountStatus(acct.ID, true, "reauthRequired")
				s.logger.Warn("account_marked_reauth", "id", acct.ID, "error", err)
			} else {
				s.db.MarkAccountFailed(acct.ID, 60)
			}
			lastErr = fmt.Errorf("token refresh failed for account %d: %w", acct.ID, err)
			continue
		}

		cred := upstream.Credential{
			AccessToken: accessToken,
			UserID:       acct.UserID,
			Email:        acct.Email,
		}

		result, err := s.client.PostResponses(r.Context(), cred, upstreamModel, converted, req.Stream)
		if err != nil {
			s.db.MarkAccountFailed(acct.ID, 60)
			lastErr = err
			continue
		}

		if result.StatusCode == 429 || result.StatusCode == 503 {
			// Read body for rate limit parsing
			bodyBytes, _ := io.ReadAll(io.LimitReader(result.Body, 64<<10))
			result.Body.Close()

			cooldown := int64(300) // default 5 min for 503
			if result.StatusCode == 429 {
				cooldown = 3600 // default 1h
				if rl := upstream.RateLimitFromResponse(429, result.Header, bodyBytes); rl != nil {
					cooldown = int64(rl.RetryAfter.Seconds())
					if cooldown < 2 {
						cooldown = 2
					}
					s.logger.Info("rate_limit_parsed", "account_id", acct.ID, "scope", rl.Scope, "retry_after", rl.RetryAfter, "actual", rl.Actual, "limit", rl.Limit)
				}
			}

			now := time.Now().Unix()
			s.db.MarkAccountFailed(acct.ID, cooldown)

			// Record quota window
			s.db.UpsertQuotaWindow(db.QuotaWindow{
				AccountID: acct.ID,
				Mode: "build",
				Remaining: 0,
				ResetAt: now + cooldown,
				SyncedAt: now,
				Source: "upstream",
			})

			// Schedule recovery probe
			s.db.EnsureQuotaRecovery(db.RecoveryEvent{
				AccountID: acct.ID,
				Mode: "build",
				DueAt: now + cooldown,
			})

			lastCode = result.StatusCode
			lastErr = fmt.Errorf("upstream %d for account %d", result.StatusCode, acct.ID)
			continue
		}

		if result.StatusCode != 200 {
			result.Body.Close()
			lastCode = result.StatusCode
			lastErr = fmt.Errorf("upstream %d", result.StatusCode)
			// don't cooldown for 400/401, just try next
			continue
		}

		// success
		s.db.MarkAccountSuccess(acct.ID)
		s.handleChatResponse(w, result, acct.ID, req.Model, req.Stream)
		return
	}

	if lastCode == 429 {
		writeError(w, 429, "upstream_quota_exhausted", "All accounts quota-exhausted for this model")
	} else if lastCode == 503 {
		writeError(w, 503, "upstream_unavailable", "All accounts unavailable for this model")
	} else if lastErr != nil {
		writeError(w, 502, "upstream_error", fmt.Sprintf("All accounts failed: %v", lastErr))
	} else {
		writeError(w, 503, "upstream_unavailable", fmt.Sprintf("No healthy account for model %s", upstreamModel))
	}

}

func (s *Server) handleChatResponse(w http.ResponseWriter, result *upstream.ChatResult, accountID int64, model string, stream bool) {
	defer result.Body.Close()
	if stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(200)
		sc := converter.NewStreamConverter(w, model)
		sc.ProcessStream(result.Body)
		if usage := sc.LastUsage(); usage != nil {
			s.recordUsage(accountID, usage)
		}
	} else {
		respBody, err := io.ReadAll(io.LimitReader(result.Body, 8<<20))
		if err != nil {
			writeError(w, 502, "upstream_error", err.Error())
			return
		}
		converted, err := converter.ConvertResponsesToChat(respBody, model)
		if err != nil {
			writeError(w, 500, "conversion_error", err.Error())
			return
		}
		var chatResp struct {
			Usage *struct {
				PromptTokens     int64 `json:"prompt_tokens"`
				CompletionTokens int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(converted, &chatResp) == nil && chatResp.Usage != nil {
			s.db.AddAccountUsage(accountID, chatResp.Usage.PromptTokens, chatResp.Usage.CompletionTokens)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(converted)
	}
}

func (s *Server) recordUsage(accountID int64, usage map[string]any) {
	prompt, _ := usage["prompt_tokens"].(float64)
	completion, _ := usage["completion_tokens"].(float64)
	if prompt > 0 || completion > 0 {
		s.db.AddAccountUsage(accountID, int64(prompt), int64(completion))
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode, message string) {
	writeJSON(w, code, map[string]any{
		"error": map[string]any{
			"code":    errCode,
			"message": message,
			"type":    "invalid_request_error",
		},
	})
}
