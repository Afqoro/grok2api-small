package server

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"context"
	"strings"

	"grok2api-small/internal/db"
	"grok2api-small/internal/upstream"
)

var cryptoRand = rand.Reader

func (s *Server) AdminRoutes(mux *http.ServeMux) {
	auth := func(h http.HandlerFunc) http.HandlerFunc { return s.adminAuthMiddleware(h) }
	mux.HandleFunc("/api/admin/accounts", auth(s.handleAdminAccounts))
	mux.HandleFunc("/api/admin/accounts/", auth(s.handleAdminAccountItem))
	mux.HandleFunc("/api/admin/accounts/import", auth(s.handleAdminImport))
	mux.HandleFunc("/api/admin/models", auth(s.handleAdminModels))
	mux.HandleFunc("/api/admin/keys", auth(s.handleAdminKeys))
	mux.HandleFunc("/api/admin/keys/", auth(s.handleAdminKeyItem))
	mux.HandleFunc("/api/admin/keys/generate", auth(s.handleAdminKeyGen))
	mux.HandleFunc("/api/admin/sync", auth(s.handleAdminSync))
	mux.HandleFunc("/api/admin/reauth", auth(s.handleAdminReauthList))
	mux.HandleFunc("/api/admin/usage", auth(s.handleAdminUsage))
}

func (s *Server) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method_not_allowed", "GET only")
		return
	}
	accounts, err := s.db.ListAllAccounts()
	if err != nil {
		writeError(w, 500, "db_error", err.Error())
		return
	}
	var out []map[string]any
	for _, a := range accounts {
		out = append(out, map[string]any{
			"id": a.ID, "name": a.Name, "email": a.Email,
			"enabled": a.Enabled, "auth_status": a.AuthStatus,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleAdminAccountItem(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/accounts/")
	var id int64
	fmt.Sscanf(idStr, "%d", &id)
	if id == 0 {
		writeError(w, 400, "invalid_id", "Invalid account ID")
		return
	}
	switch r.Method {
	case "PATCH":
		var body struct {
			Enabled    *bool   `json:"enabled"`
			AuthStatus *string `json:"auth_status"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		acct, err := s.db.GetAccount(id)
		if err != nil {
			writeError(w, 404, "not_found", "Account not found")
			return
		}
		enabled := acct.Enabled
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		status := acct.AuthStatus
		if body.AuthStatus != nil {
			status = *body.AuthStatus
		}
		s.db.SetAccountStatus(id, enabled, status)
		writeJSON(w, 200, map[string]any{"ok": true})
	case "DELETE":
		s.db.DeleteAccount(id)
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		writeError(w, 405, "method_not_allowed", "")
	}
}

func (s *Server) handleAdminImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "method_not_allowed", "POST only")
		return
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
		Name         string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.RefreshToken == "" {
		writeError(w, 400, "invalid_request", "refresh_token required")
		return
	}

	ctx := r.Context()
	client := upstream.NewClient()
	tokens, err := client.RefreshToken(ctx, body.RefreshToken)
	if err != nil {
		writeError(w, 400, "refresh_failed", err.Error())
		return
	}

	encAccess, _ := s.cipher.Encrypt(tokens.AccessToken)
	encRefresh, _ := s.cipher.Encrypt(tokens.RefreshToken)

	expiresAt := int64(0)
	if tokens.ExpiresIn > 0 {
		expiresAt = int64(tokens.ExpiresIn)
	}

	id, err := s.db.InsertAccount(db.Account{
		Name:                  body.Name,
		EncryptedAccessToken:  encAccess,
		EncryptedRefreshToken: encRefresh,
		ExpiresAt:             expiresAt,
		OIDCClientID:          upstream.OAuthClientID,
	})
	if err != nil {
		writeError(w, 500, "db_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "status": "imported"})
}

func (s *Server) handleAdminModels(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT id, provider, public_id, upstream_model, origin, enabled FROM model_routes ORDER BY id")
	if err != nil {
		writeError(w, 500, "db_error", err.Error())
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int64
		var provider, publicID, upstreamModel, origin string
		var enabled int
		rows.Scan(&id, &provider, &publicID, &upstreamModel, &origin, &enabled)
		out = append(out, map[string]any{
			"id": id, "provider": provider, "public_id": publicID,
			"upstream_model": upstreamModel, "origin": origin, "enabled": enabled == 1,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.db.ListClientKeys()
	if err != nil {
		writeError(w, 500, "db_error", err.Error())
		return
	}
	var out []map[string]any
	for _, k := range keys {
		out = append(out, map[string]any{"id": k.ID, "name": k.Name})
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleAdminKeyItem(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/keys/")
	var id int64
	fmt.Sscanf(idStr, "%d", &id)
	if r.Method == "DELETE" {
		s.db.Exec("DELETE FROM client_keys WHERE id=?", id)
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	writeError(w, 405, "method_not_allowed", "")
}

func (s *Server) handleAdminKeyGen(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "method_not_allowed", "POST only")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Name == "" {
		body.Name = "default"
	}

	// generate random key
	keyBytes := make([]byte, 32)
	if _, err := io.ReadFull(cryptoRand, keyBytes); err != nil {
		writeError(w, 500, "rng_error", err.Error())
		return
	}
	plainKey := fmt.Sprintf("sk-gs-%x", keyBytes)
	encKey, _ := s.cipher.Encrypt(plainKey)

	id, err := s.db.InsertClientKey(body.Name, encKey, true)
	if err != nil {
		writeError(w, 500, "db_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "name": body.Name, "key": plainKey})
}

func (s *Server) handleAdminSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "method_not_allowed", "POST only")
		return
	}
	go s.syncSvc.SyncAll(context.Background())
	writeJSON(w, 200, map[string]any{"message": "sync triggered"})
}


func (s *Server) handleAdminReauthList(w http.ResponseWriter, r *http.Request) {
	// GET: list reauthRequired accounts
	// POST: update account tokens after device_mint
	if r.Method == "GET" {
		accounts, err := s.db.ListAllAccounts()
		if err != nil {
			writeError(w, 500, "db_error", err.Error())
			return
		}
		var out []map[string]any
		for _, a := range accounts {
			if a.AuthStatus == "reauthRequired" {
				out = append(out, map[string]any{
					"id": a.ID, "name": a.Name, "email": a.Email,
					"auth_status": a.AuthStatus,
				})
			}
		}
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(w, 200, out)
		return
	}
	if r.Method == "POST" {
		var body struct {
			AccountID    int64  `json:"account_id"`
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			Name         string `json:"name"`
			Email        string `json:"email"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.AccountID == 0 || body.AccessToken == "" {
			writeError(w, 400, "invalid_request", "account_id and access_token required")
			return
		}
		encAccess, _ := s.cipher.Encrypt(body.AccessToken)
		encRefresh := body.RefreshToken
		if encRefresh != "" {
			enc, _ := s.cipher.Encrypt(body.RefreshToken)
			encRefresh = enc
		}
		exp := upstream.TokenExpiry(body.AccessToken)
		if err := s.db.UpdateAccountTokens(body.AccountID, encAccess, encRefresh, exp); err != nil {
			writeError(w, 500, "db_error", err.Error())
			return
		}
		if body.Name != "" || body.Email != "" {
			s.db.Exec("UPDATE accounts SET name=?, email=?, updated_at=unixepoch() WHERE id=?", body.Name, body.Email, body.AccountID)
		}
		writeJSON(w, 200, map[string]any{"id": body.AccountID, "status": "reauthed"})
		return
	}
	writeError(w, 405, "method_not_allowed", "GET or POST")
}

func (s *Server) handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method_not_allowed", "GET only")
		return
	}
	rows, err := s.db.ListUsageToday()
	if err != nil {
		writeError(w, 500, "db_error", err.Error())
		return
	}
	if rows == nil {
		rows = []db.UsageRow{}
	}
	writeJSON(w, 200, rows)
}

// adminAuthMiddleware requires a bearer token for requests arriving through
// the public tunnel (identified by CF-Connecting-IP / X-Forwarded-For headers
// set by cloudflared). Direct local/Tailscale access is not restricted.
func (s *Server) adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("CF-Connecting-IP") != "" || r.Header.Get("X-Forwarded-For") != "" {
			// spoof risk: these headers could be set by the client itself when
			// hitting the local port directly; only trust them when the request
			// came from a loopback source (cloudflared connects from 127.0.0.1)
			isLoopback := false
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil && (host == "127.0.0.1" || host == "::1") {
				isLoopback = true
			}
			if !isLoopback {
				// direct remote client claiming CF headers = spoof attempt; require token
				token, _ := os.ReadFile("data/admin_token.txt")
				expected := strings.TrimSpace(string(token))
				auth := r.Header.Get("Authorization")
				if expected != "" && (auth == "Bearer "+expected || r.URL.Query().Get("token") == expected) {
					next(w, r)
					return
				}
				writeError(w, 401, "admin_auth_required", "admin token required")
				return
			}
			token, _ := os.ReadFile("data/admin_token.txt")
			expected := strings.TrimSpace(string(token))
			if expected == "" {
				writeError(w, 503, "admin_auth_unconfigured", "admin token not configured")
				return
			}
			auth := r.Header.Get("Authorization")
			if auth == "Bearer "+expected || r.URL.Query().Get("token") == expected {
				next(w, r)
				return
			}
			writeError(w, 401, "admin_auth_required", "admin token required for public access")
			return
		}
		next(w, r)
	}
}
