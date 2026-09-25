package sync

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"grok2api-small/internal/crypto"
	"grok2api-small/internal/db"
	"grok2api-small/internal/upstream"
)

type retainedEntry struct {
	modTime     time.Time
	perProvider map[string][]string
}

var retainedCache atomic.Pointer[retainedEntry]

func retainedModels(provider string) []string {
	const path = "data/retained_models.json"
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if e := retainedCache.Load(); e != nil && e.modTime.Equal(st.ModTime()) {
		return e.perProvider[provider]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	parsed := make(map[string][]string)
	if err := json.Unmarshal(raw, &parsed); err != nil {
		slog.Warn("retained_models_parse_failed", "error", err)
		return nil
	}
	entry := &retainedEntry{modTime: st.ModTime(), perProvider: parsed}
	retainedCache.Store(entry)
	slog.Info("retained_models_loaded", "provider", provider, "count", len(parsed[provider]))
	return parsed[provider]
}

func appendRetained(models []string, provider string) []string {
	extras := retainedModels(provider)
	if len(extras) == 0 {
		return models
	}
	return append(models, extras...)
}

type SyncService struct {
	db      *db.DB
	client  *upstream.Client
	cipher  *crypto.Cipher
	logger  *slog.Logger
}

func NewSyncService(database *db.DB, client *upstream.Client, cipher *crypto.Cipher) *SyncService {
	return &SyncService{db: database, client: client, cipher: cipher, logger: slog.Default()}
}

func (s *SyncService) SyncAll(ctx context.Context) (int, int) {
	accounts, err := s.db.ListActiveAccounts()
	if err != nil {
		s.logger.Error("sync_list_accounts_failed", "error", err)
		return 0, 0
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	succeeded := atomic.Int32{}
	failed := atomic.Int32{}

	for _, acct := range accounts {
		wg.Add(1)
		go func(a db.Account) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if err := s.syncAccount(ctx, a); err != nil {
				s.logger.Warn("sync_account_failed", "id", a.ID, "error", err)
				failed.Add(1)
			} else {
				succeeded.Add(1)
			}
		}(acct)
	}
	wg.Wait()
	return int(succeeded.Load()), int(failed.Load())
}

func (s *SyncService) syncAccount(ctx context.Context, a db.Account) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cred := upstream.Credential{
		UserID: a.UserID,
		Email:  a.Email,
	}
	token, err := upstream.RefreshAndStore(ctx, s.client, s.db, s.cipher, a.ID, a.EncryptedAccessToken, a.EncryptedRefreshToken)
	if err != nil {
		return err
	}
	cred.AccessToken = token

	models, err := s.client.ListModels(ctx, cred)
	if err != nil {
		s.db.MarkSyncFailed(a.ID, err.Error())
		return err
	}

	models = appendRetained(models, "grok_build")

	if err := s.db.ReplaceAccountCapabilities(a.ID, models); err != nil {
		return err
	}

	// upsert routes
	s.db.UpsertDiscoveredRoutes("grok_build", models)
	return nil
}

func (s *SyncService) SyncStartup(ctx context.Context) {
	slog.Info("startup_sync_begin")
	succ, fail := s.SyncAll(ctx)
	slog.Info("startup_sync_completed", "succeeded", succ, "failed", fail)
}
