package recovery

import (
	"context"
	"log/slog"
	"time"

	"grok2api-small/internal/crypto"
	"grok2api-small/internal/db"
	"grok2api-small/internal/upstream"
)

const (
	workerTickInterval    = 1 * time.Second
	reconcileInterval     = 1 * time.Minute
	recoveryProbeTimeout = 30 * time.Second
	reconcileLimit       = 1000
	consoleInterval      = 24 * time.Hour
	claimLease           = 2 * time.Minute
)

type Service struct {
	db     *db.DB
	client *upstream.Client
	cipher *crypto.Cipher
	logger *slog.Logger
	base   time.Duration
	max    time.Duration
}

func New(database *db.DB, client *upstream.Client, cipher *crypto.Cipher) *Service {
	return &Service{
		db:     database,
		client: client,
		cipher: cipher,
		logger: slog.Default(),
		base:   30 * time.Second,
		max:    30 * time.Minute,
	}
}

func (s *Service) Run(ctx context.Context) {
	s.logger.Info("quota_recovery_started")
	ticker := time.NewTicker(workerTickInterval)
	defer ticker.Stop()
	reconcileTicker := time.NewTicker(reconcileInterval)
	defer reconcileTicker.Stop()
	s.reconcile(ctx, time.Now().UTC())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.runDue(ctx, now.UTC())
		case now := <-reconcileTicker.C:
			s.reconcile(ctx, now.UTC())
		}
	}
}

func (s *Service) runDue(ctx context.Context, now time.Time) {
	events, err := s.db.ClaimDueRecoveries(now.Unix(), 25)
	if err != nil {
		s.logger.Warn("quota_recovery_claim_failed", "error", err)
		return
	}
	if len(events) == 0 {
		return
	}
	s.logger.Info("quota_recovery_run", "events", len(events))
	for _, ev := range events {
		s.runOne(ctx, now, ev)
	}
}

func (s *Service) runOne(ctx context.Context, now time.Time, ev db.RecoveryEvent) {
	probeCtx, cancel := context.WithTimeout(ctx, recoveryProbeTimeout)
	defer cancel()

	// Probe: try a lightweight /models request to see if account is healthy
	acct, err := s.db.GetAccount(ev.AccountID)
	if err != nil {
		ev.Attempts++
		ev.DueAt = now.Add(s.backoff(ev.Attempts)).Unix()
		s.db.RescheduleQuotaRecovery(ev)
		return
	}

	if !acct.Enabled || acct.AuthStatus != "active" {
		s.db.AckQuotaRecovery(ev)
		return
	}

	// Check if cooldown has passed
	if acct.CooldownUntil > 0 && acct.CooldownUntil > now.Unix() {
		// Still in cooldown — reschedule to cooldown end
		ev.DueAt = acct.CooldownUntil
		ev.Attempts++
		s.db.RescheduleQuotaRecovery(ev)
		return
	}

	// Try token refresh to probe account health
	_, err = upstream.RefreshAndStore(probeCtx, s.client, s.db, s.cipher, acct.ID, acct.EncryptedAccessToken, acct.EncryptedRefreshToken)
	if err != nil {
		errStr := err.Error()
		if contains(errStr, "invalid_grant") || contains(errStr, "refresh_denied") {
			s.db.SetAccountStatus(ev.AccountID, true, "reauthRequired")
			s.logger.Warn("quota_recovery_marked_reauth", "account_id", ev.AccountID, "error", err)
			s.db.AckQuotaRecovery(ev)
			return
		}
		ev.Attempts++
		ev.DueAt = now.Add(s.backoff(ev.Attempts)).Unix()
		s.db.RescheduleQuotaRecovery(ev)
		return
	}

	// Token refresh succeeded — clear cooldown and quota window
	s.db.ClearAccountCooldownIfQuotaRecovered(ev.AccountID)
	s.db.AckQuotaRecovery(ev)
	s.logger.Info("quota_recovery_cleared", "account_id", ev.AccountID)
}

func (s *Service) reconcile(ctx context.Context, now time.Time) {
	windows, err := s.db.ListDueQuotaWindows(now.Unix(), reconcileLimit)
	if err != nil {
		s.logger.Warn("quota_recovery_reconcile_failed", "error", err)
		return
	}
	s.logger.Info("quota_recovery_reconcile", "windows_due", len(windows))
	for _, w := range windows {
		s.db.EnsureQuotaRecovery(db.RecoveryEvent{
			AccountID: w.AccountID,
			Mode:     w.Mode,
			DueAt:    now.Unix(),
		})
	}
}

func (s *Service) backoff(attempt int) time.Duration {
	base := s.base
	maximum := s.max
	if base <= 0 {
		base = 30 * time.Second
	}
	if maximum < base {
		maximum = 30 * time.Minute
	}
	value := base
	for i := 1; i < attempt && value < maximum; i++ {
		value *= 2
	}
	if value > maximum {
		return maximum
	}
	return value
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
