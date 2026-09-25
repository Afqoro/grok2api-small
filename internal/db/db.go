package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func Open(path string) (*DB, error) {
	d, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	if err := d.Ping(); err != nil {
		return nil, err
	}
	db := &DB{d}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) migrate() error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS accounts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL DEFAULT '',
	email TEXT NOT NULL DEFAULT '',
	user_id TEXT NOT NULL DEFAULT '',
	encrypted_access_token TEXT NOT NULL,
	encrypted_refresh_token TEXT NOT NULL,
	expires_at INTEGER NOT NULL DEFAULT 0,
	oidc_client_id TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	auth_status TEXT NOT NULL DEFAULT 'active',
	created_at INTEGER NOT NULL DEFAULT (unixepoch()),
	updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
	failure_count INTEGER NOT NULL DEFAULT 0,
	cooldown_until INTEGER NOT NULL DEFAULT 0,
	last_used_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS client_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL DEFAULT 'default',
	encrypted_secret TEXT NOT NULL,
	allow_model_aliases INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS model_routes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	provider TEXT NOT NULL DEFAULT 'grok_build',
	public_id TEXT NOT NULL,
	upstream_model TEXT NOT NULL,
	origin TEXT NOT NULL DEFAULT 'discovered',
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS account_model_capabilities (
	account_id INTEGER NOT NULL,
	upstream_model TEXT NOT NULL,
	PRIMARY KEY (account_id, upstream_model)
);

CREATE TABLE IF NOT EXISTS account_model_sync_states (
	account_id INTEGER PRIMARY KEY,
	last_attempt_at TEXT,
	last_success_at TEXT,
	last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_routes_public ON model_routes(public_id);
CREATE INDEX IF NOT EXISTS idx_routes_provider ON model_routes(provider);
CREATE INDEX IF NOT EXISTS idx_caps_model ON account_model_capabilities(upstream_model);

`)
	if err != nil {
		return err
	}
	return db.migrateColumns()
}

func (db *DB) migrateColumns() error {
	cols := map[string]bool{}
	rows, err := db.Query("PRAGMA table_info(accounts)")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk)
		cols[name] = true
	}
	for _, col := range []struct{ name, def string }{
		{"failure_count", "INTEGER NOT NULL DEFAULT 0"},
		{"cooldown_until", "INTEGER NOT NULL DEFAULT 0"},
		{"last_used_at", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if !cols[col.name] {
			if _, err := db.Exec(fmt.Sprintf("ALTER TABLE accounts ADD COLUMN %s %s", col.name, col.def)); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- Account operations ---

type Account struct {
	ID                    int64
	Name                  string
	Email                 string
	UserID                string
	EncryptedAccessToken  string
	EncryptedRefreshToken string
	ExpiresAt             int64
	OIDCClientID          string
	Enabled               bool
	AuthStatus            string
	FailureCount          int64
	CooldownUntil         int64
	LastUsedAt            int64
}

func (db *DB) ListActiveAccounts() ([]Account, error) {
	rows, err := db.Query("SELECT id, name, email, user_id, encrypted_access_token, encrypted_refresh_token, expires_at, oidc_client_id, enabled, auth_status, failure_count, cooldown_until, last_used_at FROM accounts WHERE enabled=1 AND auth_status='active' ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		var enabled int
		if err := rows.Scan(&a.ID, &a.Name, &a.Email, &a.UserID, &a.EncryptedAccessToken, &a.EncryptedRefreshToken, &a.ExpiresAt, &a.OIDCClientID, &enabled, &a.AuthStatus, &a.FailureCount, &a.CooldownUntil, &a.LastUsedAt); err != nil {
			return nil, err
		}
		a.Enabled = enabled == 1
		out = append(out, a)
	}
	return out, nil
}

func (db *DB) ListAllAccounts() ([]Account, error) {
	rows, err := db.Query("SELECT id, name, email, user_id, encrypted_access_token, encrypted_refresh_token, expires_at, oidc_client_id, enabled, auth_status, failure_count, cooldown_until, last_used_at FROM accounts ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		var enabled int
		if err := rows.Scan(&a.ID, &a.Name, &a.Email, &a.UserID, &a.EncryptedAccessToken, &a.EncryptedRefreshToken, &a.ExpiresAt, &a.OIDCClientID, &enabled, &a.AuthStatus, &a.FailureCount, &a.CooldownUntil, &a.LastUsedAt); err != nil {
			return nil, err
		}
		a.Enabled = enabled == 1
		out = append(out, a)
	}
	return out, nil
}

func (db *DB) GetAccount(id int64) (*Account, error) {
	var a Account
	var enabled int
	err := db.QueryRow("SELECT id, name, email, user_id, encrypted_access_token, encrypted_refresh_token, expires_at, oidc_client_id, enabled, auth_status, failure_count, cooldown_until, last_used_at FROM accounts WHERE id=?", id).
		Scan(&a.ID, &a.Name, &a.Email, &a.UserID, &a.EncryptedAccessToken, &a.EncryptedRefreshToken, &a.ExpiresAt, &a.OIDCClientID, &enabled, &a.AuthStatus, &a.FailureCount, &a.CooldownUntil, &a.LastUsedAt)
	if err != nil {
		return nil, err
	}
	a.Enabled = enabled == 1
	return &a, nil
}

func (db *DB) InsertAccount(a Account) (int64, error) {
	res, err := db.Exec("INSERT INTO accounts (name, email, user_id, encrypted_access_token, encrypted_refresh_token, expires_at, oidc_client_id, enabled, auth_status) VALUES (?,?,?,?,?,?,?,1,'active')",
		a.Name, a.Email, a.UserID, a.EncryptedAccessToken, a.EncryptedRefreshToken, a.ExpiresAt, a.OIDCClientID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) UpdateAccountTokens(id int64, encAccess, encRefresh string, expiresAt int64) error {
	_, err := db.Exec("UPDATE accounts SET encrypted_access_token=?, encrypted_refresh_token=?, expires_at=?, auth_status='active', updated_at=unixepoch() WHERE id=?", encAccess, encRefresh, expiresAt, id)
	return err
}

func (db *DB) SetAccountStatus(id int64, enabled bool, authStatus string) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := db.Exec("UPDATE accounts SET enabled=?, auth_status=?, updated_at=unixepoch() WHERE id=?", e, authStatus, id)
	return err
}

func (db *DB) DeleteAccount(id int64) error {
	_, err := db.Exec("DELETE FROM accounts WHERE id=?", id)
	return err
}

// --- Client key operations ---

type ClientKey struct {
	ID                int64
	Name              string
	EncryptedSecret   string
	AllowModelAliases bool
}

func (db *DB) GetClientKeyByName(name string) (*ClientKey, error) {
	var k ClientKey
	var allow int
	err := db.QueryRow("SELECT id, name, encrypted_secret, allow_model_aliases FROM client_keys WHERE name=?", name).
		Scan(&k.ID, &k.Name, &k.EncryptedSecret, &allow)
	if err != nil {
		return nil, err
	}
	k.AllowModelAliases = allow == 1
	return &k, nil
}

func (db *DB) ListClientKeys() ([]ClientKey, error) {
	rows, err := db.Query("SELECT id, name, encrypted_secret, allow_model_aliases FROM client_keys ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientKey
	for rows.Next() {
		var k ClientKey
		var allow int
		if err := rows.Scan(&k.ID, &k.Name, &k.EncryptedSecret, &allow); err != nil {
			return nil, err
		}
		k.AllowModelAliases = allow == 1
		out = append(out, k)
	}
	return out, nil
}

func (db *DB) InsertClientKey(name, encryptedSecret string, allowAliases bool) (int64, error) {
	a := 0
	if allowAliases {
		a = 1
	}
	res, err := db.Exec("INSERT INTO client_keys (name, encrypted_secret, allow_model_aliases) VALUES (?,?,?)", name, encryptedSecret, a)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// --- Model route operations ---

type ModelRoute struct {
	ID            int64
	Provider      string
	PublicID      string
	UpstreamModel string
	Origin        string
	Enabled       bool
}

func (db *DB) ListEnabledRoutes() ([]ModelRoute, error) {
	rows, err := db.Query(`
		SELECT r.id, r.provider, r.public_id, r.upstream_model, r.origin, r.enabled
		FROM model_routes r
		WHERE r.enabled=1
		AND EXISTS (
			SELECT 1 FROM accounts a
			WHERE a.enabled=1 AND a.auth_status='active'
			AND (
				EXISTS (SELECT 1 FROM account_model_capabilities c WHERE c.account_id=a.id AND c.upstream_model=r.upstream_model)
				OR NOT EXISTS (SELECT 1 FROM account_model_capabilities c WHERE c.upstream_model=r.upstream_model)
			)
		)
		GROUP BY r.public_id
	`) // simplified: show route if any active account has capability OR no account has it (discovered but not synced yet)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModelRoute
	seen := map[string]bool{}
	for rows.Next() {
		var r ModelRoute
		var enabled int
		if err := rows.Scan(&r.ID, &r.Provider, &r.PublicID, &r.UpstreamModel, &r.Origin, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		pub := r.PublicID
		if seen[pub] {
			continue
		}
		seen[pub] = true
		out = append(out, r)
	}
	return out, nil
}

func (db *DB) GetRouteByModel(model string) (*ModelRoute, error) {
	var r ModelRoute
	var enabled int
	err := db.QueryRow("SELECT id, provider, public_id, upstream_model, origin, enabled FROM model_routes WHERE public_id=? AND enabled=1 ORDER BY id LIMIT 1", model).
		Scan(&r.ID, &r.Provider, &r.PublicID, &r.UpstreamModel, &r.Origin, &enabled)
	if err != nil {
		return nil, err
	}
	r.Enabled = enabled == 1
	return &r, nil
}

func (db *DB) UpsertDiscoveredRoutes(provider string, models []string) error {
	for _, m := range models {
		var count int
		db.QueryRow("SELECT COUNT(*) FROM model_routes WHERE provider=? AND upstream_model=?", provider, m).Scan(&count)
		if count == 0 {
			publicID := m
			db.Exec("INSERT INTO model_routes (provider, public_id, upstream_model, origin, enabled) VALUES (?,?,?,'discovered',1)", provider, publicID, m)
		}
	}
	return nil
}

// --- Capability operations ---

func (db *DB) ReplaceAccountCapabilities(accountID int64, models []string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM account_model_capabilities WHERE account_id=?", accountID); err != nil {
		tx.Rollback()
		return err
	}
	for _, m := range models {
		if _, err := tx.Exec("INSERT OR IGNORE INTO account_model_capabilities (account_id, upstream_model) VALUES (?,?)", accountID, m); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO account_model_sync_states (account_id, last_attempt_at, last_success_at, last_error)
		VALUES (?,?,?,NULL)
		ON CONFLICT(account_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at, last_success_at=excluded.last_success_at, last_error=NULL`,
		accountID, fmt.Sprintf("%d", accountID), fmt.Sprintf("%d", accountID)); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (db *DB) GetActiveAccountForModel(upstreamModel string) (*Account, error) {
	var a Account
	var enabled int
	err := db.QueryRow(`
		SELECT a.id, a.name, a.email, a.user_id, a.encrypted_access_token, a.encrypted_refresh_token, a.expires_at, a.oidc_client_id, a.enabled, a.auth_status, a.failure_count, a.cooldown_until, a.last_used_at
		FROM accounts a
		WHERE a.enabled=1 AND a.auth_status='active'
		AND EXISTS (SELECT 1 FROM account_model_capabilities c WHERE c.account_id=a.id AND c.upstream_model=?)
		ORDER BY a.id
		LIMIT 1`, upstreamModel).
		Scan(&a.ID, &a.Name, &a.Email, &a.UserID, &a.EncryptedAccessToken, &a.EncryptedRefreshToken, &a.ExpiresAt, &a.OIDCClientID, &enabled, &a.AuthStatus, &a.FailureCount, &a.CooldownUntil, &a.LastUsedAt)
	if err != nil {
		return nil, err
	}
	a.Enabled = enabled == 1
	return &a, nil
}

func (db *DB) MarkSyncFailed(accountID int64, msg string) error {
	_, err := db.Exec(`INSERT INTO account_model_sync_states (account_id, last_attempt_at, last_error)
		VALUES (?,? ,?)
		ON CONFLICT(account_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at, last_error=excluded.last_error`,
		accountID, fmt.Sprintf("%d", accountID), msg)
	return err
}

func (db *DB) ListAccountCapabilities(accountID int64) ([]string, error) {
	rows, err := db.Query("SELECT upstream_model FROM account_model_capabilities WHERE account_id=?", accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// --- Failover & round-robin ---

func (db *DB) GetHealthyAccountForModel(upstreamModel string) (*Account, error) {
	var a Account
	var enabled int
	now := time.Now().Unix()
	err := db.QueryRow(`
		SELECT a.id, a.name, a.email, a.user_id, a.encrypted_access_token, a.encrypted_refresh_token, a.expires_at, a.oidc_client_id, a.enabled, a.auth_status, a.failure_count, a.cooldown_until, a.last_used_at
		FROM accounts a
		WHERE a.enabled=1 AND a.auth_status='active'
		AND a.cooldown_until <= ?
		AND EXISTS (SELECT 1 FROM account_model_capabilities c WHERE c.account_id=a.id AND c.upstream_model=?)
		ORDER BY a.last_used_at ASC, a.id ASC
		LIMIT 1`, now, upstreamModel).
		Scan(&a.ID, &a.Name, &a.Email, &a.UserID, &a.EncryptedAccessToken, &a.EncryptedRefreshToken, &a.ExpiresAt, &a.OIDCClientID, &enabled, &a.AuthStatus, &a.FailureCount, &a.CooldownUntil, &a.LastUsedAt)
	if err != nil {
		return nil, err
	}
	a.Enabled = enabled == 1
	return &a, nil
}

func (db *DB) MarkAccountUsed(id int64) error {
	_, err := db.Exec("UPDATE accounts SET last_used_at=unixepoch(), updated_at=unixepoch() WHERE id=?", id)
	return err
}

func (db *DB) MarkAccountFailed(id int64, cooldownSeconds int64) error {
	if cooldownSeconds <= 0 {
		cooldownSeconds = 300 // default 5 min
	}
	_, err := db.Exec("UPDATE accounts SET failure_count=failure_count+1, cooldown_until=unixepoch()+?, updated_at=unixepoch() WHERE id=?", cooldownSeconds, id)
	return err
}

func (db *DB) MarkAccountSuccess(id int64) error {
	_, err := db.Exec("UPDATE accounts SET failure_count=0, cooldown_until=0, last_used_at=unixepoch(), updated_at=unixepoch() WHERE id=?", id)
	return err
}

func (db *DB) CountActiveAccountsForModel(upstreamModel string) (int, error) {
	var count int
	now := time.Now().Unix()
	err := db.QueryRow(`
		SELECT COUNT(*) FROM accounts a
		WHERE a.enabled=1 AND a.auth_status='active'
		AND a.cooldown_until <= ?
		AND EXISTS (SELECT 1 FROM account_model_capabilities c WHERE c.account_id=a.id AND c.upstream_model=?)`, now, upstreamModel).Scan(&count)
	return count, err
}
