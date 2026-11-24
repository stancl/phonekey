// Package store is phonekeyd's SQLite persistence.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"phonekey/internal/protocol"
	"phonekey/internal/sshwire"
)

var ErrNotFound = errors.New("not found")

// ErrLastKey is returned when removing the only registered key, which would
// leave no way to log in without a new pairing code.
var ErrLastKey = errors.New("can't remove the last key")

// ErrNotPending is returned when resolving a request or an enrollment that's
// already resolved.
var ErrNotPending = errors.New("request is not pending")

// ErrTooManyEnrollments is returned by CreateEnrollment when too many were
// asked for lately.
var ErrTooManyEnrollments = errors.New("too many dev box enrollments lately; try again in a few minutes")

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
	id            INTEGER PRIMARY KEY,
	public_key    TEXT NOT NULL UNIQUE,
	fingerprint   TEXT NOT NULL,
	label         TEXT NOT NULL,
	credential_id TEXT NOT NULL DEFAULT '',
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devboxes (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL UNIQUE,
	token_hash   TEXT NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER
);
CREATE TABLE IF NOT EXISTS enrollments (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	host        TEXT NOT NULL,
	user        TEXT NOT NULL,
	token_hash  TEXT NOT NULL UNIQUE,
	code        TEXT NOT NULL,
	status      TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS pair_codes (
	code_hash  TEXT PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
	nonce      TEXT PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	key_id     INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS push_subscriptions (
	id           INTEGER PRIMARY KEY,
	endpoint     TEXT NOT NULL UNIQUE,
	subscription TEXT NOT NULL,
	key_id       INTEGER REFERENCES keys(id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
	id          TEXT PRIMARY KEY,
	devbox_id   INTEGER NOT NULL REFERENCES devboxes(id) ON DELETE CASCADE,
	public_key  TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	kind        TEXT NOT NULL,
	data        BLOB NOT NULL,
	details     TEXT NOT NULL,
	context     TEXT NOT NULL,
	summary     TEXT NOT NULL,
	status      TEXT NOT NULL,
	signature   BLOB,
	via_grant   INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS requests_status ON requests(status, expires_at);
`

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

// RandomToken returns n random bytes, base32-encoded without padding.
func RandomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Settings

func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Keys

type Key = protocol.WebKey

func (s *Store) AddKey(ctx context.Context, publicKey, fingerprint, label, credentialID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO keys(public_key, fingerprint, label, credential_id, created_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(public_key) DO UPDATE SET label = excluded.label, credential_id = excluded.credential_id`,
		publicKey, fingerprint, label, credentialID, now())
	if err != nil {
		return 0, err
	}
	if id, err := res.LastInsertId(); err == nil && id != 0 {
		return id, nil
	}
	k, err := s.KeyByPublicKey(ctx, publicKey)
	if err != nil {
		return 0, err
	}
	return k.ID, nil
}

const keyCols = `id, public_key, fingerprint, label, credential_id, created_at`

func scanKey(row interface{ Scan(...any) error }) (*Key, error) {
	var k Key
	err := row.Scan(&k.ID, &k.PublicKey, &k.Fingerprint, &k.Label, &k.CredentialID, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &k, err
}

func (s *Store) KeyByPublicKey(ctx context.Context, publicKey string) (*Key, error) {
	return scanKey(s.db.QueryRowContext(ctx, `SELECT `+keyCols+` FROM keys WHERE public_key = ?`, publicKey))
}

// Keys returns all registered keys with what each one has opened.
func (s *Store) Keys(ctx context.Context) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+keyCols+`,
		(SELECT count(*) FROM sessions WHERE key_id = keys.id AND expires_at > ?),
		(SELECT count(*) FROM push_subscriptions WHERE key_id = keys.id)
		FROM keys ORDER BY id`, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.ID, &k.PublicKey, &k.Fingerprint, &k.Label, &k.CredentialID, &k.CreatedAt,
			&k.Logins, &k.Notified); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RemoveKey revokes a key, given its fingerprint or id: the sessions opened
// with it and the push subscriptions made from them go with it (foreign
// keys), and its pending requests are denied. The last key can't be removed.
func (s *Store) RemoveKey(ctx context.Context, ref string) (*Key, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	k, err := scanKey(tx.QueryRowContext(ctx, `SELECT `+keyCols+` FROM keys WHERE fingerprint = ? OR CAST(id AS TEXT) = ?`, ref, ref))
	if err != nil {
		return nil, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keys`).Scan(&count); err != nil {
		return nil, err
	}
	if count <= 1 {
		return nil, ErrLastKey
	}
	if _, err := tx.ExecContext(ctx, `UPDATE requests SET status = ?, resolved_at = ? WHERE public_key = ? AND status = ?`,
		protocol.StatusDenied, now(), k.PublicKey, protocol.StatusPending); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM keys WHERE id = ?`, k.ID); err != nil {
		return nil, err
	}
	return k, tx.Commit()
}

// Dev boxes

type Devbox struct {
	ID         int64
	Name       string
	CreatedAt  int64
	LastSeenAt sql.NullInt64
}

func newDevboxToken() string {
	return "pkd_" + RandomToken(24)
}

// AddDevbox registers a dev box and returns its bearer token.
func (s *Store) AddDevbox(ctx context.Context, name string) (string, error) {
	token := newDevboxToken()
	_, err := s.db.ExecContext(ctx, `INSERT INTO devboxes(name, token_hash, created_at) VALUES(?, ?, ?)`,
		name, hash(token), now())
	return token, err
}

func (s *Store) DevboxByToken(ctx context.Context, token string) (*Devbox, error) {
	var d Devbox
	err := s.db.QueryRowContext(ctx, `SELECT id, name, created_at, last_seen_at FROM devboxes WHERE token_hash = ?`,
		hash(token)).Scan(&d.ID, &d.Name, &d.CreatedAt, &d.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.db.ExecContext(ctx, `UPDATE devboxes SET last_seen_at = ? WHERE id = ?`, now(), d.ID)
	return &d, nil
}

func (s *Store) Devboxes(ctx context.Context) ([]Devbox, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, last_seen_at FROM devboxes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Devbox
	for rows.Next() {
		var d Devbox
		if err := rows.Scan(&d.ID, &d.Name, &d.CreatedAt, &d.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RemoveDevbox(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM devboxes WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Enrollments

type Enrollment struct {
	protocol.WebEnrollment
	Status string
}

// CreateEnrollment records a dev box asking to be registered. The returned
// token only works once the enrollment is approved. It fails with
// ErrTooManyEnrollments if max were asked for within the last ttl, however
// they ended.
func (s *Store) CreateEnrollment(ctx context.Context, req protocol.EnrollRequest, ttl time.Duration, max int) (*protocol.EnrollResponse, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var recent int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM enrollments WHERE created_at > ?`,
		time.Now().Add(-ttl).Unix()).Scan(&recent); err != nil {
		return nil, err
	}
	if recent >= max {
		return nil, ErrTooManyEnrollments
	}
	code := strings.ToUpper(RandomToken(5))
	resp := &protocol.EnrollResponse{
		ID:        RandomToken(16),
		Token:     newDevboxToken(),
		Code:      code[:4] + "-" + code[4:],
		ExpiresAt: time.Now().Add(ttl).Unix(),
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollments
		(id, name, host, user, token_hash, code, status, created_at, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		resp.ID, req.Name, req.Host, req.User, hash(resp.Token), resp.Code, protocol.StatusPending, now(), resp.ExpiresAt); err != nil {
		return nil, err
	}
	return resp, tx.Commit()
}

const enrollmentCols = `id, name, host, user, code, status, created_at, expires_at,
	EXISTS(SELECT 1 FROM devboxes WHERE devboxes.name = enrollments.name)`

func scanEnrollment(row interface{ Scan(...any) error }) (*Enrollment, error) {
	var e Enrollment
	err := row.Scan(&e.ID, &e.Name, &e.Host, &e.User, &e.Code, &e.Status, &e.CreatedAt, &e.ExpiresAt, &e.Replaces)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &e, err
}

func (s *Store) Enrollment(ctx context.Context, id string) (*Enrollment, error) {
	return scanEnrollment(s.db.QueryRowContext(ctx, `SELECT `+enrollmentCols+` FROM enrollments WHERE id = ?`, id))
}

// EnrollmentByToken returns the enrollment that handed out token.
func (s *Store) EnrollmentByToken(ctx context.Context, token string) (*Enrollment, error) {
	return scanEnrollment(s.db.QueryRowContext(ctx, `SELECT `+enrollmentCols+` FROM enrollments WHERE token_hash = ?`, hash(token)))
}

// PendingEnrollments returns live enrollments, oldest first.
func (s *Store) PendingEnrollments(ctx context.Context) ([]Enrollment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+enrollmentCols+` FROM enrollments
		WHERE status = ? AND expires_at > ? ORDER BY created_at, rowid`, protocol.StatusPending, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Enrollment
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// ResolveEnrollment moves a live pending enrollment to status. Approving it
// registers the dev box with the enrollment's token, or gives a registered
// dev box of the same name that token instead of its old one.
func (s *Store) ResolveEnrollment(ctx context.Context, id, status string) (*Enrollment, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	e, err := scanEnrollment(tx.QueryRowContext(ctx, `SELECT `+enrollmentCols+` FROM enrollments WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE enrollments SET status = ?, resolved_at = ?
		WHERE id = ? AND status = ? AND expires_at > ?`, status, now(), id, protocol.StatusPending, now())
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotPending
	}
	if status == protocol.StatusApproved {
		if _, err := tx.ExecContext(ctx, `INSERT INTO devboxes(name, token_hash, created_at)
			SELECT name, token_hash, ? FROM enrollments WHERE id = ?
			ON CONFLICT(name) DO UPDATE SET token_hash = excluded.token_hash`, now(), id); err != nil {
			return nil, err
		}
	}
	e.Status = status
	return e, tx.Commit()
}

// Pairing codes and nonces

// NewPairCode creates a one-time code that lets a page register a key.
func (s *Store) NewPairCode(ctx context.Context, ttl time.Duration) (string, error) {
	code := RandomToken(10)
	_, err := s.db.ExecContext(ctx, `INSERT INTO pair_codes(code_hash, expires_at) VALUES(?, ?)`,
		hash(code), time.Now().Add(ttl).Unix())
	return code, err
}

// ConsumePairCode deletes the code and reports whether it was valid.
func (s *Store) ConsumePairCode(ctx context.Context, code string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pair_codes WHERE code_hash = ? AND expires_at > ?`,
		hash(strings.ToLower(strings.TrimSpace(code))), now())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Store) NewNonce(ctx context.Context, ttl time.Duration) (string, error) {
	n := RandomToken(20)
	_, err := s.db.ExecContext(ctx, `INSERT INTO nonces(nonce, expires_at) VALUES(?, ?)`, n, time.Now().Add(ttl).Unix())
	return n, err
}

func (s *Store) ConsumeNonce(ctx context.Context, nonce string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nonces WHERE nonce = ? AND expires_at > ?`, nonce, now())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Sessions

func (s *Store) NewSession(ctx context.Context, keyID int64, ttl time.Duration) (string, error) {
	token := RandomToken(32)
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, key_id, created_at, expires_at) VALUES(?, ?, ?, ?)`,
		hash(token), keyID, now(), time.Now().Add(ttl).Unix())
	return token, err
}

// SessionKey returns the key id a session token belongs to.
func (s *Store) SessionKey(ctx context.Context, token string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT key_id FROM sessions WHERE token_hash = ? AND expires_at > ?`,
		hash(token), now()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash(token))
	return err
}

// Push subscriptions

type PushSubscription struct {
	ID           int64
	Endpoint     string
	Subscription string // JSON as produced by PushSubscription.toJSON()
}

func (s *Store) SavePushSubscription(ctx context.Context, endpoint, subscription string, keyID int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO push_subscriptions(endpoint, subscription, key_id, created_at)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(endpoint) DO UPDATE SET subscription = excluded.subscription, key_id = excluded.key_id`,
		endpoint, subscription, keyID, now())
	return err
}

func (s *Store) PushSubscriptions(ctx context.Context) ([]PushSubscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, endpoint, subscription FROM push_subscriptions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushSubscription
	for rows.Next() {
		var p PushSubscription
		if err := rows.Scan(&p.ID, &p.Endpoint, &p.Subscription); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeletePushSubscription(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE id = ?`, id)
	return err
}

// Requests

type Request struct {
	protocol.WebRequest
	DevboxID  int64
	Signature []byte
	ViaGrant  bool
}

type NewRequest struct {
	DevboxID    int64
	PublicKey   string
	Fingerprint string
	Data        []byte
	Details     sshwire.Details
	Context     protocol.Context
	Summary     string
	ExpiresAt   time.Time
}

func (s *Store) CreateRequest(ctx context.Context, r NewRequest) (string, error) {
	id := RandomToken(16)
	details, _ := json.Marshal(r.Details)
	rc, _ := json.Marshal(r.Context)
	_, err := s.db.ExecContext(ctx, `INSERT INTO requests
		(id, devbox_id, public_key, fingerprint, kind, data, details, context, summary, status, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, r.DevboxID, r.PublicKey, r.Fingerprint, r.Details.Kind, r.Data, string(details), string(rc), r.Summary,
		protocol.StatusPending, now(), r.ExpiresAt.Unix())
	return id, err
}

const requestCols = `r.id, r.devbox_id, d.name, r.public_key, r.fingerprint, r.data, r.details, r.context, r.summary,
	r.status, r.signature, r.via_grant, r.created_at, r.expires_at`

func scanRequest(row interface{ Scan(...any) error }) (*Request, error) {
	var r Request
	var details, rc string
	err := row.Scan(&r.ID, &r.DevboxID, &r.Devbox, &r.PublicKey, &r.Fingerprint, &r.Data, &details, &rc, &r.Summary,
		&r.Status, &r.Signature, &r.ViaGrant, &r.CreatedAt, &r.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(details), &r.Details)
	json.Unmarshal([]byte(rc), &r.Context)
	return &r, nil
}

func (s *Store) Request(ctx context.Context, id string) (*Request, error) {
	return scanRequest(s.db.QueryRowContext(ctx, `SELECT `+requestCols+`
		FROM requests r JOIN devboxes d ON d.id = r.devbox_id WHERE r.id = ?`, id))
}

// SignedInScopeSince reports whether a request with the given context scope
// was signed at or after since.
func (s *Store) SignedInScopeSince(ctx context.Context, scope string, since time.Time) (bool, error) {
	var found bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM requests
		WHERE status = ? AND resolved_at >= ? AND json_extract(context, '$.scope') = ?)`,
		protocol.StatusSigned, since.Unix(), scope).Scan(&found)
	return found, err
}

// PendingRequests returns live requests, oldest first.
func (s *Store) PendingRequests(ctx context.Context) ([]Request, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+requestCols+`
		FROM requests r JOIN devboxes d ON d.id = r.devbox_id
		WHERE r.status = ? AND r.expires_at > ? ORDER BY r.created_at, r.rowid`, protocol.StatusPending, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// Resolve moves a live pending request to status, optionally storing a
// signature. It fails with ErrNotPending if the request was resolved or
// expired in the meantime.
func (s *Store) Resolve(ctx context.Context, id, status string, signature []byte, viaGrant bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE requests SET status = ?, signature = ?, via_grant = ?, resolved_at = ?
		WHERE id = ? AND status = ? AND expires_at > ?`,
		status, signature, viaGrant, now(), id, protocol.StatusPending, now())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.Request(ctx, id); err != nil {
			return err
		}
		return ErrNotPending
	}
	return nil
}

// Sweep marks overdue requests expired and deletes old rows. It reports
// whether anything changed state.
func (s *Store) Sweep(ctx context.Context, retention time.Duration) (bool, error) {
	t := now()
	res, err := s.db.ExecContext(ctx, `UPDATE requests SET status = ?, resolved_at = ?
		WHERE status = ? AND expires_at <= ?`, protocol.StatusExpired, t, protocol.StatusPending, t)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	cutoff := time.Now().Add(-retention).Unix()
	for _, d := range []struct {
		query string
		arg   int64
	}{
		{`DELETE FROM requests WHERE status != 'pending' AND resolved_at < ?`, cutoff},
		{`DELETE FROM enrollments WHERE expires_at < ?`, cutoff},
		{`DELETE FROM nonces WHERE expires_at < ?`, t},
		{`DELETE FROM pair_codes WHERE expires_at < ?`, t},
		{`DELETE FROM sessions WHERE expires_at < ?`, t},
	} {
		if _, err := s.db.ExecContext(ctx, d.query, d.arg); err != nil {
			return n > 0, err
		}
	}
	return n > 0, nil
}

// History returns the most recent resolved requests, newest first.
func (s *Store) History(ctx context.Context, limit int) ([]Request, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+requestCols+`
		FROM requests r JOIN devboxes d ON d.id = r.devbox_id
		WHERE r.status != 'pending' ORDER BY r.resolved_at DESC, r.rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}
