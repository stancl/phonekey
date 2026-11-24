// Package server implements phonekeyd: the request queue, the dev box and
// web APIs, push delivery and the embedded approval web app.
package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"phonekey/internal/keyderive"
	"phonekey/internal/protocol"
	"phonekey/internal/sshwire"
	"phonekey/internal/store"
	"phonekey/web"
)

type Config struct {
	RPName string
	// Salt is the PRF salt. Bump the version suffix to rotate keys without a
	// new passkey.
	Salt         string
	VAPIDSubject string

	DefaultTTL time.Duration
	MaxTTL     time.Duration
	SessionTTL time.Duration
	Retention  time.Duration
	MaxGrant   time.Duration
	// EnrollTTL is how long a dev box's enrollment waits for approval.
	EnrollTTL time.Duration
	// MaxEnrollments caps the enrollments asked for within EnrollTTL.
	// Anyone who can reach phonekeyd can ask, and each sends a push.
	MaxEnrollments int
	// PushHoldBack is how long a new request waits before its push when the
	// page may hold a grant that will sign it right away.
	PushHoldBack time.Duration

	// AllowUnknownKinds lets dev boxes queue data that's neither an SSH
	// userauth payload nor an SSHSIG blob.
	AllowUnknownKinds bool

	// Origins are extra origins accepted for state-changing web API calls
	// from browsers that don't send Sec-Fetch-Site.
	Origins []string

	PushClient *http.Client
	Logger     *slog.Logger
}

func (c *Config) defaults() {
	if c.RPName == "" {
		c.RPName = "phonekey"
	}
	if c.Salt == "" {
		c.Salt = keyderive.DefaultSalt
	}
	if c.VAPIDSubject == "" {
		c.VAPIDSubject = "phonekey@example.com"
	}
	if c.DefaultTTL == 0 {
		c.DefaultTTL = 90 * time.Second
	}
	if c.MaxTTL == 0 {
		c.MaxTTL = 5 * time.Minute
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 30 * 24 * time.Hour
	}
	if c.Retention == 0 {
		c.Retention = 7 * 24 * time.Hour
	}
	if c.EnrollTTL == 0 {
		c.EnrollTTL = 5 * time.Minute
	}
	if c.MaxEnrollments == 0 {
		c.MaxEnrollments = 3
	}
	if c.PushHoldBack == 0 {
		c.PushHoldBack = 2 * time.Second
	}
	if c.PushClient == nil {
		c.PushClient = &http.Client{Timeout: 20 * time.Second}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

type Server struct {
	cfg    Config
	store  *store.Store
	log    *slog.Logger
	push   *pusher
	vapid  string
	events *broker
	mux    *http.ServeMux
}

// broker wakes long-polls and event streams whenever any request changes.
type broker struct {
	mu sync.Mutex
	ch chan struct{}
}

func (b *broker) wait() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ch == nil {
		b.ch = make(chan struct{})
	}
	return b.ch
}

func (b *broker) notify() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ch != nil {
		close(b.ch)
		b.ch = nil
	}
}

func New(ctx context.Context, st *store.Store, cfg Config) (*Server, error) {
	cfg.defaults()
	pub, priv, err := loadVAPID(ctx, st)
	if err != nil {
		return nil, fmt.Errorf("vapid keys: %w", err)
	}
	s := &Server{
		cfg:    cfg,
		store:  st,
		log:    cfg.Logger,
		vapid:  pub,
		events: &broker{},
		mux:    http.NewServeMux(),
		push: &pusher{
			store: st, log: cfg.Logger, subject: cfg.VAPIDSubject,
			public: pub, private: priv, client: cfg.PushClient,
		},
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("POST /api/devbox/requests", s.devbox(s.createRequest))
	m.HandleFunc("GET /api/devbox/requests/{id}", s.devbox(s.pollRequest))
	m.HandleFunc("DELETE /api/devbox/requests/{id}", s.devbox(s.cancelRequest))
	m.HandleFunc("GET /api/devbox/keys", s.devbox(s.devboxKeys))
	m.HandleFunc("POST /api/devbox/enroll", s.enroll)
	m.HandleFunc("GET /api/devbox/enroll", s.enrollment(s.pollEnrollment))
	m.HandleFunc("DELETE /api/devbox/enroll", s.enrollment(s.cancelEnrollment))

	m.HandleFunc("GET /api/web/config", s.webConfig)
	m.HandleFunc("POST /api/web/nonce", s.sameOrigin(s.nonce))
	m.HandleFunc("POST /api/web/login", s.sameOrigin(s.login))
	m.HandleFunc("POST /api/web/pair", s.sameOrigin(s.pair))
	m.HandleFunc("POST /api/web/logout", s.sameOrigin(s.logout))
	m.HandleFunc("GET /api/web/requests", s.session(s.listRequests))
	m.HandleFunc("GET /api/web/history", s.session(s.history))
	m.HandleFunc("GET /api/web/events", s.session(s.eventStream))
	m.HandleFunc("POST /api/web/requests/{id}/signature", s.sameOrigin(s.session(s.submitSignature)))
	m.HandleFunc("POST /api/web/requests/{id}/deny", s.sameOrigin(s.session(s.denyRequest)))
	m.HandleFunc("DELETE /api/web/keys/{id}", s.sameOrigin(s.session(s.removeKey)))
	m.HandleFunc("GET /api/web/devboxes", s.session(s.listDevboxes))
	m.HandleFunc("DELETE /api/web/devboxes/{id}", s.sameOrigin(s.session(s.removeDevbox)))
	m.HandleFunc("GET /api/web/enrollments", s.session(s.listEnrollments))
	m.HandleFunc("POST /api/web/enrollments/{id}/approve", s.sameOrigin(s.session(s.approveEnrollment)))
	m.HandleFunc("POST /api/web/enrollments/{id}/deny", s.sameOrigin(s.session(s.denyEnrollment)))
	m.HandleFunc("POST /api/web/push/subscribe", s.sameOrigin(s.session(s.subscribe)))
	m.HandleFunc("POST /api/web/push/test", s.sameOrigin(s.session(s.testPush)))

	static, _ := fs.Sub(web.FS, ".")
	files := http.FileServerFS(static)
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".webmanifest") {
			w.Header().Set("Content-Type", "application/manifest+json")
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	s.mux.ServeHTTP(w, r)
}

// Sweep runs the expiry sweeper until ctx is done.
func (s *Server) Sweep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := s.store.Sweep(ctx, s.cfg.Retention)
			if err != nil {
				s.log.Error("sweep", "err", err)
			}
			if changed {
				s.events.notify()
			}
		}
	}
}

// Helpers

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

func errorf(code int, format string, args ...any) error {
	return httpError{code, fmt.Sprintf(format, args...)}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var he httpError
	switch {
	case errors.As(err, &he):
	case errors.Is(err, store.ErrNotFound):
		he = httpError{http.StatusNotFound, "not found"}
	case errors.Is(err, store.ErrNotPending):
		he = httpError{http.StatusConflict, "request is no longer pending"}
	default:
		s.log.Error("request failed", "path", r.URL.Path, "err", err)
		he = httpError{http.StatusInternalServerError, "internal error"}
	}
	writeJSON(w, he.code, map[string]string{"error": he.msg})
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errorf(http.StatusBadRequest, "bad json: %v", err)
	}
	return nil
}

func parseEd25519(authorized string) (ssh.PublicKey, ed25519.PublicKey, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return nil, nil, errorf(http.StatusBadRequest, "bad public key: %v", err)
	}
	ck, ok := k.(ssh.CryptoPublicKey)
	if !ok || k.Type() != ssh.KeyAlgoED25519 {
		return nil, nil, errorf(http.StatusBadRequest, "only ssh-ed25519 keys are supported")
	}
	return k, ck.CryptoPublicKey().(ed25519.PublicKey), nil
}

// normalizeKey drops any comment from an authorized_keys line.
func normalizeKey(k ssh.PublicKey) string {
	b := ssh.MarshalAuthorizedKey(k)
	return strings.TrimSpace(string(b))
}

// Dev box API

func bearer(r *http.Request) (string, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return "", errorf(http.StatusUnauthorized, "missing bearer token")
	}
	return token, nil
}

func (s *Server) devbox(h func(http.ResponseWriter, *http.Request, *store.Devbox)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := bearer(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d, err := s.store.DevboxByToken(r.Context(), token)
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, errorf(http.StatusUnauthorized, "unknown dev box token"))
			return
		} else if err != nil {
			s.fail(w, r, err)
			return
		}
		h(w, r, d)
	}
}

func (s *Server) createRequest(w http.ResponseWriter, r *http.Request, d *store.Devbox) {
	var req protocol.CreateRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	k, _, err := parseEd25519(req.PublicKey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pk := normalizeKey(k)
	if _, err := s.store.KeyByPublicKey(r.Context(), pk); errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, errorf(http.StatusBadRequest, "key %s is not registered", ssh.FingerprintSHA256(k)))
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	details := sshwire.Parse(req.Data)
	if details.Kind == sshwire.KindUnknown && !s.cfg.AllowUnknownKinds {
		s.fail(w, r, errorf(http.StatusBadRequest, "data is neither an SSH userauth request nor an SSHSIG blob"))
		return
	}
	if details.Kind == sshwire.KindUserauth && details.KeyFingerprint != ssh.FingerprintSHA256(k) {
		s.fail(w, r, errorf(http.StatusBadRequest, "userauth request is for a different key"))
		return
	}
	ttl := s.cfg.DefaultTTL
	if req.TTLSeconds > 0 {
		ttl = min(time.Duration(req.TTLSeconds)*time.Second, s.cfg.MaxTTL)
	}
	// Round up: expiry is stored in whole seconds and mustn't come before
	// the agent's own deadline.
	expires := time.Now().Add(ttl).Truncate(time.Second).Add(time.Second)
	summary := summarize(details, req.Context)
	id, err := s.store.CreateRequest(r.Context(), store.NewRequest{
		DevboxID:    d.ID,
		PublicKey:   pk,
		Fingerprint: ssh.FingerprintSHA256(k),
		Data:        req.Data,
		Details:     details,
		Context:     req.Context,
		Summary:     summary,
		ExpiresAt:   expires,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("request created", "id", id, "devbox", d.Name, "kind", details.Kind, "summary", summary)
	s.events.notify()
	go s.notify(context.WithoutCancel(r.Context()), id, req.Context.Scope, PushMessage{ID: id, Title: d.Name, Body: summary})
	writeJSON(w, http.StatusCreated, protocol.CreateResponse{ID: id, ExpiresAt: expires.Unix()})
}

// notify pushes a new request. If a request from the same command was
// signed recently enough that the page may still hold a grant for it, the
// push waits briefly and is dropped if the grant signed the request.
func (s *Server) notify(ctx context.Context, id, scope string, msg PushMessage) {
	if scope != "" && s.cfg.MaxGrant > 0 {
		recent, err := s.store.SignedInScopeSince(ctx, scope, time.Now().Add(-s.cfg.MaxGrant))
		if err != nil {
			s.log.Error("push: checking scope", "err", err)
		}
		if recent {
			time.Sleep(s.cfg.PushHoldBack)
			if req, err := s.store.Request(ctx, id); err == nil && req.Status != protocol.StatusPending {
				return
			}
		}
	}
	s.push.send(ctx, msg)
}

func effectiveStatus(status string, expiresAt int64) string {
	if status == protocol.StatusPending && expiresAt <= time.Now().Unix() {
		return protocol.StatusExpired
	}
	return status
}

// longPoll answers with what state returns once that's no longer pending, or
// with the pending state after ?wait=N seconds. It asks state again whenever
// anything changes, and when the pending state expires.
func (s *Server) longPoll(w http.ResponseWriter, r *http.Request, state func() (*protocol.RequestState, int64, error)) {
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	deadline := time.After(time.Duration(min(max(wait, 0), 60)) * time.Second)
	for {
		changed := s.events.wait()
		st, expiresAt, err := state()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if st.Status != protocol.StatusPending {
			writeJSON(w, http.StatusOK, st)
			return
		}
		expiry := time.Until(time.Unix(expiresAt, 0)) + 100*time.Millisecond
		select {
		case <-changed:
		case <-time.After(expiry):
		case <-deadline:
			writeJSON(w, http.StatusOK, st)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) pollRequest(w http.ResponseWriter, r *http.Request, d *store.Devbox) {
	id := r.PathValue("id")
	s.longPoll(w, r, func() (*protocol.RequestState, int64, error) {
		req, err := s.store.Request(r.Context(), id)
		if err == nil && req.DevboxID != d.ID {
			err = store.ErrNotFound
		}
		if err != nil {
			return nil, 0, err
		}
		status := effectiveStatus(req.Status, req.ExpiresAt)
		return &protocol.RequestState{ID: id, Status: status, Signature: req.Signature}, req.ExpiresAt, nil
	})
}

func (s *Server) cancelRequest(w http.ResponseWriter, r *http.Request, d *store.Devbox) {
	id := r.PathValue("id")
	req, err := s.store.Request(r.Context(), id)
	if err == nil && req.DevboxID != d.ID {
		err = store.ErrNotFound
	}
	if err == nil {
		err = s.store.Resolve(r.Context(), id, protocol.StatusCancelled, nil, false)
	}
	if err != nil && !errors.Is(err, store.ErrNotPending) {
		s.fail(w, r, err)
		return
	}
	s.events.notify()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) devboxKeys(w http.ResponseWriter, r *http.Request, d *store.Devbox) {
	keys, err := s.store.Keys(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, k := range keys {
		fmt.Fprintf(w, "%s %s\n", k.PublicKey, strings.ReplaceAll(protocol.CleanLabel(k.Label), " ", "_"))
	}
}

// devboxName is what an enrolling dev box may call itself: a hostname's
// characters, so a name can't pass for anything else on the card, such as a
// second code.
var devboxName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// enroll lets a dev box ask to be registered, without a token. The page
// shows the request with a code the dev box shows too, and approving it
// takes a passkey.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	// A web page can only send JSON to another origin after a CORS
	// preflight, which phonekeyd doesn't allow, so this keeps any site a
	// browser on the tailnet opens from asking.
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		s.fail(w, r, errorf(http.StatusUnsupportedMediaType, "expected application/json"))
		return
	}
	var req protocol.EnrollRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !devboxName.MatchString(req.Name) {
		s.fail(w, r, errorf(http.StatusBadRequest, "the dev box name must be 1 to 64 letters, digits, dots, dashes or underscores"))
		return
	}
	req.Host = truncate(protocol.CleanLabel(req.Host), 64)
	req.User = truncate(protocol.CleanLabel(req.User), 64)
	resp, err := s.store.CreateEnrollment(r.Context(), req, s.cfg.EnrollTTL, s.cfg.MaxEnrollments)
	if errors.Is(err, store.ErrTooManyEnrollments) {
		s.fail(w, r, errorf(http.StatusTooManyRequests, "%v", err))
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	e, err := s.store.Enrollment(r.Context(), resp.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("dev box enrollment requested", "id", e.ID, "name", e.Name, "host", e.Host, "code", e.Code, "replaces", e.Replaces)
	s.events.notify()
	title := "Add a dev box?"
	if e.Replaces {
		title = "Replace a dev box?"
	}
	go s.push.send(context.WithoutCancel(r.Context()), PushMessage{
		ID: e.ID, Title: title, Body: fmt.Sprintf("%s, code %s", e.Name, e.Code),
	})
	writeJSON(w, http.StatusCreated, resp)
}

// enrollment authenticates a dev box by the token its enrollment handed
// out, approved or not.
func (s *Server) enrollment(h func(http.ResponseWriter, *http.Request, *store.Enrollment)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := bearer(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		e, err := s.store.EnrollmentByToken(r.Context(), token)
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, errorf(http.StatusUnauthorized, "unknown enrollment token"))
			return
		} else if err != nil {
			s.fail(w, r, err)
			return
		}
		h(w, r, e)
	}
}

func (s *Server) pollEnrollment(w http.ResponseWriter, r *http.Request, e *store.Enrollment) {
	s.longPoll(w, r, func() (*protocol.RequestState, int64, error) {
		cur, err := s.store.Enrollment(r.Context(), e.ID)
		if err != nil {
			return nil, 0, err
		}
		return &protocol.RequestState{ID: cur.ID, Status: effectiveStatus(cur.Status, cur.ExpiresAt)}, cur.ExpiresAt, nil
	})
}

// cancelEnrollment withdraws a pending enrollment and answers with how the
// enrollment ended, which may be an approval that came first.
func (s *Server) cancelEnrollment(w http.ResponseWriter, r *http.Request, e *store.Enrollment) {
	if _, err := s.store.ResolveEnrollment(r.Context(), e.ID, protocol.StatusCancelled); err != nil && !errors.Is(err, store.ErrNotPending) {
		s.fail(w, r, err)
		return
	}
	s.events.notify()
	cur, err := s.store.Enrollment(r.Context(), e.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.RequestState{ID: cur.ID, Status: effectiveStatus(cur.Status, cur.ExpiresAt)})
}

// Web API

const sessionCookie = "phonekey_session"

// sameOrigin rejects cross-site state-changing requests. Browsers that send
// Sec-Fetch-Site are trusted on it; otherwise the Origin header must match.
func (s *Server) sameOrigin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
			if site != "same-origin" {
				s.fail(w, r, errorf(http.StatusForbidden, "cross-site request"))
				return
			}
			h(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		u, err := url.Parse(origin)
		if origin == "" || err != nil {
			s.fail(w, r, errorf(http.StatusForbidden, "missing origin"))
			return
		}
		ok := u.Host == r.Host || (r.Header.Get("X-Forwarded-Host") != "" && u.Host == r.Header.Get("X-Forwarded-Host"))
		for _, o := range s.cfg.Origins {
			ok = ok || o == origin
		}
		if !ok {
			s.fail(w, r, errorf(http.StatusForbidden, "origin %s not allowed", origin))
			return
		}
		h(w, r)
	}
}

type keyIDCtx struct{}

func (s *Server) sessionKeyID(r *http.Request) (int64, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return 0, false
	}
	id, err := s.store.SessionKey(r.Context(), c.Value)
	return id, err == nil
}

func (s *Server) session(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.sessionKeyID(r)
		if !ok {
			s.fail(w, r, errorf(http.StatusUnauthorized, "not logged in"))
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), keyIDCtx{}, id)))
	}
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, keyID int64) error {
	token, err := s.store.NewSession(r.Context(), keyID, s.cfg.SessionTTL)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		MaxAge: int(s.cfg.SessionTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (s *Server) webConfig(w http.ResponseWriter, r *http.Request) {
	c := protocol.WebConfig{
		RPName:          s.cfg.RPName,
		Salt:            s.cfg.Salt,
		HKDFInfo:        keyderive.HKDFInfo,
		VAPIDPublicKey:  s.vapid,
		MaxGrantSeconds: int(s.cfg.MaxGrant.Seconds()),
	}
	if current, ok := s.sessionKeyID(r); ok {
		c.LoggedIn = true
		keys, err := s.store.Keys(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for i := range keys {
			keys[i].Current = keys[i].ID == current
		}
		c.Keys = keys
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) nonce(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.NewNonce(r.Context(), 5*time.Minute)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.NonceResponse{Nonce: n})
}

// checkAuth verifies a nonce signature and returns the normalized key.
func (s *Server) checkAuth(r *http.Request, publicKey, nonce string, sig []byte) (ssh.PublicKey, error) {
	k, pub, err := parseEd25519(publicKey)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, protocol.AuthMessage(nonce), sig) {
		return nil, errorf(http.StatusUnauthorized, "signature does not verify")
	}
	ok, err := s.store.ConsumeNonce(r.Context(), nonce)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errorf(http.StatusUnauthorized, "nonce expired or already used")
	}
	return k, nil
}

// checkApproval requires a fresh signature from a registered key, so a
// session cookie alone can't change which keys are registered.
func (s *Server) checkApproval(r *http.Request, a *protocol.Approval) error {
	if a == nil {
		return errorf(http.StatusForbidden, "this needs approval with a registered passkey")
	}
	k, err := s.checkAuth(r, a.PublicKey, a.Nonce, a.Signature)
	if err != nil {
		return err
	}
	if _, err := s.store.KeyByPublicKey(r.Context(), normalizeKey(k)); errors.Is(err, store.ErrNotFound) {
		return errorf(http.StatusForbidden, "the approving key isn't registered")
	} else if err != nil {
		return err
	}
	return nil
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req protocol.LoginRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	k, err := s.checkAuth(r, req.PublicKey, req.Nonce, req.Signature)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	key, err := s.store.KeyByPublicKey(r.Context(), normalizeKey(k))
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, errorf(http.StatusUnauthorized, "key %s is not registered; pair it first", ssh.FingerprintSHA256(k)))
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.setSession(w, r, key.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	var req protocol.PairRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	k, err := s.checkAuth(r, req.PublicKey, req.Nonce, req.Signature)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// A one-time code from `phonekeyd pair-code`, or a logged-in session
	// approved with a registered passkey (e.g. adding a second provider).
	if _, loggedIn := s.sessionKeyID(r); loggedIn && req.Code == "" {
		if err := s.checkApproval(r, req.Approval); err != nil {
			s.fail(w, r, err)
			return
		}
	} else {
		ok, err := s.store.ConsumePairCode(r.Context(), req.Code)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !ok {
			s.fail(w, r, errorf(http.StatusUnauthorized, "invalid or expired pairing code"))
			return
		}
	}
	label := protocol.CleanLabel(req.Label)
	if label == "" {
		label = "passkey"
	}
	id, err := s.store.AddKey(r.Context(), normalizeKey(k), ssh.FingerprintSHA256(k), label, req.CredentialID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("key paired", "fingerprint", ssh.FingerprintSHA256(k), "label", label)
	if err := s.setSession(w, r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	key, _ := s.store.KeyByPublicKey(r.Context(), normalizeKey(k))
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) removeKey(w http.ResponseWriter, r *http.Request) {
	var req protocol.Approved
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.checkApproval(r, req.Approval); err != nil {
		s.fail(w, r, err)
		return
	}
	k, err := s.store.RemoveKey(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrLastKey) {
		s.fail(w, r, errorf(http.StatusConflict, "%v", err))
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("key removed", "fingerprint", k.Fingerprint, "label", k.Label)
	s.events.notify()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listDevboxes(w http.ResponseWriter, r *http.Request) {
	ds, err := s.store.Devboxes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]protocol.WebDevbox, 0, len(ds))
	for _, d := range ds {
		out = append(out, protocol.WebDevbox{ID: d.ID, Name: d.Name, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt.Int64})
	}
	writeJSON(w, http.StatusOK, out)
}

// removeDevbox revokes a dev box's token. It needs no passkey: it only takes
// access away, as denying a request does.
func (s *Server) removeDevbox(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	name, err := s.store.RemoveDevboxByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("dev box removed", "name", name)
	s.events.notify()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.store.DeleteSession(r.Context(), c.Value)
		s.events.notify() // ends this session's event streams
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pending(ctx context.Context) ([]protocol.WebRequest, error) {
	reqs, err := s.store.PendingRequests(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]protocol.WebRequest, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.WebRequest)
	}
	return out, nil
}

func (s *Server) pendingEnrollments(ctx context.Context) ([]protocol.WebEnrollment, error) {
	es, err := s.store.PendingEnrollments(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]protocol.WebEnrollment, 0, len(es))
	for _, e := range es {
		out = append(out, e.WebEnrollment)
	}
	return out, nil
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	es, err := s.pendingEnrollments(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, es)
}

// approveEnrollment registers a dev box. Like changing the keys, that takes a
// passkey approval, not just a session.
func (s *Server) approveEnrollment(w http.ResponseWriter, r *http.Request) {
	var req protocol.Approved
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.checkApproval(r, req.Approval); err != nil {
		s.fail(w, r, err)
		return
	}
	s.resolveEnrollment(w, r, protocol.StatusApproved)
}

func (s *Server) denyEnrollment(w http.ResponseWriter, r *http.Request) {
	s.resolveEnrollment(w, r, protocol.StatusDenied)
}

func (s *Server) resolveEnrollment(w http.ResponseWriter, r *http.Request, status string) {
	e, err := s.store.ResolveEnrollment(r.Context(), r.PathValue("id"), status)
	if errors.Is(err, store.ErrNotPending) {
		s.fail(w, r, errorf(http.StatusConflict, "the dev box enrollment is no longer pending"))
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("dev box enrollment "+status, "id", e.ID, "name", e.Name, "replaces", e.Replaces)
	s.events.notify()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRequests(w http.ResponseWriter, r *http.Request) {
	reqs, err := s.pending(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, reqs)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	reqs, err := s.store.History(r.Context(), 50)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type item struct {
		protocol.WebRequest
		ViaGrant bool `json:"via_grant"`
	}
	out := make([]item, 0, len(reqs))
	for _, q := range reqs {
		q.Data = nil
		out = append(out, item{q.WebRequest, q.ViaGrant})
	}
	writeJSON(w, http.StatusOK, out)
}

// eventStream pushes the pending enrollments and requests over server-sent
// events whenever they change. Grants on the page depend on this live
// connection.
func (s *Server) eventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.fail(w, r, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	// The session is checked again on every update and heartbeat, so a
	// removed key, a logout or an expired session ends the stream.
	live := func() bool {
		_, ok := s.sessionKeyID(r)
		return ok
	}
	for {
		changed := s.events.wait()
		if !live() {
			return
		}
		enrollments, err := s.pendingEnrollments(r.Context())
		if err != nil {
			return
		}
		reqs, err := s.pending(r.Context())
		if err != nil {
			return
		}
		b, _ := json.Marshal(enrollments)
		fmt.Fprintf(w, "event: enrollments\ndata: %s\n\n", b)
		b, _ = json.Marshal(reqs)
		fmt.Fprintf(w, "event: requests\ndata: %s\n\n", b)
		flusher.Flush()
		// Wake up when the earliest one expires so the page drops it.
		var expires []int64
		for _, e := range enrollments {
			expires = append(expires, e.ExpiresAt)
		}
		for _, q := range reqs {
			expires = append(expires, q.ExpiresAt)
		}
		var expiry <-chan time.Time
		if len(expires) > 0 {
			expiry = time.After(time.Until(time.Unix(slices.Min(expires), 0)) + 100*time.Millisecond)
		}
	wait:
		select {
		case <-changed:
		case <-expiry:
		case <-heartbeat.C:
			if !live() {
				return
			}
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
			goto wait
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) submitSignature(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var sub protocol.SignatureSubmission
	if err := decode(r, &sub); err != nil {
		s.fail(w, r, err)
		return
	}
	req, err := s.store.Request(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The key may have been removed after the request was queued.
	if _, err := s.store.KeyByPublicKey(r.Context(), req.PublicKey); errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, errorf(http.StatusConflict, "key %s was removed", req.Fingerprint))
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	_, pub, err := parseEd25519(req.PublicKey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ed25519.Verify(pub, req.Data, sub.Signature) {
		s.fail(w, r, errorf(http.StatusBadRequest, "signature does not verify against %s", req.Fingerprint))
		return
	}
	if err := s.store.Resolve(r.Context(), id, protocol.StatusSigned, sub.Signature, sub.Grant); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("request signed", "id", id, "grant", sub.Grant)
	s.events.notify()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) denyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.Resolve(r.Context(), id, protocol.StatusDenied, nil, false); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("request denied", "id", id)
	s.events.notify()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) subscribe(w http.ResponseWriter, r *http.Request) {
	var sub struct {
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256dh string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var raw json.RawMessage
	if err := decode(r, &raw); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := json.Unmarshal(raw, &sub); err != nil || sub.Endpoint == "" || sub.Keys.P256dh == "" || sub.Keys.Auth == "" {
		s.fail(w, r, errorf(http.StatusBadRequest, "not a push subscription"))
		return
	}
	if u, err := url.Parse(sub.Endpoint); err != nil || u.Scheme != "https" {
		s.fail(w, r, errorf(http.StatusBadRequest, "push endpoint must be https"))
		return
	}
	keyID := r.Context().Value(keyIDCtx{}).(int64)
	if err := s.store.SavePushSubscription(r.Context(), sub.Endpoint, string(raw), keyID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("push subscription saved", "endpoint", sub.Endpoint)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testPush(w http.ResponseWriter, r *http.Request) {
	go s.push.send(context.WithoutCancel(r.Context()), PushMessage{Title: "phonekey", Body: "Test notification"})
	w.WriteHeader(http.StatusAccepted)
}
