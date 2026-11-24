package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"phonekey/internal/agent"
	"phonekey/internal/protocol"
	"phonekey/internal/server"
	"phonekey/internal/sim"
	"phonekey/internal/store"
)

type env struct {
	t       *testing.T
	url     string
	store   *store.Store
	phone   *sim.Phone
	backend *agent.Backend
}

func setup(t *testing.T, cfg server.Config) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.New(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	sweepCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go srv.Sweep(sweepCtx, 100*time.Millisecond)

	token, err := st.AddDevbox(ctx, "devbox")
	if err != nil {
		t.Fatal(err)
	}
	code, err := st.NewPairCode(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	phone := sim.New(ts.URL, []byte("0123456789abcdef0123456789abcdef"))
	if err := phone.Pair(ctx, code, "test phone"); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, url: ts.URL, store: st, phone: phone, backend: &agent.Backend{URL: ts.URL, Token: token}}
}

func sshsigBlob(msg string) []byte {
	h := sha512.Sum512([]byte(msg))
	return append([]byte("SSHSIG"), ssh.Marshal(struct {
		NS, Reserved, Alg string
		Hash              []byte
	}{"git", "", "sha512", h[:]})...)
}

func TestApproveFlow(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()
	data := sshsigBlob("tree 123\n\nhello\n")
	created, err := e.backend.Create(ctx, protocol.CreateRequest{
		PublicKey: e.phone.PublicKey(),
		Data:      data,
		Context:   protocol.Context{GitObject: &protocol.GitObject{Type: "commit", Subject: "hello"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	pending, err := e.phone.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Summary != "Sign commit: hello" || pending[0].Details.Namespace != "git" {
		t.Fatalf("unexpected pending list: %+v", pending)
	}

	// The long-poll should wake up as soon as the phone signs.
	done := make(chan *protocol.RequestState)
	go func() {
		st, err := e.backend.Wait(ctx, created.ID)
		if err != nil {
			t.Error(err)
		}
		done <- st
	}()
	time.Sleep(100 * time.Millisecond)
	if err := e.phone.Approve(ctx, pending[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case st := <-done:
		if st.Status != protocol.StatusSigned || !ed25519.Verify(e.phone.Key.Public().(ed25519.PublicKey), data, st.Signature) {
			t.Fatalf("bad result %+v", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll didn't return")
	}

	if err := e.phone.Approve(ctx, pending[0]); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("second approval should conflict, got %v", err)
	}
}

func TestBadSignatureRejected(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()
	created, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob("x")})
	if err != nil {
		t.Fatal(err)
	}
	req := protocol.WebRequest{ID: created.ID, PublicKey: e.phone.PublicKey(), Data: sshsigBlob("something else")}
	if err := e.phone.Approve(ctx, req); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("want verification failure, got %v", err)
	}
}

func TestDenyCancelExpire(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()
	mk := func(ttl int) string {
		c, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob("x"), TTLSeconds: ttl})
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	denied, cancelled, expired := mk(60), mk(60), mk(1)
	if err := e.phone.Deny(ctx, denied); err != nil {
		t.Fatal(err)
	}
	if err := e.backend.Cancel(ctx, cancelled); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{denied: "denied", cancelled: "cancelled", expired: "expired"} {
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := e.backend.Wait(wctx, id)
		cancel()
		if err != nil || st.Status != want {
			t.Fatalf("%s: got %+v, %v; want %s", id, st, err, want)
		}
	}
	if p, _ := e.phone.Pending(ctx); len(p) != 0 {
		t.Fatalf("resolved requests still pending: %+v", p)
	}
}

func TestCreateValidation(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()
	other := sim.New(e.url, []byte("another passkey's prf output!!!!"))
	cases := map[string]protocol.CreateRequest{
		"unregistered key": {PublicKey: other.PublicKey(), Data: sshsigBlob("x")},
		"unknown data":     {PublicKey: e.phone.PublicKey(), Data: []byte("phonekey-auth-v1\nabc")},
		"bad key":          {PublicKey: "ssh-ed25519 nope", Data: sshsigBlob("x")},
	}
	for name, req := range cases {
		if _, err := e.backend.Create(ctx, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := &agent.Backend{URL: e.url, Token: "pkd_wrong"}
	if _, err := bad.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob("x")}); err == nil {
		t.Error("wrong token accepted")
	}
}

func TestWebAuth(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()

	// A key that wasn't paired can't log in, and a pairing code works once.
	other := sim.New(e.url, []byte("another passkey's prf output!!!!"))
	if err := other.Login(ctx); err == nil {
		t.Fatal("unpaired key logged in")
	}
	code, _ := e.store.NewPairCode(ctx, time.Minute)
	if err := other.Pair(ctx, code, "second"); err != nil {
		t.Fatal(err)
	}
	third := sim.New(e.url, []byte("a third passkey's prf output!!!!"))
	if err := third.Pair(ctx, code, "third"); err == nil {
		t.Fatal("pairing code reused")
	}

	// Logged in, a new key needs no code but an approval from a registered
	// passkey; the session cookie alone isn't enough.
	if err := other.Login(ctx); err != nil {
		t.Fatal(err)
	}
	newKey := sim.New(e.url, []byte("added while logged in, approved."))
	nonce, sig := newKey.SignNonce(t, ctx, other)
	if err := other.Post(ctx, "/api/web/pair", protocol.PairRequest{
		Label: "unapproved", PublicKey: newKey.PublicKey(), Nonce: nonce, Signature: sig,
	}, nil); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("pairing without approval: %v", err)
	}
	approval, err := other.Approval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce, sig = newKey.SignNonce(t, ctx, other)
	if err := other.Post(ctx, "/api/web/pair", protocol.PairRequest{
		Label: "approved\x1b]0;pwned\x07 key", PublicKey: newKey.PublicKey(), Nonce: nonce, Signature: sig, Approval: approval,
	}, nil); err != nil {
		t.Fatalf("pairing with approval: %v", err)
	}
	k, err := e.store.KeyByPublicKey(ctx, newKey.PublicKey())
	if err != nil || k.Label != "approved ]0;pwned key" {
		t.Fatalf("approved key: %+v, %v", k, err)
	}

	// Cross-site writes are refused.
	req, _ := http.NewRequest(http.MethodPost, e.url+"/api/web/nonce", strings.NewReader("{}"))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site nonce: %s", resp.Status)
	}
	req, _ = http.NewRequest(http.MethodPost, e.url+"/api/web/nonce", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://evil.example")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin nonce: %s", resp.Status)
	}

	// Without a session, the pending list isn't readable.
	resp, _ = http.Get(e.url + "/api/web/requests")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous list: %s", resp.Status)
	}
}

func TestEventsAndPush(t *testing.T) {
	var mu sync.Mutex
	var pushes []*http.Request
	pushSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pushes = append(pushes, r)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushSrv.Close()

	e := setup(t, server.Config{PushClient: pushSrv.Client(), VAPIDSubject: "mailto:you@example.com"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sub, _ := json.Marshal(map[string]any{
		"endpoint": pushSrv.URL + "/push/abc",
		"keys": map[string]string{
			// A valid P-256 point and auth secret, as a browser would send.
			"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
			"auth":   "tBHItJI5svbpez7KI4CCXg",
		},
	})
	if err := e.phone.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.phone.Post(ctx, "/api/web/push/subscribe", json.RawMessage(sub), nil); err != nil {
		t.Fatal(err)
	}

	got := make(chan []protocol.WebRequest, 10)
	go e.phone.Watch(ctx, func(r []protocol.WebRequest) error {
		got <- r
		return nil
	})
	if first := <-got; len(first) != 0 {
		t.Fatalf("expected empty initial list, got %d", len(first))
	}
	if _, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob("x")}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if len(r) != 1 {
			t.Fatalf("expected one request in stream, got %d", len(r))
		}
	case <-ctx.Done():
		t.Fatal("no event after request creation")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(pushes)
		mu.Unlock()
		if n > 0 {
			mu.Lock()
			p := pushes[0]
			mu.Unlock()
			auth := p.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "vapid t=") || p.Header.Get("Content-Encoding") != "aes128gcm" {
				t.Fatalf("push missing VAPID/encryption headers: %v", p.Header)
			}
			// Apple rejects the push (403 BadJwtToken) unless sub is a
			// single mailto: or https: URL. webpush-go adds "mailto:" itself,
			// which turned a configured mailto: subject into "mailto:mailto:…".
			jwt, _, _ := strings.Cut(strings.TrimPrefix(auth, "vapid t="), ",")
			parts := strings.Split(jwt, ".")
			if len(parts) != 3 {
				t.Fatalf("VAPID token isn't a JWT: %q", jwt)
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatal(err)
			}
			var claims struct{ Sub string }
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatal(err)
			}
			if claims.Sub != "mailto:you@example.com" {
				t.Fatalf("VAPID sub = %q, want mailto:you@example.com", claims.Sub)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no push sent")
}

func TestPushHoldBack(t *testing.T) {
	var pushes atomic.Int32
	pushSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushes.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushSrv.Close()
	e := setup(t, server.Config{PushClient: pushSrv.Client(), MaxGrant: time.Minute, PushHoldBack: 300 * time.Millisecond})
	ctx := context.Background()
	if err := e.phone.Login(ctx); err != nil {
		t.Fatal(err)
	}
	sub, _ := json.Marshal(map[string]any{
		"endpoint": pushSrv.URL + "/push/abc",
		"keys": map[string]string{
			"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
			"auth":   "tBHItJI5svbpez7KI4CCXg",
		},
	})
	if err := e.phone.Post(ctx, "/api/web/push/subscribe", json.RawMessage(sub), nil); err != nil {
		t.Fatal(err)
	}
	create := func(scope string) protocol.WebRequest {
		t.Helper()
		c, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob(scope), Context: protocol.Context{Scope: scope}})
		if err != nil {
			t.Fatal(err)
		}
		return protocol.WebRequest{ID: c.ID, PublicKey: e.phone.PublicKey(), Data: sshsigBlob(scope)}
	}
	waitPushes := func(want int32) {
		t.Helper()
		time.Sleep(600 * time.Millisecond)
		if got := pushes.Load(); got != want {
			t.Fatalf("pushes: got %d, want %d", got, want)
		}
	}

	// The first request of a command notifies; the user approves it.
	first := create("jj:1")
	waitPushes(1)
	if err := e.phone.Approve(ctx, first); err != nil {
		t.Fatal(err)
	}
	// The next one from the same command is signed by the grant before its
	// held-back push goes out, so there's no notification for it.
	if err := e.phone.Approve(ctx, create("jj:1")); err != nil {
		t.Fatal(err)
	}
	waitPushes(1)
	// Left unanswered, a held-back request still notifies.
	create("jj:1")
	waitPushes(2)
	// Another command notifies as usual.
	create("git:2")
	waitPushes(3)
}

func TestRemoveKey(t *testing.T) {
	pushSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushSrv.Close()
	e := setup(t, server.Config{PushClient: pushSrv.Client()})
	ctx := context.Background()

	// A second passkey, logged in on another device that also gets
	// notifications, with a request waiting for it.
	code, _ := e.store.NewPairCode(ctx, time.Minute)
	other := sim.New(e.url, []byte("another passkey's prf output!!!!"))
	if err := other.Pair(ctx, code, "accidental"); err != nil {
		t.Fatal(err)
	}
	sub, _ := json.Marshal(map[string]any{
		"endpoint": pushSrv.URL + "/push/other",
		"keys": map[string]string{
			"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
			"auth":   "tBHItJI5svbpez7KI4CCXg",
		},
	})
	if err := other.Post(ctx, "/api/web/push/subscribe", json.RawMessage(sub), nil); err != nil {
		t.Fatal(err)
	}
	pending, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: other.PublicKey(), Data: sshsigBlob("x")})
	if err != nil {
		t.Fatal(err)
	}

	if err := e.phone.Login(ctx); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.phone.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var target protocol.WebKey
	for _, k := range cfg.Keys {
		if k.Label == "accidental" {
			target = k
		} else if !k.Current {
			t.Fatalf("own key not marked current: %+v", k)
		}
	}
	if target.Logins != 1 || target.Notified != 1 || target.Current {
		t.Fatalf("accidental key usage: %+v", target)
	}

	// The removed key's open event stream must end with its session.
	streamEnded := make(chan error, 1)
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	go func() { streamEnded <- other.Watch(wctx, func([]protocol.WebRequest) error { return nil }) }()
	time.Sleep(200 * time.Millisecond)

	// A session cookie alone can't remove keys.
	if err := e.phone.Delete(ctx, fmt.Sprintf("/api/web/keys/%d", target.ID)); err == nil {
		t.Fatal("removed a key without a passkey approval")
	}
	if err := e.phone.RemoveKey(ctx, target.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-streamEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("removed key's event stream is still open")
	}
	// Its login ended, its subscription is gone and its request was denied;
	// this session is unaffected.
	if _, err := other.Pending(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("removed key's session still works: %v", err)
	}
	if subs, _ := e.store.PushSubscriptions(ctx); len(subs) != 0 {
		t.Fatalf("removed key's push subscription kept: %+v", subs)
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if st, err := e.backend.Wait(wctx, pending.ID); err != nil || st.Status != protocol.StatusDenied {
		t.Fatalf("pending request for removed key: %+v, %v", st, err)
	}
	if _, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: other.PublicKey(), Data: sshsigBlob("x")}); err == nil {
		t.Fatal("removed key still accepted for new requests")
	}
	if _, err := e.phone.Pending(ctx); err != nil {
		t.Fatalf("own session ended: %v", err)
	}

	// The last key stays.
	cfg, _ = e.phone.Config(ctx)
	if err := e.phone.RemoveKey(ctx, cfg.Keys[0].ID); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("removing the last key: %v", err)
	}
}

func TestEnroll(t *testing.T) {
	e := setup(t, server.Config{MaxEnrollments: 10})
	ctx := context.Background()
	enroll := func(name string) (*agent.Backend, *protocol.EnrollResponse) {
		t.Helper()
		b := &agent.Backend{URL: e.url}
		resp, err := b.Enroll(ctx, protocol.EnrollRequest{Name: name, Host: "box.example", User: "you"})
		if err != nil {
			t.Fatal(err)
		}
		b.Token = resp.Token
		return b, resp
	}
	wait := func(b *agent.Backend) string {
		t.Helper()
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		st, err := b.WaitEnrollment(wctx)
		if err != nil {
			t.Fatal(err)
		}
		return st.Status
	}

	// A new dev box asks; the page lists it with the code the dev box shows,
	// and its token doesn't work yet.
	box, resp := enroll("laptop")
	if err := e.phone.Login(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := e.phone.Enrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "laptop" || list[0].Code != resp.Code || list[0].Host != "box.example" || list[0].Replaces {
		t.Fatalf("enrollments: %+v", list)
	}
	if _, err := box.Keys(ctx); err == nil {
		t.Fatal("token works before approval")
	}

	// A session alone can't approve it; a passkey approval can.
	if err := e.phone.Post(ctx, "/api/web/enrollments/"+list[0].ID+"/approve", protocol.Approved{}, nil); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("approving without a passkey: %v", err)
	}
	if err := e.phone.ApproveEnrollment(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if st := wait(box); st != protocol.StatusApproved {
		t.Fatalf("approved enrollment: %s", st)
	}
	if _, err := box.Keys(ctx); err != nil {
		t.Fatalf("approved token: %v", err)
	}
	if err := e.phone.ApproveEnrollment(ctx, list[0].ID); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("approving twice: %v", err)
	}

	// Enrolling under a registered name replaces that dev box's token.
	again, _ := enroll("devbox")
	list, _ = e.phone.Enrollments(ctx)
	if len(list) != 1 || !list[0].Replaces {
		t.Fatalf("re-enrollment: %+v", list)
	}
	if err := e.phone.ApproveEnrollment(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	wait(again)
	if _, err := e.backend.Keys(ctx); err == nil {
		t.Fatal("replaced token still works")
	}
	if _, err := again.Keys(ctx); err != nil {
		t.Fatalf("replacing token: %v", err)
	}
	if ds, _ := e.store.Devboxes(ctx); len(ds) != 2 {
		t.Fatalf("dev boxes: %+v", ds)
	}

	// Denied and withdrawn enrollments leave nothing usable behind.
	denied, _ := enroll("denied")
	withdrawn, _ := enroll("withdrawn")
	list, _ = e.phone.Enrollments(ctx)
	if err := e.phone.DenyEnrollment(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if st := wait(denied); st != protocol.StatusDenied {
		t.Fatalf("denied enrollment: %s", st)
	}
	if st, err := withdrawn.CancelEnrollment(ctx); err != nil || st.Status != protocol.StatusCancelled {
		t.Fatalf("withdrawing: %+v, %v", st, err)
	}
	if st := wait(withdrawn); st != protocol.StatusCancelled {
		t.Fatalf("withdrawn enrollment: %s", st)
	}
	for _, b := range []*agent.Backend{denied, withdrawn} {
		if _, err := b.Keys(ctx); err == nil {
			t.Fatal("unapproved token works")
		}
	}
	if list, _ := e.phone.Enrollments(ctx); len(list) != 0 {
		t.Fatalf("resolved enrollments still pending: %+v", list)
	}

	// Withdrawing after the approval came in reports the approval, so the dev
	// box can still keep the token.
	late, _ := enroll("late")
	list, _ = e.phone.Enrollments(ctx)
	if err := e.phone.ApproveEnrollment(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if st, err := late.CancelEnrollment(ctx); err != nil || st.Status != protocol.StatusApproved {
		t.Fatalf("withdrawing after approval: %+v, %v", st, err)
	}

	// Names are hostname-like, so one can't pose as a code on the card.
	for _, name := range []string{"", " ", "laptop, code ABCD-EFGH", "a\u202eb", strings.Repeat("x", 65)} {
		if _, err := (&agent.Backend{URL: e.url}).Enroll(ctx, protocol.EnrollRequest{Name: name}); err == nil {
			t.Errorf("enrolled as %q", name)
		}
	}

	// A web page can't ask: a cross-site POST can't be JSON without a
	// preflight.
	res, err := http.Post(e.url+"/api/devbox/enroll", "text/plain", strings.NewReader(`{"name":"drive-by"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain enrollment: %s", res.Status)
	}
}

func TestEnrollLimit(t *testing.T) {
	e := setup(t, server.Config{MaxEnrollments: 2})
	ctx := context.Background()
	enroll := func() (*agent.Backend, error) {
		b := &agent.Backend{URL: e.url}
		resp, err := b.Enroll(ctx, protocol.EnrollRequest{Name: "spam"})
		if err == nil {
			b.Token = resp.Token
		}
		return b, err
	}
	// Withdrawn enrollments still count, or asking and withdrawing in a
	// loop would send a push each time without ever reaching the cap.
	for range 2 {
		b, err := enroll()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.CancelEnrollment(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := enroll(); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("enrollment past the limit: %v", err)
	}
}

func TestEnrollExpiry(t *testing.T) {
	e := setup(t, server.Config{EnrollTTL: time.Second})
	ctx := context.Background()
	b := &agent.Backend{URL: e.url}
	resp, err := b.Enroll(ctx, protocol.EnrollRequest{Name: "slow"})
	if err != nil {
		t.Fatal(err)
	}
	b.Token = resp.Token
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if st, err := b.WaitEnrollment(wctx); err != nil || st.Status != protocol.StatusExpired {
		t.Fatalf("expired enrollment: %+v, %v", st, err)
	}
	if err := e.phone.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := e.phone.Enrollments(ctx); len(list) != 0 {
		t.Fatalf("expired enrollment still listed: %+v", list)
	}
}
