//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"golang.org/x/crypto/ssh"

	"phonekey/internal/agent"
	"phonekey/internal/keyderive"
	"phonekey/internal/protocol"
	"phonekey/internal/server"
	"phonekey/internal/sim"
	"phonekey/internal/store"
)

// TestBrowser drives the real approval page in headless Chromium, with a
// virtual platform authenticator that supports PRF standing in for the
// phone's passkey.
func TestBrowser(t *testing.T) {
	need(t, "chromium", "ssh-keygen", "git")
	dir := t.TempDir()
	ctx := context.Background()

	st, err := store.Open(filepath.Join(dir, "phonekey.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := server.New(ctx, st, server.Config{MaxGrant: 60 * time.Second, Logger: testLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// failEvents makes the event stream answer 502, as a proxy in front of a
	// restarting phonekeyd would.
	var failEvents, failedEvents atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failEvents.Load() && r.URL.Path == "/api/web/events" {
			failedEvents.Store(true)
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		srv.ServeHTTP(w, r)
	})
	hs := &http.Server{Handler: handler}
	go hs.Serve(ln)
	defer func() { hs.Close() }()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	// WebAuthn needs a domain, not an IP, and localhost counts as secure.
	url := "http://localhost:" + port

	code, _ := st.NewPairCode(ctx, time.Minute)

	alloc, cancel := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(mustLook(t, "chromium")),
		chromedp.UserDataDir(filepath.Join(dir, "chrome")),
	)...)
	defer cancel()
	browser, cancel := chromedp.NewContext(alloc, chromedp.WithLogf(t.Logf))
	defer cancel()
	// The first call starts the browser and must not carry a timeout.
	if _, err := chromedp.Call(browser, webauthn.Enable, webauthn.EnableParams{}); err != nil {
		t.Fatal(err)
	}
	browser, cancel = context.WithTimeout(browser, 90*time.Second)
	defer cancel()
	if _, err := chromedp.Call(browser, webauthn.AddVirtualAuthenticator, webauthn.AddVirtualAuthenticatorParams{
		Options: &webauthn.VirtualAuthenticatorOptions{
			Protocol:                    webauthn.AuthenticatorProtocolCtap2,
			Ctap2version:                webauthn.Ctap2versionCtap21,
			Transport:                   webauthn.AuthenticatorTransportInternal,
			HasResidentKey:              true,
			HasUserVerification:         true,
			IsUserVerified:              true,
			HasPrf:                      true,
			AutomaticPresenceSimulation: true,
		},
	}); err != nil {
		t.Fatal(err)
	}
	do(t, browser,
		chromedp.EmulateViewport(390, 844, chromedp.EmulateScale(2), chromedp.EmulateMobile),
		chromedp.Navigate(url),
		chromedp.WaitVisible(chromedp.ID("pair")),
	)
	shot(t, browser, "1-pair")

	// The page's HKDF step must match the Go mirror exactly.
	seedHex := evalAsync[string](t, browser, `import('/ed25519.js').then(async (m) => {
		const seed = await m.deriveSeed(new Uint8Array(32).fill(0x42), 'phonekey ssh-ed25519 seed v1');
		return Array.from(seed, (b) => b.toString(16).padStart(2, '0')).join('');
	})`)
	if want := hex.EncodeToString(keyderive.Seed(bytes.Repeat([]byte{0x42}, 32))); seedHex != want {
		t.Fatalf("JS seed %s != Go seed %s", seedHex, want)
	}
	tests := evalAsync[map[string]map[string]any](t, browser,
		`import('/ed25519.js').then(async (m) => ({webcrypto: await m.selfTest('webcrypto'), noble: await m.selfTest('noble')}))`)
	t.Logf("Ed25519 self-tests in Chromium: %v", tests)
	if tests["noble"]["ok"] != true {
		t.Fatalf("noble self-test failed: %v", tests["noble"])
	}

	// Pair: create a passkey, derive the key, register it.
	if err := chromedp.Do(browser,
		chromedp.SetValue(chromedp.ID("pair-code"), code),
		chromedp.SetValue(chromedp.ID("pair-label"), "virtual authenticator"),
		chromedp.Click(chromedp.ID("pair-create")),
		chromedp.WaitVisible(chromedp.ID("paired-key")),
	); err != nil {
		t.Fatalf("pairing: %v (page error: %s)", err, pageError(browser))
	}
	paired := text(t, browser, "paired-key-text")
	do(t, browser, chromedp.Click(chromedp.ID("paired-key-done")), chromedp.WaitVisible(chromedp.ID("requests")))
	keys, _ := st.Keys(ctx)
	if len(keys) != 1 || !strings.HasPrefix(paired, keys[0].PublicKey) {
		t.Fatalf("paired %q, stored %+v", paired, keys)
	}
	t.Logf("paired key: %s", keys[0].PublicKey)
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keys[0].PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	// The dev box enrolls itself: the page shows the code it got, and
	// approving takes the passkey.
	devbox := &agent.Backend{URL: url}
	enrolled, err := devbox.Enroll(ctx, protocol.EnrollRequest{Name: "browser-devbox", Host: "devbox.example", User: "you"})
	if err != nil {
		t.Fatal(err)
	}
	devbox.Token = enrolled.Token
	do(t, browser, chromedp.WaitVisible(chromedp.CSS("#enrollment-list .card")))
	if got := evalAsync[string](t, browser, `Promise.resolve(document.querySelector('#enrollment-list .enroll-code').textContent)`); got != enrolled.Code {
		t.Fatalf("page shows code %q, dev box got %q", got, enrolled.Code)
	}
	shot(t, browser, "1b-enrollment")
	do(t, browser,
		chromedp.Click(chromedp.CSS("#enrollment-list .card-actions button")),
		chromedp.WaitNotPresent(chromedp.CSS("#enrollment-list .card")),
	)
	if st, err := devbox.WaitEnrollment(browser); err != nil || st.Status != protocol.StatusApproved {
		t.Fatalf("enrollment: %+v, %v (page error: %s)", st, err, pageError(browser))
	}

	// Enrolling under the same name asks to replace it, which the card makes
	// plain. Deny keeps the dev box as it is.
	again := &agent.Backend{URL: url}
	if _, err := again.Enroll(ctx, protocol.EnrollRequest{Name: "browser-devbox"}); err != nil {
		t.Fatal(err)
	}
	do(t, browser, chromedp.WaitVisible(chromedp.CSS("#enrollment-list .card .warning")))
	if got := evalAsync[string](t, browser, `Promise.resolve([...document.querySelectorAll('#enrollment-list .card-title, #enrollment-list .card-actions button')].map((e) => e.textContent).join(", "))`); got != "Replace a dev box, Replace, Deny" {
		t.Fatalf("replacing card: %q", got)
	}
	shot(t, browser, "1c-replacement")
	do(t, browser,
		chromedp.Click(chromedp.CSS("#enrollment-list .card-actions button.danger")),
		chromedp.WaitNotPresent(chromedp.CSS("#enrollment-list .card")),
	)

	pubFile := filepath.Join(dir, "phone.pub")
	os.WriteFile(pubFile, []byte(keys[0].PublicKey+"\n"), 0o644)
	allowed := filepath.Join(dir, "allowed_signers")
	os.WriteFile(allowed, []byte("test@example.com "+keys[0].PublicKey+"\n"), 0o644)

	// Agent on a private socket.
	sock := filepath.Join(dir, "agent.sock")
	aln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer aln.Close()
	go agent.New(agent.Config{
		Backend:  devbox,
		Keys:     func() []ssh.PublicKey { return []ssh.PublicKey{pk} },
		Deadline: 30 * time.Second,
		Logger:   testLogger(t),
	}).Serve(aln)
	env := isolatedEnv(t, dir, sock, pubFile, allowed)

	// File signatures through the agent, approved by tapping Approve. The
	// first arrives with nothing else pending and is preselected; the second
	// arrives while the first is still waiting and must not be swept into
	// the same approval.
	startSign := func(name string) (*exec.Cmd, *bytes.Buffer, string) {
		msg := filepath.Join(dir, name)
		os.WriteFile(msg, []byte("signed in a browser: "+name+"\n"), 0o644)
		cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", pubFile, "-n", "file", msg)
		cmd.Env = env
		out := &bytes.Buffer{}
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd, out, msg
	}
	verifySig := func(msg string) {
		t.Helper()
		v := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "test@example.com", "-n", "file", "-s", msg+".sig")
		v.Stdin, _ = os.Open(msg)
		if out, err := v.CombinedOutput(); err != nil {
			t.Fatalf("verify %s: %v\n%s", msg, err, out)
		}
	}
	signA, outA, msgA := startSign("a.txt")
	do(t, browser, chromedp.WaitVisible(chromedp.CSS("#request-list .card")))
	shot(t, browser, "2-request")
	// A lone ssh-keygen signs once, so there's nothing for a grant to cover.
	if evalAsync[bool](t, browser, `Promise.resolve(document.getElementById('approve-grant').hidden)`) != true {
		t.Fatal("offered a grant for a one-shot ssh-keygen")
	}
	signB, outB, msgB := startSign("b.txt")
	do(t, browser, chromedp.WaitVisible(chromedp.CSS("#request-list .card:nth-child(2)")))
	checked := evalAsync[[]bool](t, browser, `Promise.resolve([...document.querySelectorAll('#request-list input[type=checkbox]')].map((c) => c.checked))`)
	if len(checked) != 2 || !checked[0] || checked[1] {
		t.Fatalf("checkbox states %v, want [true false]", checked)
	}
	do(t, browser, chromedp.Click(chromedp.ID("approve")))
	waitCmd(t, signA, outA)
	verifySig(msgA)
	do(t, browser,
		chromedp.WaitNotPresent(chromedp.CSS("#request-list .card:nth-child(2)")),
		chromedp.Click(chromedp.CSS("#request-list input[type=checkbox]")),
		chromedp.Click(chromedp.ID("approve")),
	)
	waitCmd(t, signB, outB)
	verifySig(msgB)

	// Grant: a rebase re-signs three commits. One tap approves the first;
	// the open grant signs the other two as they arrive.
	repo := filepath.Join(dir, "repo")
	gitIn := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = repo, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	os.MkdirAll(repo, 0o755)
	gitIn("init", "-q")
	for _, m := range []string{"base", "one", "two", "three"} {
		os.WriteFile(filepath.Join(repo, m), []byte(m), 0o644)
		gitIn("add", m)
		gitIn("commit", "-q", "-m", m)
	}
	rebase := exec.Command("git", "rebase", "--force-rebase", "--gpg-sign", "HEAD~3")
	rebase.Dir, rebase.Env = repo, env
	rebaseOut := &bytes.Buffer{}
	rebase.Stdout, rebase.Stderr = rebaseOut, rebaseOut
	if err := rebase.Start(); err != nil {
		t.Fatal(err)
	}
	do(t, browser, chromedp.WaitVisible(chromedp.CSS("#request-list .card")))
	if label := text(t, browser, "approve-grant"); !strings.Contains(label, "git rebase --force-rebase") {
		t.Fatalf("grant button label %q", label)
	}
	shot(t, browser, "3-rebase-request")
	do(t, browser, chromedp.Click(chromedp.ID("approve-grant")))
	waitCmd(t, rebase, rebaseOut)
	for _, rev := range []string{"HEAD", "HEAD~1", "HEAD~2"} {
		gitIn("verify-commit", rev)
	}
	hist, _ := st.History(ctx, 10)
	grants := 0
	for _, r := range hist {
		if r.ViaGrant {
			grants++
		}
	}
	if grants != 2 {
		t.Fatalf("expected 2 signatures under the grant, got %d", grants)
	}
	if title := text(t, browser, "grant-title"); !strings.Contains(title, "Auto-approving more from: git rebase") {
		t.Fatalf("grant banner title %q", title)
	}
	if n := evalAsync[int](t, browser, `Promise.resolve(document.querySelectorAll('#grant-signed li').length)`); n != 2 {
		t.Fatalf("grant banner lists %d signatures, want 2", n)
	}
	if e := pageError(browser); e != "" {
		t.Fatalf("page shows an error after the grant: %s", e)
	}
	shot(t, browser, "4-grant")

	// Recent shows who signed each request and the command it came from.
	do(t, browser,
		chromedp.Evaluate[chromedp.Void](`document.getElementById('history-details').open = true`),
		chromedp.WaitVisible(chromedp.CSS("#history li")),
	)
	recent := text(t, browser, "history")
	for _, want := range []string{"✓ signed · grant", "✓ signed · you", "git rebase --force-rebase --gpg-sign HEAD~3 · browser-devbox"} {
		if !strings.Contains(recent, want) {
			t.Fatalf("Recent lacks %q:\n%s", want, recent)
		}
	}
	do(t, browser, chromedp.Click(chromedp.CSS("#history li details summary")))
	shot(t, browser, "4b-recent")
	do(t, browser, chromedp.Evaluate[chromedp.Void](`document.getElementById('history-details').open = false`))

	// A restart behind a proxy: the stream drops and the reconnect gets a
	// 502, after which the browser stops retrying on its own. The page has
	// to reconnect by itself.
	failEvents.Store(true)
	hs.Close()
	ln, err = net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	hs = &http.Server{Handler: handler}
	go hs.Serve(ln)
	for i := 0; i < 100 && !failedEvents.Load(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if !failedEvents.Load() {
		t.Fatal("the page never retried the event stream")
	}
	failEvents.Store(false)
	do(t, browser, chromedp.Poll[chromedp.Void](`document.getElementById('conn').textContent === 'live'`, chromedp.WithPollingTimeout(15*time.Second)))

	// Diagnostics: the page's own SSHSIG output verifies with OpenSSH.
	do(t, browser,
		chromedp.Evaluate[chromedp.Void](`document.getElementById('diag-details').open = true`),
		chromedp.Click(chromedp.ID("diag-sign")),
		chromedp.WaitVisible(chromedp.ID("diag-out")),
	)
	shot(t, browser, "5-diagnostics")
	verifyDiag(t, text(t, browser, "diag-out"), "webcrypto")

	// The same through noble-ed25519, the fallback for browsers whose
	// WebCrypto Ed25519 is wrong. It once signed with a wiped seed.
	do(t, browser,
		chromedp.SetValue(chromedp.ID("impl-pref"), "noble"),
		chromedp.Evaluate[chromedp.Void](`document.getElementById('impl-pref').dispatchEvent(new Event('change'))`),
		chromedp.Evaluate[chromedp.Void](`document.getElementById('diag-out').hidden = true`),
		chromedp.Click(chromedp.ID("diag-sign")),
		chromedp.WaitVisible(chromedp.ID("diag-out")),
	)
	verifyDiag(t, text(t, browser, "diag-out"), "noble")

	// Dev boxes lists the enrolled one, and removing it revokes its token.
	do(t, browser,
		chromedp.Evaluate[chromedp.Void](`document.getElementById('diag-details').open = false`),
		chromedp.Evaluate[chromedp.Void](`document.getElementById('devboxes-details').open = true`),
		chromedp.WaitVisible(chromedp.CSS("#devboxes .key-row")),
	)
	if got := text(t, browser, "devboxes"); !strings.Contains(got, "browser-devbox") || !strings.Contains(got, "last seen") {
		t.Fatalf("dev boxes list %q", got)
	}
	if got := text(t, browser, "enroll-command"); got != "phonekey-agent enroll --backend "+url {
		t.Fatalf("enroll command %q", got)
	}
	shot(t, browser, "5b-devboxes")
	do(t, browser,
		chromedp.Evaluate[chromedp.Void](`window.confirm = () => true`),
		chromedp.Click(chromedp.CSS("#devboxes .key-row button")),
		chromedp.WaitNotPresent(chromedp.CSS("#devboxes .key-row")),
	)
	if _, err := devbox.Keys(ctx); err == nil {
		t.Fatal("removed dev box's token still works")
	}

	// Removing keys from the page. Two accidental keys get paired; removing
	// one leaves this session alone, removing the key this page logged in
	// with logs it out, and the other key's session carries on.
	var extra []*sim.Phone
	for i, label := range []string{"accidental one", "accidental two"} {
		code, _ := st.NewPairCode(ctx, time.Minute)
		p := sim.New(url, bytes.Repeat([]byte{byte(i + 1)}, 32))
		if err := p.Pair(ctx, code, label); err != nil {
			t.Fatal(err)
		}
		extra = append(extra, p)
	}
	removeKey := func(label string) {
		t.Helper()
		do(t, browser,
			chromedp.Evaluate[chromedp.Void](`window.confirm = () => true`),
			chromedp.Evaluate[chromedp.Void](fmt.Sprintf(
				`[...document.querySelectorAll('#keys li')].find((li) => li.textContent.includes(%q)).querySelector('button').click()`, label)),
		)
	}
	// The Reload button reloads the page (home-screen apps have no other way).
	do(t, browser,
		chromedp.Evaluate[chromedp.Void](`window.beforeReload = true`),
		chromedp.Click(chromedp.ID("reload")),
	)
	reloaded := false
	for i := 0; i < 50 && !reloaded; i++ {
		time.Sleep(100 * time.Millisecond)
		// Evaluating fails while the old page goes away; that's expected.
		reloaded, _ = chromedp.Run(browser, chromedp.Evaluate[bool](`window.beforeReload === undefined && document.readyState === 'complete'`))
	}
	if !reloaded {
		t.Fatal("Reload didn't reload the page")
	}
	do(t, browser, chromedp.WaitVisible(chromedp.ID("requests")))
	if status := text(t, browser, "status"); status != "logged in with virtual authenticator" {
		t.Fatalf("status %q", status)
	}
	do(t, browser, chromedp.Evaluate[chromedp.Void](`document.getElementById('setup-details').open = true`))
	shot(t, browser, "6-keys")
	removeKey("accidental one")
	do(t, browser, chromedp.Poll[chromedp.Void](`!document.getElementById('keys').textContent.includes('accidental one')`))
	if _, err := extra[0].Pending(ctx); err == nil {
		t.Fatal("removed key's session still works")
	}
	removeKey("virtual authenticator")
	do(t, browser, chromedp.WaitVisible(chromedp.ID("pair")))
	if keys, _ := st.Keys(ctx); len(keys) != 1 || keys[0].Label != "accidental two" {
		t.Fatalf("keys left: %+v", keys)
	}
	if _, err := extra[1].Pending(ctx); err != nil {
		t.Fatalf("remaining key's session ended: %v", err)
	}
}

func verifyDiag(t *testing.T, diag, impl string) {
	t.Helper()
	if !strings.Contains(diag, "# implementation: "+impl) {
		t.Fatalf("diagnostics used the wrong implementation, want %s:\n%s", impl, diag)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "verify.sh")
	os.WriteFile(script, []byte(diag), 0o755)
	vcmd := exec.Command("sh", script)
	vcmd.Dir = dir
	out, err := vcmd.CombinedOutput()
	if err != nil || !regexp.MustCompile(`Good "phonekey-test" signature for phonekey`).Match(out) {
		t.Fatalf("%s diagnostics signature didn't verify: %v\n%s\n--- script:\n%s", impl, err, out, diag)
	}
}

// shot saves a full-page screenshot when $PHONEKEY_SCREENSHOTS names a directory.
func shot(t *testing.T, ctx context.Context, name string) {
	dir := os.Getenv("PHONEKEY_SCREENSHOTS")
	if dir == "" {
		return
	}
	png, err := chromedp.Run(ctx, chromedp.FullScreenshot(90))
	if err != nil {
		t.Logf("screenshot %s: %v", name, err)
		return
	}
	os.WriteFile(filepath.Join(dir, name+".png"), png, 0o644)
}

func mustLook(t *testing.T, name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skip(err)
	}
	return p
}

func evalAsync[T any](t *testing.T, ctx context.Context, js string) T {
	t.Helper()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[T](js, chromedp.EvalAwaitPromise))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return v
}

func do(t *testing.T, ctx context.Context, steps ...chromedp.Action[chromedp.Void]) {
	t.Helper()
	if err := chromedp.Do(ctx, steps...); err != nil {
		t.Fatalf("browser: %v (page error: %s)", err, pageError(ctx))
	}
}

func text(t *testing.T, ctx context.Context, id string) string {
	t.Helper()
	s, err := chromedp.Run(ctx, chromedp.Text(chromedp.ID(id)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pageError(ctx context.Context) string {
	s, _ := chromedp.Run(ctx, chromedp.Evaluate[string](`document.getElementById('error')?.textContent ?? ''`))
	return s
}

func waitCmd(t *testing.T, cmd *exec.Cmd, out *bytes.Buffer) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%v: %v\n%s", cmd.Args, err, out)
		}
	case <-time.After(40 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("%v timed out\n%s", cmd.Args, out)
	}
}

func isolatedEnv(t *testing.T, dir, sock, pubFile, allowed string) []string {
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o700)
	gitconfig := filepath.Join(dir, "gitconfig")
	os.WriteFile(gitconfig, []byte(fmt.Sprintf(`[user]
	name = Test User
	email = test@example.com
	signingkey = %s
[gpg]
	format = ssh
[gpg "ssh"]
	allowedSignersFile = %s
[init]
	defaultBranch = main
`, pubFile, allowed)), 0o644)
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_GLOBAL=" + gitconfig,
		"GIT_CONFIG_NOSYSTEM=1",
		"SSH_AUTH_SOCK=" + sock,
	}
}
