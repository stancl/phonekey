// Command phonekey-agent is an ssh-agent that gets its signatures approved
// and made on your phone through phonekeyd.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"phonekey/internal/agent"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		if err := enroll(os.Args[2:]); err != nil {
			fatal(err)
		}
		return
	}
	home, _ := os.UserHomeDir()
	// No fallback to a shared directory like /tmp, where another account
	// could create the socket path first.
	defaultSocket := ""
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		defaultSocket = filepath.Join(runtime, "phonekey-agent.sock")
	}
	socket := flag.String("socket", envOr("PHONEKEY_SOCKET", defaultSocket), "agent socket path (default $XDG_RUNTIME_DIR/phonekey-agent.sock) ($PHONEKEY_SOCKET)")
	backendURL := flag.String("backend", os.Getenv("PHONEKEY_BACKEND"), "phonekeyd URL ($PHONEKEY_BACKEND)")
	tokenFile := flag.String("token-file", os.Getenv("PHONEKEY_TOKEN_FILE"), "file holding the dev box token ($PHONEKEY_TOKEN_FILE; or set $PHONEKEY_TOKEN)")
	keysFile := flag.String("keys", os.Getenv("PHONEKEY_KEYS"), "authorized_keys-format file of phone keys to offer (default: fetch from phonekeyd) ($PHONEKEY_KEYS)")
	deadline := flag.Duration("deadline", 90*time.Second, "how long to wait for an approval")
	upstream := flag.String("upstream", os.Getenv("PHONEKEY_UPSTREAM"), "another agent socket whose keys to offer too, e.g. a forwarded 1Password agent ($PHONEKEY_UPSTREAM)")
	requireBind := flag.Bool("require-session-bind", true, "refuse SSH logins not bound with session-bind@openssh.com")
	requireKnown := flag.Bool("require-known-host", false, "refuse SSH logins to hosts not in known_hosts")
	knownHosts := flag.String("known-hosts", filepath.Join(home, ".ssh/known_hosts")+",/etc/ssh/ssh_known_hosts",
		"comma-separated known_hosts files used to name servers (read only)")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "usage: phonekey-agent [flags]\n"+
			"       phonekey-agent enroll [--backend URL] [--token-file FILE] [--name NAME]\n"+
			"         ask phonekeyd to register this dev box, approved on the phone\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	// Paths may refer to $HOME or $XDG_RUNTIME_DIR, e.g. from a settings file
	// shared by several users.
	for _, p := range []*string{socket, tokenFile, keysFile, upstream} {
		*p = os.ExpandEnv(*p)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *backendURL == "" {
		fatal(errors.New("--backend is required"))
	}
	if *socket == "" {
		fatal(errors.New("no $XDG_RUNTIME_DIR: set --socket to a path in a directory only you can write to"))
	}
	token := os.Getenv("PHONEKEY_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fatal(err)
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		fatal(errors.New("no dev box token: use --token-file or $PHONEKEY_TOKEN, or get one with `phonekey-agent enroll`"))
	}
	backend := &agent.Backend{URL: *backendURL, Token: token, HTTP: &http.Client{Timeout: time.Minute}}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ks := &keySet{log: log}
	if *keysFile != "" {
		if err := ks.loadFile(*keysFile); err != nil {
			fatal(err)
		}
	} else {
		if err := ks.fetch(ctx, backend); err != nil {
			fatal(fmt.Errorf("fetching keys from phonekeyd: %w", err))
		}
		go ks.refresh(ctx, backend, 5*time.Minute)
	}

	hostname, _ := os.Hostname()
	a := agent.New(agent.Config{
		Backend:            backend,
		Keys:               ks.get,
		Deadline:           *deadline,
		Upstream:           *upstream,
		RequireSessionBind: *requireBind,
		RequireKnownHost:   *requireKnown,
		KnownHosts:         strings.Split(*knownHosts, ","),
		Hostname:           hostname,
		Logger:             log,
	})

	if err := os.MkdirAll(filepath.Dir(*socket), 0o700); err != nil {
		fatal(err)
	}
	if c, err := net.Dial("unix", *socket); err == nil {
		c.Close()
		fatal(fmt.Errorf("%s is in use by another agent", *socket))
	}
	os.Remove(*socket)
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", *socket)
	syscall.Umask(old)
	if err != nil {
		fatal(err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	log.Info("listening", "socket", *socket, "keys", len(ks.get()))
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", *socket)
	if err := a.Serve(ln); err != nil {
		fatal(err)
	}
}

type keySet struct {
	mu   sync.RWMutex
	keys []ssh.PublicKey
	log  *slog.Logger
}

func (k *keySet) get() []ssh.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys
}

func (k *keySet) set(text string) error {
	var keys []ssh.PublicKey
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return fmt.Errorf("bad key line %q: %w", line, err)
		}
		if pk.Type() != ssh.KeyAlgoED25519 {
			return fmt.Errorf("only ssh-ed25519 phone keys are supported, got %s", pk.Type())
		}
		keys = append(keys, pk)
	}
	k.mu.Lock()
	k.keys = keys
	k.mu.Unlock()
	return nil
}

func (k *keySet) loadFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return k.set(string(b))
}

func (k *keySet) fetch(ctx context.Context, b *agent.Backend) error {
	text, err := b.Keys(ctx)
	if err != nil {
		return err
	}
	return k.set(text)
}

func (k *keySet) refresh(ctx context.Context, b *agent.Backend, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := k.fetch(ctx, b); err != nil {
				k.log.Warn("refreshing keys failed", "err", err)
			}
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "phonekey-agent:", err)
	os.Exit(1)
}
