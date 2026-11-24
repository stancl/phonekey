package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"phonekey/internal/agent"
	"phonekey/internal/protocol"
)

// enroll asks phonekeyd to register this dev box. The phone gets a
// notification, and once the enrollment is approved there with a passkey,
// the dev box token is written to the token file.
func enroll(args []string) error {
	home, _ := os.UserHomeDir()
	hostname, _ := os.Hostname()
	fs := flag.NewFlagSet("phonekey-agent enroll", flag.ExitOnError)
	backendURL := fs.String("backend", os.Getenv("PHONEKEY_BACKEND"), "phonekeyd URL ($PHONEKEY_BACKEND)")
	tokenFile := fs.String("token-file", envOr("PHONEKEY_TOKEN_FILE", filepath.Join(home, ".config/phonekey/token")),
		"where to write the dev box token ($PHONEKEY_TOKEN_FILE)")
	name := fs.String("name", hostname, "the dev box's name on phonekeyd")
	fs.Parse(args)
	*tokenFile = os.ExpandEnv(*tokenFile)
	if *backendURL == "" {
		return errors.New("--backend is required")
	}
	if _, err := os.Stat(*tokenFile); err == nil {
		return fmt.Errorf("%s already exists; remove it to enroll again", *tokenFile)
	}
	if err := os.MkdirAll(filepath.Dir(*tokenFile), 0o700); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	backend := &agent.Backend{URL: *backendURL, HTTP: &http.Client{Timeout: time.Minute}}
	req := protocol.EnrollRequest{Name: *name, Host: hostname}
	if u, err := user.Current(); err == nil {
		req.User = u.Username
	}
	resp, err := backend.Enroll(ctx, req)
	if err != nil {
		return err
	}
	backend.Token = resp.Token
	fmt.Printf("Approve the dev box %q in phonekey. Check that it shows the code\n\n    %s\n\n", *name, resp.Code)

	wctx, cancel := context.WithDeadline(ctx, time.Unix(resp.ExpiresAt, 0).Add(5*time.Second))
	defer cancel()
	st, err := backend.WaitEnrollment(wctx)
	if ctx.Err() != nil {
		// The approval may have come in just before.
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if st, err = backend.CancelEnrollment(cctx); err != nil || st.Status != protocol.StatusApproved {
			return errors.New("cancelled")
		}
	}
	switch {
	case err != nil:
		return errors.New("not approved in time")
	case st.Status != protocol.StatusApproved:
		return fmt.Errorf("enrollment %s", st.Status)
	}

	f, err := os.OpenFile(*tokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("approved, but writing the token failed: %w", err)
	}
	if _, err := fmt.Fprintln(f, resp.Token); err != nil {
		f.Close()
		return fmt.Errorf("approved, but writing the token failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("approved, but writing the token failed: %w", err)
	}
	fmt.Printf("Approved. The token is in %s.\n", *tokenFile)
	return nil
}
