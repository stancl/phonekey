package main

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"phonekey/internal/server"
	"phonekey/internal/sim"
	"phonekey/internal/store"
)

func TestEnroll(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := server.New(ctx, st, server.Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	code, _ := st.NewPairCode(ctx, time.Minute)
	phone := sim.New(ts.URL, []byte("0123456789abcdef0123456789abcdef"))
	if err := phone.Pair(ctx, code, "phone"); err != nil {
		t.Fatal(err)
	}

	tokenFile := filepath.Join(dir, "config/phonekey/token")
	args := []string{"--backend", ts.URL, "--token-file", tokenFile, "--name", "laptop"}
	done := make(chan error, 1)
	go func() { done <- enroll(args) }()
	var id string
	for id == "" {
		list, err := phone.Enrollments(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) == 1 {
			id = list[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := phone.ApproveEnrollment(ctx, id); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("enroll didn't return after the approval")
	}

	fi, err := os.Stat(tokenFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v, %v", fi, err)
	}
	token, _ := os.ReadFile(tokenFile)
	if d, err := st.DevboxByToken(ctx, strings.TrimSpace(string(token))); err != nil || d.Name != "laptop" {
		t.Fatalf("stored token: %+v, %v", d, err)
	}
	if err := enroll(args); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("enrolling over an existing token file: %v", err)
	}
}
