// Package sim is a stand-in for the approval web app: it talks to phonekeyd's
// web API exactly like the page does, with a key derived from a fixed "PRF
// output" instead of a passkey. It's for tests and for exercising the dev box
// side without a phone.
package sim

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"phonekey/internal/keyderive"
	"phonekey/internal/protocol"
)

type Phone struct {
	URL     string
	Key     ed25519.PrivateKey
	HTTP    *http.Client
	session string
}

func New(url string, prf []byte) *Phone {
	return &Phone{URL: strings.TrimRight(url, "/"), Key: keyderive.Key(prf), HTTP: http.DefaultClient}
}

func (p *Phone) PublicKey() string {
	return keyderive.AuthorizedKey(p.Key.Public().(ed25519.PublicKey))
}

// Post sends an authenticated web API request.
func (p *Phone) Post(ctx context.Context, path string, body, out any) error {
	return p.do(ctx, http.MethodPost, path, body, out)
}

// Delete sends an authenticated DELETE to the web API.
func (p *Phone) Delete(ctx context.Context, path string) error {
	return p.do(ctx, http.MethodDelete, path, nil, nil)
}

// Config returns the web config as this phone's session sees it.
func (p *Phone) Config(ctx context.Context) (*protocol.WebConfig, error) {
	var c protocol.WebConfig
	return &c, p.do(ctx, http.MethodGet, "/api/web/config", nil, &c)
}

func (p *Phone) do(ctx context.Context, method, path string, body, out any) error {
	resp, err := p.send(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (p *Phone) send(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", p.URL)
	req.Header.Set("Content-Type", "application/json")
	if p.session != "" {
		req.AddCookie(&http.Cookie{Name: "phonekey_session", Value: p.session})
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	for _, c := range resp.Cookies() {
		if c.Name == "phonekey_session" {
			p.session = c.Value
		}
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

func (p *Phone) signedNonce(ctx context.Context) (string, []byte, error) {
	var n protocol.NonceResponse
	if err := p.do(ctx, http.MethodPost, "/api/web/nonce", struct{}{}, &n); err != nil {
		return "", nil, err
	}
	return n.Nonce, ed25519.Sign(p.Key, protocol.AuthMessage(n.Nonce)), nil
}

func (p *Phone) Pair(ctx context.Context, code, label string) error {
	nonce, sig, err := p.signedNonce(ctx)
	if err != nil {
		return err
	}
	return p.do(ctx, http.MethodPost, "/api/web/pair", protocol.PairRequest{
		Code: code, Label: label, PublicKey: p.PublicKey(), Nonce: nonce, Signature: sig,
	}, nil)
}

// SignNonce gets a nonce through via's session and signs it with this
// phone's key, for building web API requests by hand in tests.
func (p *Phone) SignNonce(t interface{ Fatal(...any) }, ctx context.Context, via *Phone) (string, []byte) {
	var n protocol.NonceResponse
	if err := via.do(ctx, http.MethodPost, "/api/web/nonce", struct{}{}, &n); err != nil {
		t.Fatal(err)
	}
	return n.Nonce, ed25519.Sign(p.Key, protocol.AuthMessage(n.Nonce))
}

// Approval signs a fresh nonce, approving a change to the registered keys.
func (p *Phone) Approval(ctx context.Context) (*protocol.Approval, error) {
	nonce, sig, err := p.signedNonce(ctx)
	if err != nil {
		return nil, err
	}
	return &protocol.Approval{PublicKey: p.PublicKey(), Nonce: nonce, Signature: sig}, nil
}

// RemoveKey removes a registered key, approved with this phone's key.
func (p *Phone) RemoveKey(ctx context.Context, id int64) error {
	a, err := p.Approval(ctx)
	if err != nil {
		return err
	}
	return p.do(ctx, http.MethodDelete, fmt.Sprintf("/api/web/keys/%d", id), protocol.Approved{Approval: a}, nil)
}

func (p *Phone) Login(ctx context.Context) error {
	nonce, sig, err := p.signedNonce(ctx)
	if err != nil {
		return err
	}
	return p.do(ctx, http.MethodPost, "/api/web/login", protocol.LoginRequest{
		PublicKey: p.PublicKey(), Nonce: nonce, Signature: sig,
	}, nil)
}

func (p *Phone) Pending(ctx context.Context) ([]protocol.WebRequest, error) {
	var out []protocol.WebRequest
	return out, p.do(ctx, http.MethodGet, "/api/web/requests", nil, &out)
}

// Approve signs a request's data, refusing anything that looks like a web
// login message (as the page does).
func (p *Phone) Approve(ctx context.Context, r protocol.WebRequest) error {
	if bytes.HasPrefix(r.Data, []byte("phonekey-auth")) {
		return errors.New("refusing to sign a login message")
	}
	if r.PublicKey != p.PublicKey() {
		return fmt.Errorf("request %s is for %s, not this key", r.ID, r.Fingerprint)
	}
	return p.do(ctx, http.MethodPost, "/api/web/requests/"+r.ID+"/signature",
		protocol.SignatureSubmission{Signature: ed25519.Sign(p.Key, r.Data)}, nil)
}

func (p *Phone) Deny(ctx context.Context, id string) error {
	return p.do(ctx, http.MethodPost, "/api/web/requests/"+id+"/deny", struct{}{}, nil)
}

func (p *Phone) Devboxes(ctx context.Context) ([]protocol.WebDevbox, error) {
	var out []protocol.WebDevbox
	return out, p.do(ctx, http.MethodGet, "/api/web/devboxes", nil, &out)
}

func (p *Phone) Enrollments(ctx context.Context) ([]protocol.WebEnrollment, error) {
	var out []protocol.WebEnrollment
	return out, p.do(ctx, http.MethodGet, "/api/web/enrollments", nil, &out)
}

// ApproveEnrollment registers a dev box, approved with this phone's key.
func (p *Phone) ApproveEnrollment(ctx context.Context, id string) error {
	a, err := p.Approval(ctx)
	if err != nil {
		return err
	}
	return p.do(ctx, http.MethodPost, "/api/web/enrollments/"+id+"/approve", protocol.Approved{Approval: a}, nil)
}

func (p *Phone) DenyEnrollment(ctx context.Context, id string) error {
	return p.do(ctx, http.MethodPost, "/api/web/enrollments/"+id+"/deny", struct{}{}, nil)
}

// Watch streams the pending list from /api/web/events, calling fn each time
// it changes, until ctx is done or fn returns an error.
func (p *Phone) Watch(ctx context.Context, fn func([]protocol.WebRequest) error) error {
	resp, err := p.send(ctx, http.MethodGet, "/api/web/events", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	var event string
	var data strings.Builder
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case line == "" && data.Len() > 0:
			if event != "requests" {
				data.Reset()
				continue
			}
			var reqs []protocol.WebRequest
			if err := json.Unmarshal([]byte(data.String()), &reqs); err != nil {
				return err
			}
			data.Reset()
			if err := fn(reqs); err != nil {
				return err
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return sc.Err()
}
