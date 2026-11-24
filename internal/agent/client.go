package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"phonekey/internal/protocol"
)

// Backend is a phonekeyd dev box API client.
type Backend struct {
	URL   string
	Token string
	HTTP  *http.Client
}

func (b *Backend) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(b.URL, "/")+path, rd)
	if err != nil {
		return err
	}
	if b.Token != "" {
		req.Header.Set("Authorization", "Bearer "+b.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := b.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var e struct{ Error string }
		if json.Unmarshal(msg, &e) == nil && e.Error != "" {
			return fmt.Errorf("phonekeyd: %s %s: %s", method, path, e.Error)
		}
		return fmt.Errorf("phonekeyd: %s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	if s, ok := out.(*string); ok {
		b, err := io.ReadAll(resp.Body)
		*s = string(b)
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (b *Backend) Create(ctx context.Context, req protocol.CreateRequest) (*protocol.CreateResponse, error) {
	var out protocol.CreateResponse
	return &out, b.do(ctx, http.MethodPost, "/api/devbox/requests", req, &out)
}

// Wait long-polls until the request leaves pending or ctx is done.
func (b *Backend) Wait(ctx context.Context, id string) (*protocol.RequestState, error) {
	return b.poll(ctx, "/api/devbox/requests/"+id+"?wait=25")
}

func (b *Backend) poll(ctx context.Context, path string) (*protocol.RequestState, error) {
	for {
		var st protocol.RequestState
		pctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		err := b.do(pctx, http.MethodGet, path, nil, &st)
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			// Transient failures (backend restart, network blip) shouldn't
			// lose a request the user may be approving right now.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		if st.Status != protocol.StatusPending {
			return &st, nil
		}
	}
}

func (b *Backend) Cancel(ctx context.Context, id string) error {
	return b.do(ctx, http.MethodDelete, "/api/devbox/requests/"+id, nil, nil)
}

// Enroll asks phonekeyd to register this dev box, without a token. The token
// it returns works once the enrollment is approved on the page.
func (b *Backend) Enroll(ctx context.Context, req protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	return &out, b.do(ctx, http.MethodPost, "/api/devbox/enroll", req, &out)
}

// WaitEnrollment long-polls, with the token Enroll returned, until the
// enrollment leaves pending or ctx is done.
func (b *Backend) WaitEnrollment(ctx context.Context) (*protocol.RequestState, error) {
	return b.poll(ctx, "/api/devbox/enroll?wait=25")
}

// CancelEnrollment withdraws the enrollment, unless it ended first, and
// returns how it ended.
func (b *Backend) CancelEnrollment(ctx context.Context) (*protocol.RequestState, error) {
	var st protocol.RequestState
	return &st, b.do(ctx, http.MethodDelete, "/api/devbox/enroll", nil, &st)
}

// Keys returns the registered keys in authorized_keys format.
func (b *Backend) Keys(ctx context.Context) (string, error) {
	var s string
	return s, b.do(ctx, http.MethodGet, "/api/devbox/keys", nil, &s)
}
