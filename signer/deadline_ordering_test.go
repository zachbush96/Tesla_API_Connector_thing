package restricted

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeadlinePolicyOrdering(t *testing.T) {
	if LiveHandlerTimeout != 50*time.Second || liveWorkTimeout != 45*time.Second ||
		LiveTLSWriteTimeout != 55*time.Second || liveFinalizationTimeout != 4*time.Second ||
		bridgeClaimTimeout != 25*time.Second || bridgeJournalTimeout != time.Second ||
		engineHandshakeTimeout != 16*time.Second || enginePhysicalTimeout != 30*time.Second ||
		minimumAttemptWindow != 13*time.Second || fleetNetworkTimeout != 10*time.Second ||
		NewHTTPConnector(target, nil).AllowedLatency() != 10*time.Second {
		t.Fatal("bounded deadline policy changed")
	}
	if liveWorkTimeout+liveFinalizationTimeout >= LiveHandlerTimeout || LiveTLSWriteTimeout <= LiveHandlerTimeout {
		t.Fatal("no room to journal and return the outcome")
	}
}

func deadlineRequest(h *liveHarness, ctx context.Context) *httptest.ResponseRecorder {
	request := httptest.NewRequest("POST", "https://"+LocalSignerAddress+"/verify_infotainment",
		bytes.NewReader(simulateRequest(infotainmentRaw(), strings.Repeat("a", 32)))).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+mockToken)
	request.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	h.service.ServeHTTP(out, request)
	return out
}

func TestDeadlineBusySignerRefusesWithoutClaimReservationOrQueue(t *testing.T) {
	h := infoHarness(t)
	h.service.mu.Lock()
	defer h.service.mu.Unlock()
	start := time.Now()
	out := deadlineRequest(h, context.Background())
	if out.Code != 409 || time.Since(start) > 250*time.Millisecond || h.claims != 0 || h.reserves != 0 || h.sends != 0 || len(h.diagnostics) != 0 {
		t.Fatal("busy service waited or acquired authorization/cost")
	}
}

func TestDeadlineCanceledAndExhaustedParentRefuseBeforeClaim(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-work-tail", true: "cancelled"}[cancelled], func(t *testing.T) {
			h := infoHarness(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if cancelled {
				cancel()
			}
			out := deadlineRequest(h, ctx)
			if out.Code != 409 || h.claims != 0 || h.reserves != 0 || h.sends != 0 {
				t.Fatal("expired/cancelled parent acquired claim or attempted transmission")
			}
		})
	}
}

func TestDeadlineInsufficientWorkRoomRefusesBeforePaidAttempt(t *testing.T) {
	h := infoHarness(t)
	// Five seconds of response/finalization tail leaves less than13 for work.
	ctx, cancel := context.WithTimeout(context.Background(), 17*time.Second)
	defer cancel()
	out := deadlineRequest(h, ctx)
	d := diagnosticResult(t, out.Body.Bytes())
	if out.Code != 409 || h.claims != 1 || h.reserves != 0 || h.sends != 0 || d.ExceptionType != "context_deadline" || d.Category != "context" || d.ReservationAcknowledged {
		t.Fatal("compressed caller deadline started a paid handshake")
	}
}

func TestDeadlineRPCHeaderCapsClaimJournalAndEarlierParent(t *testing.T) {
	for _, path := range []string{"/internal/signer/claim", "/internal/signer/reserve", "/internal/signer/diagnostic"} {
		t.Run(path, func(t *testing.T) {
			calls := 0
			parent, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			b := &bridgeClient{token: strings.Repeat("s", 64), client: &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
				calls++
				deadline, ok := r.Context().Deadline()
				cap := bridgeJournalTimeout
				if path == "/internal/signer/claim" {
					cap = bridgeClaimTimeout
				}
				remaining := time.Until(deadline)
				encoded, err := strconv.ParseInt(r.Header.Get(bridgeDeadlineHeader), 10, 64)
				if !ok || remaining <= 0 || remaining > cap || err != nil || encoded != deadline.UnixMilli() || r.GetBody != nil || r.URL.Host != "127.0.0.1:8765" {
					t.Fatal("RPC deadline/header escaped exact bounded context")
				}
				return jsonResponse(map[string]bool{"stored": true}), nil
			})}}
			var out map[string]bool
			if b.post(parent, path, map[string]bool{"synthetic": true}, &out) != nil || calls != 1 {
				t.Fatal("bounded RPC did not make exactly one synthetic attempt")
			}
			short, stop := context.WithTimeout(parent, 20*time.Millisecond)
			defer stop()
			earlier, _ := short.Deadline()
			b.client.Transport = fakeRT(func(r *http.Request) (*http.Response, error) {
				calls++
				deadline, _ := r.Context().Deadline()
				if deadline.After(earlier) {
					t.Fatal("parent deadline was extended")
				}
				return jsonResponse(map[string]bool{"stored": true}), nil
			})
			if b.post(short, path, map[string]bool{"synthetic": true}, &out) != nil || calls != 2 {
				t.Fatal("earlier parent deadline changed RPC shape")
			}
		})
	}
}

func TestDeadlineExpiredRPCResponseCannotAuthorizeNextStage(t *testing.T) {
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	b := &bridgeClient{token: strings.Repeat("s", 64), client: &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		calls++
		<-r.Context().Done()
		// A synthetic nonconforming transport returns a late valid acknowledgment.
		// The scoped postcondition still refuses it rather than advancing work.
		return jsonResponse(map[string]bool{"stored": true}), nil
	})}}
	var out map[string]bool
	if b.post(ctx, "/internal/signer/diagnostic", map[string]bool{}, &out) == nil || calls != 1 {
		t.Fatal("expired RPC response was accepted or retried")
	}
}

func TestDeadlineReservationUsesPhaseContextAndNeverRetries(t *testing.T) {
	h := infoHarness(t)
	claim, _, err := h.service.bridge.claim(context.Background(), strings.Repeat("a", 32), infotainmentRaw(), "verify_infotainment", h.service.keyHash)
	if err != nil || claim.Consume(strings.Repeat("a", 32), claim.binding) != nil {
		t.Fatal("synthetic exact claim")
	}
	callbacks := 0
	h.service.bridge.client.Transport = fakeRT(func(r *http.Request) (*http.Response, error) {
		callbacks++
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	phase, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	if claim.ReserveAttemptContext(phase, "commands", "handshake") == nil || time.Since(start) > 250*time.Millisecond || callbacks != 1 || claim.attempt != 1 || !claim.closed {
		t.Fatal("phase expiry used the wider operation context or reissued a callback")
	}
	if claim.ReserveAttemptContext(context.Background(), "commands", "handshake") == nil || callbacks != 1 {
		t.Fatal("uncertain reservation callback replayed")
	}
}

func TestDeadlineReservationPreservesOriginalParentCancellation(t *testing.T) {
	h := infoHarness(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	claim, _, err := h.service.bridge.claim(parent, strings.Repeat("a", 32), infotainmentRaw(), "verify_infotainment", h.service.keyHash)
	if err != nil || claim.Consume(strings.Repeat("a", 32), claim.binding) != nil {
		t.Fatal("synthetic exact claim")
	}
	entered := make(chan struct{})
	h.service.bridge.client.Transport = fakeRT(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	go func() { <-entered; cancel() }()
	start := time.Now()
	if claim.ReserveAttemptContext(context.Background(), "commands", "handshake") == nil || time.Since(start) > 250*time.Millisecond || !claim.closed {
		t.Fatal("reservation detached from original cancellation")
	}
}

func TestDeadlineCanceledReservationDoesNotIncrementOrCall(t *testing.T) {
	h := infoHarness(t)
	claim, _, err := h.service.bridge.claim(context.Background(), strings.Repeat("a", 32), infotainmentRaw(), "verify_infotainment", h.service.keyHash)
	if err != nil || claim.Consume(strings.Repeat("a", 32), claim.binding) != nil {
		t.Fatal("synthetic exact claim")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if claim.ReserveAttemptContext(ctx, "commands", "handshake") == nil || h.reserves != 0 || claim.attempt != 0 || h.sends != 0 || !claim.closed {
		t.Fatal("cancelled phase reserved or transmitted")
	}
	if claim.ReserveAttemptContext(context.Background(), "commands", "handshake") == nil || h.reserves != 0 {
		t.Fatal("cancelled phase reopened with a fresh context")
	}
}

func TestDeadlineDelayedDurabilityRefusesBeforeFleet(t *testing.T) {
	h := infoHarness(t)
	original := h.service.bridge.client.Transport
	var callbacks atomic.Int32
	h.service.bridge.client.Transport = fakeRT(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/internal/signer/reserve" {
			return original.RoundTrip(r)
		}
		callbacks.Add(1)
		// Simulate a committed debit whose acknowledgment stalls until the
		// journal RPC deadline. No retry or refund follows that uncertainty.
		h.mu.Lock()
		h.reserves++
		h.kinds = append(h.kinds, "handshake")
		h.mu.Unlock()
		<-r.Context().Done()
		return nil, errors.New(redactionSentinel)
	})
	start := time.Now()
	out := deadlineRequest(h, context.Background())
	d := diagnosticResult(t, out.Body.Bytes())
	if out.Code != 409 || time.Since(start) > 2*time.Second || callbacks.Load() != 1 || h.reserves != 1 || h.sends != 0 || d.ExceptionType != "bridge_refused" || d.FailureStage != "reservation_attempted" {
		t.Fatal("durability stall reached Fleet, retried, or lost bounded cause")
	}
}

func TestDeadlineFullFleetWindowCheckedBeforeWire(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: fakeRT(func(*http.Request) (*http.Response, error) { calls++; return jsonResponse(map[string]bool{}), nil })}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, fullNetworkWindowKey{}, true)
	d := newDiagnostic(nil)
	d.value.Kind = "handshake"
	d.value.Stage = "reservation_acknowledged"
	d.value.ReservationAcknowledged = true
	if _, err := roundTrip(ctx, client, target, "/signed_command", []byte(`{}`), syntheticBearer, d); err == nil || calls != 0 || d.snapshot().ExceptionType != "context_deadline" {
		t.Fatal("shortened post-reservation deadline entered Fleet transport")
	}
}

func TestDeadlineFleetWindowAndSDKLatencyRemainTenSeconds(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		calls++
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Fatal("Fleet request exceeded original10s cap")
		}
		return response(408, ""), nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, fullNetworkWindowKey{}, true)
	d := newDiagnostic(nil)
	d.value.Kind = "handshake"
	d.value.Stage = "reservation_acknowledged"
	d.value.ReservationAcknowledged = true
	if _, err := roundTrip(ctx, client, target, "/signed_command", []byte(`{}`), syntheticBearer, d); err == nil || calls != 1 || d.snapshot().HTTPStatus != 408 || NewHTTPConnector(target, nil).AllowedLatency() != 10*time.Second {
		t.Fatal("network bound, HTTP classification or no-retry shape changed")
	}
}

func TestDeadlineTerminalJournalUsesHandlerAndHonorsParentCancellation(t *testing.T) {
	handler, cancelHandler := context.WithCancel(context.Background())
	defer cancelHandler()
	work, cancelWork := context.WithCancel(handler)
	cancelWork()
	calls := 0
	d := newDiagnostic(func(ctx context.Context, _ int, _ Diagnostic) error {
		calls++
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	})
	d.noteFailure("context_deadline", "context", "none", "operation_started")
	final, cancelFinal := context.WithTimeout(handler, liveFinalizationTimeout)
	if work.Err() == nil || d.finish(final, errors.New(redactionSentinel)) == nil || calls != 1 || d.snapshot().CheckpointPersistenceFailed {
		t.Fatal("work timeout discarded still-permitted local terminal evidence")
	}
	cancelFinal()
	cancelHandler()
	d2 := newDiagnostic(func(ctx context.Context, _ int, _ Diagnostic) error { calls++; return ctx.Err() })
	final2, cancelFinal2 := context.WithTimeout(handler, liveFinalizationTimeout)
	defer cancelFinal2()
	if d2.finish(final2, errors.New(redactionSentinel)) == nil || !d2.snapshot().CheckpointPersistenceFailed || final2.Err() != context.Canceled {
		t.Fatal("terminal journal detached from original parent cancellation")
	}
}
