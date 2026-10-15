package restricted

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/protocol"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/proto"
)

func TestFleetEnvelopeClosedBranchClassification(t *testing.T) {
	for _, tc := range []struct{ name, body, exception, vehicle string }{
		{"valid", `{"response":"AQID"}`, "none", "none"},
		{"legacy_array", `{"response":[1,2,3]}`, "none", "none"},
		{"empty_body", "", "fleet_envelope_invalid_json", "malformed_response"},
		{"invalid_json", redactionSentinel, "fleet_envelope_invalid_json", "malformed_response"},
		{"trailing_value", `{"response":"AQID"} {}`, "fleet_envelope_invalid_json", "malformed_response"},
		{"duplicate", `{"response":"AQID","response":"AQID"}`, "fleet_envelope_invalid_shape", "malformed_response"},
		{"unknown_field", `{"response":"AQID","private":"` + redactionSentinel + `"}`, "fleet_envelope_invalid_shape", "malformed_response"},
		{"array", `[]`, "fleet_envelope_invalid_shape", "malformed_response"},
		{"null_envelope", `null`, "fleet_envelope_invalid_shape", "malformed_response"},
		{"wrong_payload_type", `{"response":true}`, "fleet_envelope_invalid_shape", "malformed_response"},
		{"bad_base64", `{"response":"` + redactionSentinel + `"}`, "fleet_envelope_invalid_base64", "malformed_response"},
		{"missing_payload", `{}`, "fleet_response_missing", "malformed_response"},
		{"null_payload", `{"response":null}`, "fleet_response_missing", "malformed_response"},
		{"empty_payload", `{"response":""}`, "fleet_response_missing", "malformed_response"},
		{"fleet_error", `{"response":null,"error":"` + redactionSentinel + `","error_description":"` + redactionSentinel + `"}`, "fleet_envelope_error", "unclassified"},
		{"error_with_payload", `{"response":"AQID","error":"` + redactionSentinel + `"}`, "fleet_envelope_error", "unclassified"},
		{"description_only", `{"response":"AQID","error_description":"` + redactionSentinel + `"}`, "none", "none"},
		{"null_error", `{"response":"AQID","error":null}`, "none", "none"},
		{"wrong_error_type", `{"response":"AQID","error":true}`, "fleet_envelope_invalid_shape", "malformed_response"},
		{"wrong_description_type", `{"response":"AQID","error_description":{}}`, "fleet_envelope_invalid_shape", "malformed_response"},
		{"envelope_bound", strings.Repeat(" ", 16385), "fleet_envelope_too_large", "malformed_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := decodeFleetEnvelope([]byte(tc.body))
			if tc.exception == "none" {
				if err != nil || !bytes.Equal(payload, []byte{1, 2, 3}) {
					t.Fatal("pinned base64 envelope acceptance changed")
				}
				return
			}
			var failure *replyFailure
			if payload != nil || !errors.As(err, &failure) || failure.exception != tc.exception || failure.category != "fleet" || failure.vehicle != tc.vehicle {
				t.Fatal("Fleet envelope fixed branch classification differs")
			}
			if err.Error() != "restricted response refused" {
				t.Fatal("Fleet error retained private text")
			}
			d := newDiagnostic(nil)
			d.replyFailure(err)
			raw, _ := json.Marshal(d.snapshot())
			if strings.Contains(string(raw), redactionSentinel) {
				t.Fatal("Fleet fields leaked into diagnostic")
			}
		})
	}
}

func TestDiagnosticEnvelopeRoutingAndHMACFailuresStaySingleAttempt(t *testing.T) {
	for _, tc := range []struct {
		name, exception, category, vehicle string
		response                           func(*testing.T, *http.Request) *http.Response
	}{
		{"fleet_error", "fleet_envelope_error", "fleet", "unclassified", func(_ *testing.T, _ *http.Request) *http.Response {
			return response(200, `{"error":"`+redactionSentinel+`"}`)
		}},
		{"invalid_protobuf", "routable_invalid_protobuf", "routable", "malformed_response", func(_ *testing.T, _ *http.Request) *http.Response {
			return jsonResponse(map[string][]byte{"response": {0xff}})
		}},
		{"destination_missing", "routable_destination_missing", "routable", "none", func(t *testing.T, r *http.Request) *http.Response {
			var outer struct {
				Message []byte `json:"routable_message"`
			}
			_ = json.NewDecoder(r.Body).Decode(&outer)
			f := newReplyDiagnosticFixture(t)
			f.request = &um.RoutableMessage{}
			if proto.Unmarshal(outer.Message, f.request) != nil {
				t.Fatal("synthetic request malformed")
			}
			f.response.FromDestination, f.response.RequestUuid, f.response.ToDestination = f.request.ToDestination, f.request.Uuid, nil
			return jsonResponse(map[string][]byte{"response": replyDiagnosticMarshal(t, f.response)})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := infoHarness(t)
			sends := 0
			h.service.fleetClient = &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
				sends++
				httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				return tc.response(t, r), nil
			})}
			id := strings.Repeat("a", 32)
			w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), id)
			d := diagnosticResult(t, w.Body.Bytes())
			if w.Code != 409 || sends != 1 || h.reserves != 1 || d.ExceptionType != tc.exception || d.Category != tc.category || d.VehicleError != tc.vehicle || d.FailureStage != "response_received" || !d.ResponseReceived || d.HTTPStatus != 200 || d.AuthenticatedSessionReady {
				t.Fatal("single-handshake boundary or fixed failure cause lost")
			}
			if liveRequest(h, "/verify_infotainment", infotainmentRaw(), id).Code != 409 || sends != 1 || h.reserves != 1 {
				t.Fatal("failed diagnostic permitted retry")
			}
			stored, _ := json.Marshal(h.diagnostics)
			if strings.Contains(string(stored), redactionSentinel) {
				t.Fatal("private synthetic data retained")
			}
		})
	}
}

type typedFailingReader struct{ err error }

func (r typedFailingReader) Read([]byte) (int, error) { return 0, r.err }

type syntheticTimeout struct{}

func (syntheticTimeout) Error() string   { return redactionSentinel }
func (syntheticTimeout) Timeout() bool   { return true }
func (syntheticTimeout) Temporary() bool { return true }

func TestDiagnosticResponseReadTypesSizeAndMediaType(t *testing.T) {
	for _, tc := range []struct {
		name, exception, category string
		err                       error
		large                     bool
		media                     string
	}{
		{"read_deadline", "context_deadline", "context", context.DeadlineExceeded, false, "application/json"},
		{"read_cancel", "context_canceled", "context", context.Canceled, false, "application/json"},
		{"read_timeout", "network_timeout", "transport", syntheticTimeout{}, false, "application/json"},
		{"read_dns_timeout", "network_dns", "transport", &net.DNSError{Err: redactionSentinel, IsTimeout: true}, false, "application/json"},
		{"read_reset", "network_reset", "transport", syscall.ECONNRESET, false, "application/json"},
		{"read_generic", "response_read_error", "response", errors.New(redactionSentinel), false, "application/json"},
		{"body_size", "response_too_large", "response", nil, true, "application/json"},
		{"media_type", "response_content_type", "response", nil, false, "text/plain; private=" + redactionSentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := infoHarness(t)
			h.service.fleetClient = &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
				httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				out := response(200, `{"response":"AQID"}`)
				out.Header.Set("Content-Type", tc.media)
				if tc.err != nil {
					out.Body = io.NopCloser(typedFailingReader{tc.err})
				}
				if tc.large {
					out.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 100001)))
				}
				return out, nil
			})}
			w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
			d := diagnosticResult(t, w.Body.Bytes())
			if w.Code != 409 || h.reserves != 1 || d.ExceptionType != tc.exception || d.Category != tc.category || !d.ResponseReceived || d.HTTPStatus != 200 || d.AuthenticatedSessionReady {
				t.Fatal("bounded read failure classification lost")
			}
		})
	}
}

func TestDiagnosticSDKFixedSentinelsAndTransportTypes(t *testing.T) {
	for _, tc := range []struct {
		name, exception, category string
		err                       error
	}{
		{"key_not_paired", "sdk_key_not_paired", "sdk", protocol.ErrKeyNotPaired},
		{"invalid_public_key", "sdk_invalid_public_key", "sdk", protocol.ErrInvalidPublicKey},
		{"bad_response", "sdk_bad_response", "sdk", protocol.ErrBadResponse},
		{"no_session", "sdk_no_session", "sdk", protocol.ErrNoSession},
		{"not_connected", "sdk_not_connected", "sdk", protocol.ErrNotConnected},
		{"requires_key", "sdk_requires_key", "sdk", protocol.ErrRequiresKey},
		{"protocol_unsupported", "sdk_protocol_unsupported", "sdk", protocol.ErrProtocolNotSupported},
		{"replayed_response", "sdk_replayed_response", "sdk", protocol.ErrReplayedResponse},
		{"changed_public_key", "sdk_unexpected_public_key", "sdk", protocol.ErrUnpexpectedPublicKey},
		{"no_decryption", "sdk_no_decryption_context", "sdk", protocol.ErrNoDecryptionContext},
		{"requires_encryption", "sdk_requires_encryption", "sdk", protocol.ErrRequiresEncryption},
		{"requires_ble", "sdk_requires_ble", "sdk", protocol.ErrRequiresBLE},
		{"busy", "sdk_busy", "sdk", protocol.ErrBusy},
		{"unknown", "sdk_unknown", "sdk", protocol.ErrUnknown},
		{"dns", "network_dns", "transport", &net.DNSError{Err: redactionSentinel, Name: redactionSentinel}},
		{"refused", "network_refused", "transport", syscall.ECONNREFUSED},
		{"reset", "network_reset", "transport", syscall.ECONNRESET},
		{"tls_handshake", "tls_handshake", "tls", tls.RecordHeaderError{Msg: redactionSentinel}},
		{"deadline", "context_deadline", "context", context.DeadlineExceeded},
		{"cancel", "context_canceled", "context", context.Canceled},
		{"nominal", "sdk_nominal_error", "sdk", &protocol.NominalError{Details: errors.New(redactionSentinel)}},
		{"unrecognized_after_validated", "sdk_error", "sdk", errors.New(redactionSentinel)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDiagnostic(nil)
			d.value.Kind = "handshake"
			d.value.Stage = "response_validated"
			d.sdkFailure(fmt.Errorf("%s: %w", redactionSentinel, tc.err))
			v := d.snapshot()
			raw, _ := json.Marshal(v)
			if v.ExceptionType != tc.exception || v.Category != tc.category || v.FailureStage != "response_validated" || strings.Contains(string(raw), redactionSentinel) {
				t.Fatal("SDK error classification inferred a cause or exposed error text")
			}
		})
	}
	for _, fault := range []um.MessageFault_E{um.MessageFault_E_MESSAGEFAULT_ERROR_BUSY, um.MessageFault_E(12345)} {
		d := newDiagnostic(nil)
		d.sdkFailure(&protocol.RoutableMessageError{Code: fault})
		v := d.snapshot()
		if v.ExceptionType != "sdk_routable_fault" || (fault == um.MessageFault_E_MESSAGEFAULT_ERROR_BUSY && v.VehicleError != "busy") || (fault != um.MessageFault_E_MESSAGEFAULT_ERROR_BUSY && v.VehicleError != "unknown_fault") {
			t.Fatal("typed SDK routable fault discarded")
		}
	}
}

func TestDiagnosticPrimaryCauseSurvivesTerminalCheckpointFailure(t *testing.T) {
	for _, tc := range []struct{ exception, category, vehicle string }{
		{"fleet_envelope_error", "fleet", "unclassified"}, {"session_info_hmac_mismatch", "authentication", "none"}, {"vehicle_rejected", "vehicle", "not_whitelisted"}, {"http_status", "http", "none"}, {"context_deadline", "context", "none"},
	} {
		t.Run(tc.exception, func(t *testing.T) {
			d := newDiagnostic(func(_ context.Context, _ int, v Diagnostic) error {
				if v.Stage == "operation_failed" {
					return errors.New(redactionSentinel)
				}
				return nil
			})
			d.value.Kind = "handshake"
			d.value.HTTPStatus = 200
			d.value.ResponseReceived = true
			d.noteFailure(tc.exception, tc.category, tc.vehicle, "response_received")
			if d.finish(context.Background(), refused) == nil {
				t.Fatal("unpersisted failure was accepted")
			}
			v := d.snapshot()
			if v.ExceptionType != tc.exception || v.Category != tc.category || v.VehicleError != tc.vehicle || v.FailureStage != "response_received" || !v.CheckpointPersistenceFailed || v.LocalFinalizationFailed || v.HTTPStatus != 200 || !v.ResponseReceived {
				t.Fatal("checkpoint failure replaced primary cause or erased response evidence")
			}
		})
	}
}

func TestDiagnosticUnknownVocabularyNeverRetained(t *testing.T) {
	d := newDiagnostic(nil)
	d.noteFailure(redactionSentinel, redactionSentinel, redactionSentinel, redactionSentinel)
	raw, _ := json.Marshal(d.snapshot())
	if strings.Contains(string(raw), redactionSentinel) || d.snapshot().ExceptionType != "local_refused" {
		t.Fatal("unclosed diagnostic vocabulary retained")
	}
	d = newDiagnostic(nil)
	d.value.Kind = redactionSentinel
	if d.emit(context.Background(), redactionSentinel) == nil {
		t.Fatal("unknown stage/kind accepted")
	}
	raw, _ = json.Marshal(d.snapshot())
	if strings.Contains(string(raw), redactionSentinel) {
		t.Fatal("invalid stage/kind retained")
	}
}

func TestDiagnosticGuardRetryCannotReserveOrReplacePrimaryCause(t *testing.T) {
	for _, primary := range []bool{false, true} {
		f := newReplyDiagnosticFixture(t)
		c := conn()
		c.drop = true
		b := &budget{limit: 2}
		d := newDiagnostic(nil)
		g := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_INFOTAINMENT, public: f.local.PublicBytes(), budget: b, handshakeOnly: true, diagnostic: d}
		raw := replyDiagnosticMarshal(t, f.request)
		if g.Send(context.Background(), raw) != nil {
			t.Fatal("first synthetic handshake refused")
		}
		if primary {
			d.noteFailure("session_info_hmac_mismatch", "authentication", "none", "response_received")
		}
		if g.Send(context.Background(), raw) == nil || b.calls != 1 || c.calls != 1 {
			t.Fatal("SDK retry reached reservation or wire")
		}
		v := d.snapshot()
		want := "guard_handshake_retry_blocked"
		if primary {
			want = "session_info_hmac_mismatch"
		}
		if v.ExceptionType != want {
			t.Fatal("retry cause lost or primary cause replaced")
		}
	}
}

func TestDiagnosticLateSessionResponseRemainsTerminal(t *testing.T) {
	f := newReplyDiagnosticFixture(t)
	start := time.Now()
	calls := 0
	d := newDiagnostic(nil)
	c := NewHTTPConnector(target, &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		calls++
		httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
		return jsonResponse(map[string][]byte{"response": replyDiagnosticMarshal(t, f.response)}), nil
	})}, syntheticBearer)
	c.key = f.local
	c.diagnostic = d
	c.now = func() time.Time {
		if calls == 0 {
			return start
		}
		return start.Add(11 * time.Second)
	}
	_ = d.beginAttempt(context.Background(), "handshake")
	_ = d.milestone(context.Background(), "reservation_acknowledged", 0)
	if c.Send(context.Background(), replyDiagnosticMarshal(t, f.request)) == nil || calls != 1 || d.snapshot().ExceptionType != "session_info_late" || d.snapshot().AuthenticatedSessionReady || len(c.remotePublic) != 0 {
		t.Fatal("expired session response authenticated or lost fixed cause")
	}
}

type diagnosticAdvancingBudget struct {
	calls   int
	advance func()
}

func (b *diagnosticAdvancingBudget) Reserve(category string) error {
	if category != "commands" || b.calls != 0 {
		return refused
	}
	b.calls++
	if b.advance != nil {
		b.advance()
	}
	return nil
}

func TestDiagnosticSessionWindowIncludesReserveAndValidationCheckpoints(t *testing.T) {
	for _, phase := range []string{"reserve", "validation"} {
		t.Run(phase, func(t *testing.T) {
			f := newReplyDiagnosticFixture(t)
			clock := time.Now()
			sends := 0
			advance := func() { clock = clock.Add(11 * time.Second) }
			d := newDiagnostic(func(_ context.Context, _ int, v Diagnostic) error {
				if phase == "validation" && v.Stage == "response_validated" {
					advance()
				}
				return nil
			})
			b := &diagnosticAdvancingBudget{}
			if phase == "reserve" {
				b.advance = advance
			}
			c := NewHTTPConnector(target, &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
				sends++
				httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				return jsonResponse(map[string][]byte{"response": replyDiagnosticMarshal(t, f.response)}), nil
			})}, syntheticBearer)
			c.key, c.diagnostic, c.now = f.local, d, func() time.Time { return clock }
			g := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_INFOTAINMENT, public: f.local.PublicBytes(), budget: b, handshakeOnly: true, diagnostic: d}
			if g.Send(context.Background(), replyDiagnosticMarshal(t, f.request)) == nil {
				t.Fatal("expired synthetic session window accepted")
			}
			v := d.snapshot()
			wantSends, wantStage := 0, "reservation_acknowledged"
			if phase == "validation" {
				wantSends, wantStage = 1, "response_validated"
			}
			if sends != wantSends || b.calls != 1 || v.ExceptionType != "session_info_late" || v.FailureStage != wantStage || v.AuthenticatedSessionReady || v.ResponseReceived != (phase == "validation") || len(c.inbox) != 0 {
				t.Fatal("local callback latency lost or expired reply enqueued")
			}
			if g.Send(context.Background(), replyDiagnosticMarshal(t, f.request)) == nil || sends != wantSends || b.calls != 1 {
				t.Fatal("late window enabled repeat transmission")
			}
		})
	}
}

func TestDiagnosticCanceledAfterValidationNeverEnqueuesReply(t *testing.T) {
	f := newReplyDiagnosticFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := newDiagnostic(func(_ context.Context, _ int, v Diagnostic) error {
		if v.Stage == "response_validated" {
			cancel()
		}
		return nil
	})
	c := NewHTTPConnector(target, &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
		return jsonResponse(map[string][]byte{"response": replyDiagnosticMarshal(t, f.response)}), nil
	})}, syntheticBearer)
	c.key, c.diagnostic = f.local, d
	_ = d.beginAttempt(ctx, "handshake")
	_ = d.milestone(ctx, "reservation_acknowledged", 0)
	if c.Send(ctx, replyDiagnosticMarshal(t, f.request)) == nil || len(c.inbox) != 0 || d.snapshot().ExceptionType != "context_canceled" || d.snapshot().FailureStage != "response_validated" {
		t.Fatal("expired parent context raced a buffered reply enqueue")
	}
}

func TestDiagnosticKnownHTTPFailureSurvivesResponseCheckpointRefusal(t *testing.T) {
	h := infoHarness(t)
	h.rejectDiagnosticStage = "response_received"
	h.service.fleetClient = &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
		return response(401, redactionSentinel), nil
	})}
	w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
	d := diagnosticResult(t, w.Body.Bytes())
	if w.Code != 409 || h.reserves != 1 || d.ExceptionType != "http_status" || d.Category != "http" || d.HTTPStatus != 401 || !d.ResponseReceived || !d.CheckpointPersistenceFailed || d.AuthenticatedSessionReady || d.FailureStage != "response_received" {
		t.Fatal("known HTTP cause was masked by failed checkpoint")
	}
}

func TestDiagnosticSuccessCheckpointFailureReturnsFailedStageAndOneAttempt(t *testing.T) {
	h := infoHarness(t)
	h.rejectDiagnosticStage = "operation_succeeded"
	id := strings.Repeat("a", 32)
	w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), id)
	d := diagnosticResult(t, w.Body.Bytes())
	if w.Code != 409 || h.sends != 1 || h.reserves != 1 || d.Stage != "operation_failed" || d.ExceptionType != "bridge_refused" || d.FailureStage != "operation_succeeded" || !d.CheckpointPersistenceFailed || !d.AuthenticatedSessionReady || d.LocalFinalizationFailed {
		t.Fatal("unpersisted operation was falsely presented as success")
	}
	if liveRequest(h, "/verify_infotainment", infotainmentRaw(), id).Code != 409 || h.sends != 1 || h.reserves != 1 {
		t.Fatal("final checkpoint failure permitted replay")
	}
}

func TestDiagnosticContextBeforeGuardReserveKeepsTypedCause(t *testing.T) {
	for _, tc := range []struct {
		name, exception string
		deadline        bool
	}{{"cancel", "context_canceled", false}, {"deadline", "context_deadline", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if tc.deadline {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				cancel()
			}
			defer cancel()
			f := newReplyDiagnosticFixture(t)
			c := conn()
			b := &budget{limit: 1}
			d := newDiagnostic(nil)
			g := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_INFOTAINMENT, public: f.local.PublicBytes(), budget: b, handshakeOnly: true, diagnostic: d}
			if g.Send(ctx, replyDiagnosticMarshal(t, f.request)) == nil || b.calls != 0 || c.calls != 0 || d.snapshot().ExceptionType != tc.exception {
				t.Fatal("pre-reservation context cause discarded or transmitted")
			}
			d = newDiagnostic(nil)
			e := &Engine{diagnostic: d}
			if e.VerifyInfotainment(ctx, infotainmentRaw(), "synthetic-owner-ticket", facts()) == nil || d.snapshot().ExceptionType != tc.exception {
				t.Fatal("initial handshake context was hidden by local refusal")
			}
			for _, mode := range []string{"pairing", "run", "parked"} {
				d = newDiagnostic(nil)
				e = &Engine{diagnostic: d}
				var err error
				switch mode {
				case "pairing":
					err = e.VerifyPairing(ctx, pairingRaw(), "synthetic-owner-ticket", facts())
				case "run":
					err = e.Run(ctx, rawIntent("climate_start", "{}"), "synthetic-owner-ticket", facts())
				case "parked":
					_, err = e.ReadParked(ctx, rawIntent("set_temperature", `{"driver_temp":20,"passenger_temp":20}`), "synthetic-owner-ticket", facts())
				}
				if err == nil || d.snapshot().ExceptionType != tc.exception {
					t.Fatal("initial SDK mode hid typed context failure")
				}
			}
		})
	}
}
