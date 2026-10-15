package restricted

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/connector"
	sig "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/signatures"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/proto"
)

const redactionSentinel = "SYNTHETIC_PRIVATE_SENTINEL_DO_NOT_RETAIN"

func infotainmentRaw() []byte {
	raw, _ := encodeJSON(PairingIntent{1, "synthetic-owner", target, "verify_infotainment"})
	return raw
}

func diagnosticResult(t *testing.T, body []byte) Diagnostic {
	t.Helper()
	var result struct {
		Error      string     `json:"error"`
		Diagnostic Diagnostic `json:"diagnostic"`
	}
	if json.Unmarshal(body, &result) != nil {
		t.Fatal("invalid safe diagnostic result")
	}
	if strings.Contains(string(body), redactionSentinel) || strings.Contains(string(body), target) || strings.Contains(string(body), "synthetic-local-bearer") {
		t.Fatal("private material escaped result")
	}
	return result.Diagnostic
}

func infoHarness(t *testing.T) *liveHarness {
	h := newLiveHarness(t)
	h.service.executionEnabled = false
	h.service.verificationEnabled = false
	h.service.infotainmentEnabled = true
	h.facts.Awake = false
	h.facts.Parked = false
	h.facts.Cable = false
	h.facts.MotorizedPort = false
	h.service.sessions = cached(t, um.Domain_DOMAIN_INFOTAINMENT)
	return h
}

func TestInfotainmentSeparateDefaultGateAndNoPhysicalMode(t *testing.T) {
	for _, gates := range [][3]bool{{false, false, false}, {false, true, true}, {true, false, true}, {true, true, true}} {
		if _, _, err := LoadLiveService("must-not-be-read", gates[0], gates[1], gates[2]); err == nil {
			t.Fatal("unsafe/default constructor gate")
		}
	}
	h := newLiveHarness(t)
	if liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32)).Code != 404 || h.claims != 0 || h.sends != 0 {
		t.Fatal("default diagnostic enabled")
	}
	h.service.infotainmentEnabled = true
	if liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("b", 32)).Code != 404 || h.claims != 0 || h.sends != 0 {
		t.Fatal("diagnostic with physical gate accepted")
	}
}

func TestInfotainmentOneFreshHandshakeNoPhysicalNoQueryNoGrantReceipt(t *testing.T) {
	h := infoHarness(t)
	w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
	d := diagnosticResult(t, w.Body.Bytes())
	if w.Code != 200 || h.sends != 1 || h.reserves != 1 || h.kinds[0] != "handshake" || len(h.commandPayloads) != 0 || h.stateReceipts != 0 || h.receipts != 0 || len(h.domains) != 1 || h.domains[0] != um.Domain_DOMAIN_INFOTAINMENT || !d.ReservationAcknowledged || !d.HTTPInitiated || !d.RequestWritten || !d.ResponseReceived || !d.AuthenticatedSessionReady || d.HTTPStatus != 200 || d.Stage != "operation_succeeded" || d.ExceptionType != "none" {
		t.Fatal("diagnostic exceeded handshake-only boundary or lost evidence")
	}
	if liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32)).Code != 409 || h.sends != 1 || h.reserves != 1 {
		t.Fatal("handshake authority replayed")
	}
	for n, q := range h.diagnostics {
		if q.Sequence != n+1 || q.Sequence > 32 {
			t.Fatal("checkpoint bound/order")
		}
	}
	request := httptest.NewRequest("GET", "https://"+LocalSignerAddress+"/health", nil)
	request.Header.Set("Authorization", "Bearer "+mockToken)
	w = httptest.NewRecorder()
	h.service.ServeHTTP(w, request)
	var health map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &health)
	if health["execution_enabled"] != false || health["pairing_verification_enabled"] != false || health["infotainment_diagnostic_enabled"] != true {
		t.Fatal("diagnostic falsely activates physical gates")
	}
}

func TestInfotainmentCannotReservePhysicalOrParsePhysicalIntent(t *testing.T) {
	h := infoHarness(t)
	raw := infotainmentRaw()
	claim, _, err := h.service.bridge.claim(context.Background(), strings.Repeat("a", 32), raw, "verify_infotainment", h.service.keyHash)
	if err != nil || claim.Consume(strings.Repeat("a", 32), sha256.Sum256(raw)) != nil || claim.ReserveAttempt("commands", "handshake") != nil || claim.ReserveAttempt("commands", "command") == nil || claim.ReserveAttempt("commands", "handshake") == nil || h.reserves != 1 {
		t.Fatal("diagnostic authority exceeded one 1000 command-category allowance")
	}
	for _, raw := range [][]byte{rawIntent("set_temperature", `{"driver_temp":20,"passenger_temp":20}`), pairingRaw(), []byte(`{"version":1,"principal":"synthetic-owner","target":"AAAAAAAAAAAAAAAAA","action":"verify_infotainment","payload":"ignored"}`)} {
		if liveRequest(h, "/verify_infotainment", raw, strings.Repeat("b", 32)).Code != 403 {
			t.Fatal("physical/expanded diagnostic intent allowed")
		}
	}
	if h.sends != 0 {
		t.Fatal("rejected diagnostic transmitted")
	}
}

func TestInfotainmentGuardDeniesSignedPhysicalAndStatePayloadsBeforeReserve(t *testing.T) {
	k := key(t)
	for _, payload := range [][]byte{[]byte("synthetic-physical"), []byte("synthetic-state-query")} {
		c := conn()
		b := &budget{limit: 10}
		g := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_INFOTAINMENT, public: k.PublicBytes(), budget: b, handshakeOnly: true}
		m := &um.RoutableMessage{ToDestination: &um.Destination{SubDestination: &um.Destination_Domain{Domain: um.Domain_DOMAIN_INFOTAINMENT}}, Payload: &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: payload}, SubSigData: &um.RoutableMessage_SignatureData{SignatureData: &sig.SignatureData{SignerIdentity: &sig.KeyIdentity{IdentityType: &sig.KeyIdentity_PublicKey{PublicKey: k.PublicBytes()}}, SigType: &sig.SignatureData_HMAC_PersonalizedData{HMAC_PersonalizedData: &sig.HMAC_Personalized_Signature_Data{Tag: bytes.Repeat([]byte{1}, 32)}}}}}
		raw, _ := proto.Marshal(m)
		if g.Send(context.Background(), raw) == nil || c.calls != 0 || b.calls != 0 {
			t.Fatal("diagnostic physical/state payload escaped")
		}
	}
}

func TestDiagnosticReserveRefusalDistinctFromTransmission(t *testing.T) {
	h := infoHarness(t)
	h.rejectReserveAt = 1
	w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
	d := diagnosticResult(t, w.Body.Bytes())
	if w.Code != 409 || h.reserves != 1 || h.sends != 0 || d.ReservationAcknowledged || d.HTTPInitiated || d.RequestWritten || d.ResponseReceived || d.ExceptionType != "bridge_refused" || d.FailureStage != "reservation_attempted" {
		t.Fatal("reservation failure incorrectly described as transmission")
	}
}

func TestDiagnosticCheckpointRefusalBeforeSendFailsClosed(t *testing.T) {
	for _, stage := range []string{"operation_started", "reservation_attempted", "reservation_acknowledged", "http_initiated"} {
		t.Run(stage, func(t *testing.T) {
			h := infoHarness(t)
			h.rejectDiagnosticStage = stage
			w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
			d := diagnosticResult(t, w.Body.Bytes())
			if w.Code != 409 || h.sends != 0 || d.RequestWritten || d.ResponseReceived || d.ExceptionType != "bridge_refused" || d.FailureStage != stage {
				t.Fatal("unretained pre-send checkpoint transmitted")
			}
		})
	}
}

func TestDiagnosticFailedWriteCheckpointRetainsPositiveWriteAndCannotRetry(t *testing.T) {
	h := infoHarness(t)
	h.rejectDiagnosticStage = "request_written"
	w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
	d := diagnosticResult(t, w.Body.Bytes())
	if w.Code != 409 || h.sends != 1 || h.reserves != 1 || !d.RequestWritten || d.ExceptionType != "bridge_refused" || d.FailureStage != "request_written" {
		t.Fatal("completed-write uncertainty erased or repeated")
	}
	if liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32)).Code != 409 || h.sends != 1 {
		t.Fatal("failed telemetry retried handshake")
	}
}

func TestDiagnosticTransportErrorStageStatusAndSecretRedaction(t *testing.T) {
	for _, tc := range []struct {
		name                string
		wrote               bool
		err                 error
		exception, category string
	}{
		{"before_write_tls", false, x509.UnknownAuthorityError{Cert: &x509.Certificate{DNSNames: []string{redactionSentinel}}}, "tls_certificate", "tls"},
		{"after_write_transport", true, errors.New(redactionSentinel), "network_error", "transport"},
		{"deadline", false, context.DeadlineExceeded, "context_deadline", "context"},
		{"canceled", false, context.Canceled, "context_canceled", "context"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := infoHarness(t)
			sends := 0
			h.service.fleetClient = &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
				sends++
				if tc.wrote {
					httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				}
				return nil, tc.err
			})}
			w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
			d := diagnosticResult(t, w.Body.Bytes())
			wantStage := "http_initiated"
			if tc.wrote {
				wantStage = "request_written"
			}
			if w.Code != 409 || sends != 1 || h.reserves != 1 || !d.ReservationAcknowledged || !d.HTTPInitiated || d.RequestWritten != tc.wrote || d.ResponseReceived || d.HTTPStatus != 0 || d.ExceptionType != tc.exception || d.Category != tc.category || d.FailureStage != wantStage {
				t.Fatal("typed transport evidence lost")
			}
			retained, _ := json.Marshal(h.diagnostics)
			if strings.Contains(string(retained), redactionSentinel) {
				t.Fatal("private exception retained")
			}
		})
	}
}

func TestDiagnosticHTTPStatusAndBodyNeverRetained(t *testing.T) {
	for _, status := range []int{401, 421, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			h := infoHarness(t)
			sends := 0
			h.service.fleetClient = &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
				sends++
				httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				result := response(status, `{"error":"`+redactionSentinel+`","error_description":"`+redactionSentinel+`"}`)
				result.Header.Set("X-Private", redactionSentinel)
				return result, nil
			})}
			w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
			d := diagnosticResult(t, w.Body.Bytes())
			if w.Code != 409 || sends != 1 || h.reserves != 1 || d.HTTPStatus != status || !d.RequestWritten || !d.ResponseReceived || d.AuthenticatedSessionReady || d.ExceptionType != "http_status" || d.Category != "http" || d.FailureStage != "response_received" {
				t.Fatal("HTTP status lost or mislabeled protocol")
			}
			retained, _ := json.Marshal(h.diagnostics)
			if strings.Contains(string(retained), redactionSentinel) {
				t.Fatal("private body/header retained")
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New(redactionSentinel) }
func TestDiagnosticMalformedResponseReadAndVehicleFailures(t *testing.T) {
	for _, tc := range []struct {
		name, body         string
		readFailure        bool
		exception, vehicle string
	}{
		{"malformed", redactionSentinel, false, "fleet_envelope_invalid_json", "malformed_response"},
		{"duplicate", `{"response":"AA==","response":"AA=="}`, false, "fleet_envelope_invalid_shape", "malformed_response"},
		{"fleet", `{"error":"` + redactionSentinel + `"}`, false, "fleet_envelope_error", "unclassified"},
		{"read_failure", "", true, "response_read_error", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := infoHarness(t)
			sends := 0
			h.service.fleetClient = &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
				sends++
				httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				out := response(200, tc.body)
				if tc.readFailure {
					out.Body = io.NopCloser(failingReader{})
				}
				return out, nil
			})}
			w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
			d := diagnosticResult(t, w.Body.Bytes())
			if w.Code != 409 || sends != 1 || d.HTTPStatus != 200 || !d.ResponseReceived || d.ExceptionType != tc.exception || d.VehicleError != tc.vehicle || d.AuthenticatedSessionReady {
				t.Fatal("malformed/rejection/read classification lost")
			}
			retained, _ := json.Marshal(h.diagnostics)
			if strings.Contains(string(retained), redactionSentinel) {
				t.Fatal("unsafe response retention")
			}
		})
	}
}

func TestDiagnosticSessionRejectionAndSDKAuthenticationDistinct(t *testing.T) {
	for _, badTag := range []bool{false, true} {
		h := infoHarness(t)
		h.badTag = badTag
		h.nonOKSession = !badTag
		w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
		d := diagnosticResult(t, w.Body.Bytes())
		if w.Code != 409 || h.sends != 1 || h.reserves != 1 || d.AuthenticatedSessionReady || d.HTTPStatus != 200 || !d.ResponseReceived {
			t.Fatal("invalid session authenticated or retried")
		}
		if !badTag && (d.ExceptionType != "vehicle_rejected" || d.VehicleError != "not_whitelisted") {
			t.Fatal("vehicle key rejection classification lost")
		}
		if badTag && (d.ExceptionType != "session_info_hmac_mismatch" || d.Category != "authentication" || d.FailureStage != "response_received") {
			t.Fatal("exact session authentication failure lost")
		}
	}
}

func TestDiagnosticKeepsAuthenticatedSessionWhenCommandBegins(t *testing.T) {
	h := newLiveHarness(t)
	h.uncertain = true
	w := liveRequest(h, "/execute", rawIntent("set_temperature", `{"driver_temp":20,"passenger_temp":20}`), strings.Repeat("a", 32))
	d := diagnosticResult(t, w.Body.Bytes())
	if w.Code != 409 || h.sends != 2 || h.reserves != 2 || d.Kind != "command" || !d.AuthenticatedSessionReady || !d.RequestWritten || d.ResponseReceived || d.HTTPStatus != 0 {
		t.Fatal("wire evidence incorrectly inherited or authenticated session erased")
	}
}

func TestDiagnosticInvalidBearerAfterReserveProvesZeroHTTP(t *testing.T) {
	raw := infotainmentRaw()
	b := &budget{limit: 1}
	d := newDiagnostic(nil)
	calls := 0
	k := key(t)
	e := &Engine{Owner: "synthetic-owner", Target: target, Authority: &authority{binding: sha256.Sum256(raw)}, Budget: b, Key: k, diagnostic: d, NewConnector: func(v string) connector.Connector {
		c := NewHTTPConnector(v, &http.Client{Transport: fakeRT(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New(redactionSentinel) })}, func(context.Context) (string, error) { return "", errors.New(redactionSentinel) })
		c.key = k
		c.diagnostic = d
		return c
	}}
	err := e.VerifyInfotainment(context.Background(), raw, "synthetic-owner-ticket", facts())
	_ = d.finish(context.Background(), err)
	v := d.snapshot()
	if err == nil || b.calls != 1 || calls != 0 || !v.ReservationAcknowledged || v.HTTPInitiated || v.RequestWritten || v.ResponseReceived || v.ExceptionType != "local_refused" {
		t.Fatal("reservation confused with absent HTTP attempt")
	}
}

func TestDiagnosticRecorderBoundAndUniqueStages(t *testing.T) {
	d := newDiagnostic(nil)
	ctx := context.Background()
	if d.emit(ctx, "operation_started") != nil || d.emit(ctx, "operation_started") != nil || d.sequence != 1 {
		t.Fatal("duplicate retained checkpoint")
	}
	for _, kind := range diagnosticKinds {
		for _, stage := range diagnosticStages {
			if d.sequence == 32 {
				break
			}
			d.value.Kind = kind
			_ = d.emit(ctx, stage)
		}
	}
	d.value.Kind = "navigation"
	if d.sequence != 32 || d.emit(ctx, "operation_succeeded") == nil {
		t.Fatal("unbounded diagnostics")
	}
}

func TestDiagnosticLoopbackBridgeDoesNotInheritFleetTraceOrReenterRecorder(t *testing.T) {
	var bridgeWrites atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridgeWrites.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"stored":true}`)
	}))
	defer server.Close()
	localURL, _ := url.Parse(server.URL)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.DisableKeepAlives = true
	defer base.CloseIdleConnections()
	b := &bridgeClient{token: strings.Repeat("s", 32), client: &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		if httptrace.ContextClientTrace(r.Context()) != nil {
			t.Error("Fleet trace inherited by loopback bridge")
		}
		clone := r.Clone(r.Context())
		clone.URL.Scheme, clone.URL.Host, clone.Host = localURL.Scheme, localURL.Host, localURL.Host
		return base.RoundTrip(clone)
	})}}
	d := newDiagnostic(func(ctx context.Context, sequence int, value Diagnostic) error {
		var out struct {
			Stored bool `json:"stored"`
		}
		return b.post(ctx, "/internal/signer/diagnostic", diagnosticRequest{strings.Repeat("a", 32), strings.Repeat("b", 64), sequence, value}, &out)
	})
	var fleetWrites atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) {
		fleetWrites.Add(1)
		_ = d.milestone(ctx, "request_written", 0)
	}})
	done := make(chan error, 1)
	go func() { done <- d.milestone(ctx, "http_initiated", 0) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("local checkpoint refused")
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("loopback trace reentered recorder and deadlocked")
	}
	if fleetWrites.Load() != 0 || bridgeWrites.Load() != 1 || d.snapshot().RequestWritten {
		t.Fatal("bridge write misclassified as Fleet write")
	}
	// Explicitly simulate the Fleet hook; the second bridge write must retain
	// it exactly once without inheriting/re-entering that hook itself.
	httptrace.ContextClientTrace(ctx).WroteRequest(httptrace.WroteRequestInfo{})
	if fleetWrites.Load() != 1 || bridgeWrites.Load() != 2 || !d.snapshot().RequestWritten {
		t.Fatal("isolated Fleet write checkpoint not retained")
	}
}

func TestBridgeTraceIsolationPreservesOriginalDeadlineAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { t.Fatal("unexpected bridge trace") }})
	isolated := bridgeContext{ctx}
	d1, _ := ctx.Deadline()
	d2, ok := isolated.Deadline()
	if !ok || !d1.Equal(d2) || httptrace.ContextClientTrace(isolated) != nil {
		t.Fatal("bridge trace leaked or original deadline replaced")
	}
	cancel()
	select {
	case <-isolated.Done():
	default:
		t.Fatal("bridge cancellation detached from parent")
	}
	if isolated.Err() != context.Canceled {
		t.Fatal("parent cancellation category lost")
	}
}

type neverReadErrorBody struct{ reads *atomic.Int32 }

func (r neverReadErrorBody) Read([]byte) (int, error) {
	r.reads.Add(1)
	return 0, errors.New(redactionSentinel)
}
func (r neverReadErrorBody) Close() error { return nil }

func TestDiagnosticNon200NeverReadsErrorBodyEvenIfBroken(t *testing.T) {
	for _, status := range []int{401, 421, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			h := infoHarness(t)
			var reads atomic.Int32
			h.service.fleetClient = &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
				httptrace.ContextClientTrace(r.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				out := response(status, "")
				out.Body = neverReadErrorBody{&reads}
				return out, nil
			})}
			w := liveRequest(h, "/verify_infotainment", infotainmentRaw(), strings.Repeat("a", 32))
			d := diagnosticResult(t, w.Body.Bytes())
			if w.Code != 409 || reads.Load() != 0 || d.HTTPStatus != status || d.ExceptionType != "http_status" || d.Category != "http" || !d.ResponseReceived {
				t.Fatal("HTTP status obscured by error-body access")
			}
		})
	}
}

func TestDiagnosticParkQueryKindMatchesDurableReservation(t *testing.T) {
	h := newLiveHarness(t)
	w := liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("a", 32))
	if w.Code != 200 {
		t.Fatal("Park diagnostic contract broke existing action")
	}
	seenQuery := false
	for _, q := range h.diagnostics {
		if q.Kind == "state_command" {
			t.Fatal("unsupported diagnostic kind")
		}
		if q.Kind == "state_query" && q.Stage == "reservation_acknowledged" {
			seenQuery = true
		}
	}
	if !seenQuery || strings.Join(h.kinds, ",") != "state_handshake,state_query,command" {
		t.Fatal("checkpoint kind differs from durable wire kind")
	}
}

func TestDefaultMockHealthReportsInfotainmentGateDisabled(t *testing.T) {
	m := testService(t)
	request := httptest.NewRequest("GET", "https://"+LocalSignerAddress+"/health", nil)
	request.Header.Set("Authorization", "Bearer "+mockToken)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, request)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || out["infotainment_diagnostic_enabled"] != false || out["execution_enabled"] != false {
		t.Fatal("default mock diagnostic gate omitted or enabled")
	}
}
