package restricted

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/cache"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	cs "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	sig "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/signatures"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type liveHarness struct {
	mu                                                                sync.Mutex
	t                                                                 *testing.T
	service                                                           *LiveService
	claimed                                                           map[string]bool
	bindings                                                          map[string]string
	claims, reserves, sends, receipts, stateReceipts                  int
	kinds                                                             []string
	domains                                                           []um.Domain
	facts                                                             Facts
	badTag, uncertain, rejectReserve, badClaim                        bool
	badCommandStatus, badDrive, staleDrive, futureDrive, nonOKSession bool
	badNonce                                                          bool
	omitOuterStatus, nonOKOuterStatus                                 bool
	peers                                                             map[um.Domain]protocol.ECDHPrivateKey
	mutateDrive                                                       func(*cs.DriveState)
	commandPayloads                                                   [][]byte
	diagnostics                                                       []diagnosticRequest
	rejectDiagnosticStage                                             string
	rejectReserveAt                                                   int
}

func jsonResponse(value any) *http.Response {
	raw, _ := encodeJSON(value)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}
}

func newLiveHarness(t *testing.T) *liveHarness {
	t.Helper()
	mock := testService(t)
	digest := sha256.Sum256(mock.existingKey.PublicBytes())
	s := &LiveService{mock: mock, verificationEnabled: true, executionEnabled: true, keyHash: hex.EncodeToString(digest[:]), sessions: cache.New(1)}
	h := &liveHarness{t: t, service: s, claimed: map[string]bool{}, bindings: map[string]string{}, facts: facts(), peers: map[um.Domain]protocol.ECDHPrivateKey{}}
	h.facts.Scopes["vehicle_device_data"] = true
	s.bridge = &bridgeClient{token: bridgeCapability(mock.token), client: &http.Client{Transport: fakeRT(h.bridgeRoundTrip)}}
	s.fleetClient = &http.Client{Transport: fakeRT(h.fleetRoundTrip)}
	return h
}

func (h *liveHarness) bridgeRoundTrip(request *http.Request) (*http.Response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if request.URL.Scheme != "http" || request.URL.Host != "127.0.0.1:8765" || request.GetBody != nil || request.Method != "POST" || request.Header.Get("Authorization") != "Bearer "+bridgeCapability(h.service.mock.token) {
		h.t.Fatal("bridge transport escaped fixed protected contract")
	}
	raw, _ := io.ReadAll(request.Body)
	switch request.URL.Path {
	case "/internal/signer/claim":
		var q claimRequest
		if strictJSON(raw, &q) != nil || q.SigningKeySHA256 != h.service.keyHash || h.claimed[q.OperationID] {
			return response(409, `{"error":"refused"}`), nil
		}
		h.claims++
		h.claimed[q.OperationID] = true
		digest := sha256.Sum256(q.Intent)
		h.bindings[q.OperationID] = hex.EncodeToString(digest[:])
		f := h.facts
		scopes := []string{}
		for _, scope := range []string{"vehicle_cmds", "vehicle_charging_cmds", "vehicle_device_data"} {
			if f.Scopes[scope] {
				scopes = append(scopes, scope)
			}
		}
		driveObserved := int64(0)
		if !f.DriveObserved.IsZero() {
			driveObserved = f.DriveObserved.UnixMilli()
		}
		out := claimResponse{Bearer: "synthetic-local-bearer", Facts: bridgeFacts{CableAbsent:f.CableAbsent, ClimateActive:f.ClimateActive, UserPresent:f.UserPresent, MobileAccess:f.MobileAccess, Scopes: scopes, Paired: f.Paired, SigningReady: f.SigningReady, ProtocolKnown: f.ProtocolKnown, Parked: f.Parked, Awake: f.Awake, Cable: f.Cable, MotorizedPort: f.MotorizedPort, ObservedUnixMS: f.Observed.UnixMilli(), DriveObservedUnixMS: driveObserved}}
		if h.badClaim {
			return response(200, `{"bearer":"synthetic-local-bearer","facts":{},"untrusted":true}`), nil
		}
		return jsonResponse(out), nil
	case "/internal/signer/reserve":
		var q reserveRequest
		if strictJSON(raw, &q) != nil || !h.claimed[q.OperationID] || q.BindingSHA256 != h.bindings[q.OperationID] || q.Category != "commands" || q.Attempt < 1 || q.Attempt > 4 {
			h.t.Fatal("unbound reserve reached bridge")
		}
		h.reserves++
		h.kinds = append(h.kinds, q.Kind)
		if (h.rejectReserve && q.Attempt == 3) || (h.rejectReserveAt > 0 && q.Attempt == h.rejectReserveAt) {
			return jsonResponse(map[string]bool{"reserved": false}), nil
		}
		return jsonResponse(map[string]bool{"reserved": true}), nil
	case "/internal/signer/diagnostic":
		var q diagnosticRequest
		if strictJSON(raw, &q) != nil || !h.claimed[q.OperationID] || q.BindingSHA256 != h.bindings[q.OperationID] || q.Sequence < 1 || q.Sequence > 32 {
			h.t.Fatal("invalid diagnostic callback")
		}
		if q.Stage == h.rejectDiagnosticStage {
			return response(409, `{}`), nil
		}
		h.diagnostics = append(h.diagnostics, q)
		return jsonResponse(map[string]bool{"stored": true}), nil
	case "/internal/signer/state":
		var q struct {
			OperationID      string `json:"operation_id"`
			BindingSHA256    string `json:"binding_sha256"`
			SigningKeySHA256 string `json:"signing_key_sha256"`
			Parked           bool   `json:"parked"`
			Awake            bool   `json:"awake"`
			ObservedUnixMS   int64  `json:"observed_unix_ms"`
			SDKCommit        string `json:"sdk_commit"`
		}
		if strictJSON(raw, &q) != nil || q.BindingSHA256 != h.bindings[q.OperationID] || q.SigningKeySHA256 != h.service.keyHash || !q.Parked || !q.Awake || q.SDKCommit != SDKCommit || time.Now().UnixMilli()-q.ObservedUnixMS > 60000 || q.ObservedUnixMS < h.facts.DriveObserved.UnixMilli() || h.sends < 2 {
			h.t.Fatal("unbound or unobserved state receipt")
		}
		h.stateReceipts++
		return jsonResponse(map[string]bool{"stored": true}), nil
	case "/internal/signer/pairing":
		var q struct {
			OperationID      string `json:"operation_id"`
			BindingSHA256    string `json:"binding_sha256"`
			SigningKeySHA256 string `json:"signing_key_sha256"`
			PairingVerified  bool   `json:"pairing_verified"`
			SDKCommit        string `json:"sdk_commit"`
		}
		if strictJSON(raw, &q) != nil || !h.claimed[q.OperationID] || q.BindingSHA256 != h.bindings[q.OperationID] || q.SigningKeySHA256 != h.service.keyHash || !q.PairingVerified || q.SDKCommit != SDKCommit {
			h.t.Fatal("unbound pairing receipt")
		}
		h.receipts++
		return jsonResponse(map[string]bool{"stored": true}), nil
	default:
		h.t.Fatal("arbitrary bridge route")
		return nil, refused
	}
}

func (h *liveHarness) fleetRoundTrip(request *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(request.Context()); trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sends++
	if h.reserves < h.sends || request.GetBody != nil || request.Header.Get("Authorization") != "Bearer synthetic-local-bearer" || request.URL.Scheme != "https" || request.URL.Host != "fleet-api.prd.na.vn.cloud.tesla.com" || request.Method != "POST" {
		h.t.Fatal("Fleet send before reservation or outside fixed contract")
	}
	if strings.HasSuffix(request.URL.Path, "/command/navigation_request") {
		if h.kinds[len(h.kinds)-1] != "navigation" {
			h.t.Fatal("navigation charged as wrong category")
		}
		return jsonResponse(map[string]any{"response": map[string]bool{"result": true}}), nil
	}
	if request.URL.Path != "/api/1/vehicles/"+target+"/signed_command" {
		h.t.Fatal("arbitrary Fleet endpoint")
	}
	var body struct {
		Message []byte `json:"routable_message"`
	}
	raw, _ := io.ReadAll(request.Body)
	if json.Unmarshal(raw, &body) != nil {
		h.t.Fatal("bad wire JSON")
	}
	var message um.RoutableMessage
	if proto.Unmarshal(body.Message, &message) != nil {
		h.t.Fatal("bad SDK protobuf")
	}
	h.domains = append(h.domains, message.GetToDestination().GetDomain())
	reply := &um.RoutableMessage{ToDestination: message.FromDestination, FromDestination: message.ToDestination, RequestUuid: message.Uuid, Uuid: bytes.Repeat([]byte{7}, 16), SignedMessageStatus: &um.MessageStatus{}}
	if h.omitOuterStatus {
		reply.SignedMessageStatus = nil
	}
	if h.nonOKOuterStatus {
		reply.SignedMessageStatus.OperationStatus = um.OperationStatus_E_OPERATIONSTATUS_WAIT
	}
	if message.GetSessionInfoRequest() != nil {
		if (h.kinds[len(h.kinds)-1] != "handshake" && h.kinds[len(h.kinds)-1] != "state_handshake") || !bytes.Equal(message.GetSessionInfoRequest().GetPublicKey(), h.service.mock.existingKey.PublicBytes()) {
			h.t.Fatal("handshake did not use bound existing key")
		}
		peer := key(h.t)
		h.peers[message.GetToDestination().GetDomain()] = peer
		infoValue := &sig.SessionInfo{PublicKey: peer.PublicBytes(), Epoch: bytes.Repeat([]byte{2}, 16)}
		if h.nonOKSession {
			infoValue.Status = sig.Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST
		}
		info, _ := proto.Marshal(infoValue)
		session, err := peer.Exchange(message.GetSessionInfoRequest().GetPublicKey())
		if err != nil {
			h.t.Fatal("synthetic key exchange failed")
		}
		tag, err := session.SessionInfoHMAC([]byte(target), message.Uuid, info)
		if err != nil {
			h.t.Fatal("synthetic response authentication failed")
		}
		if h.badTag {
			tag[0] ^= 1
		}
		reply.Payload = &um.RoutableMessage_SessionInfo{SessionInfo: info}
		reply.SubSigData = &um.RoutableMessage_SignatureData{SignatureData: &sig.SignatureData{SigType: &sig.SignatureData_SessionInfoTag{SessionInfoTag: &sig.HMAC_Signature_Data{Tag: tag}}}}
	} else {
		kind := h.kinds[len(h.kinds)-1]
		if (kind != "command" && kind != "state_query") || message.GetSignatureData().GetHMAC_PersonalizedData() == nil {
			h.t.Fatal("unsigned physical/state send")
		}
		if kind == "command" && h.stateReceipts == 0 && h.kinds[0] == "state_handshake" {
			h.t.Fatal("physical send preceded verified parked state")
		}
		if kind == "command" {
			h.commandPayloads = append(h.commandPayloads, append([]byte(nil), message.GetProtobufMessageAsBytes()...))
		}
		if h.uncertain && kind == "command" {
			return nil, errors.New("synthetic-private-transport-failure")
		}
		payload := []byte{}
		if message.GetToDestination().GetDomain() == um.Domain_DOMAIN_INFOTAINMENT {
			result := &cs.Response{ActionStatus: &cs.ActionStatus{Result: cs.OperationStatus_E_OPERATIONSTATUS_OK}}
			if kind == "state_query" {
				if !driveQueryOnly(message.GetProtobufMessageAsBytes()) {
					h.t.Fatal("preflight allowed physical/broad data query")
				}
				stamp := time.Now()
				if h.staleDrive {
					stamp = stamp.Add(-61 * time.Second)
				}
				if h.futureDrive {
					stamp = stamp.Add(time.Hour)
				}
				drive := &cs.DriveState{ShiftState: &cs.ShiftState{Type: &cs.ShiftState_P{P: &cs.Void{}}}, Timestamp: timestamppb.New(stamp)}
				if h.badDrive {
					drive.ShiftState = nil
				}
				if h.mutateDrive != nil {
					h.mutateDrive(drive)
				}
				result.ResponseMsg = &cs.Response_VehicleData{VehicleData: &cs.VehicleData{DriveState: drive}}
			} else if h.badCommandStatus {
				result.ActionStatus = nil
			}
			payload, _ = proto.Marshal(result)
		}
		reply.Payload = &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: payload}
		// Exercise real SDK AES-GCM response decryption as well as strict status
		// inspection; the unmodified SDK independently validates this metadata.
		peer := h.peers[message.GetToDestination().GetDomain()]
		session, err := peer.Exchange(h.service.mock.existingKey.PublicBytes())
		if err != nil {
			h.t.Fatal("response exchange")
		}
		gcm := &sig.AES_GCM_Response_Signature_Data{Counter: uint32(h.sends)}
		reply.SubSigData = &um.RoutableMessage_SignatureData{SignatureData: &sig.SignatureData{SigType: &sig.SignatureData_AES_GCM_ResponseData{AES_GCM_ResponseData: gcm}}}
		associated, err := responseAssociatedData(target, &message, reply)
		if err != nil {
			h.t.Fatal("response metadata")
		}
		gcm.Nonce, payload, gcm.Tag, err = session.Encrypt(payload, associated)
		if err != nil {
			h.t.Fatal("response encryption")
		}
		if h.badNonce {
			gcm.Nonce = gcm.Nonce[:1]
		}
		reply.Payload = &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: payload}
	}
	encoded, _ := proto.Marshal(reply)
	return jsonResponse(map[string][]byte{"response": encoded}), nil
}

func liveRequest(h *liveHarness, path string, raw []byte, id string) *httptest.ResponseRecorder {
	request := httptest.NewRequest("POST", "https://"+LocalSignerAddress+path, bytes.NewReader(simulateRequest(raw, id)))
	request.Header.Set("Authorization", "Bearer "+mockToken)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.service.ServeHTTP(w, request)
	return w
}

func pairingRaw() []byte {
	raw, _ := encodeJSON(PairingIntent{1, "synthetic-owner", target, "verify_pairing"})
	return raw
}

func TestLiveDefaultGatesPreserveMockWithoutBridgeOrFleet(t *testing.T) {
	if _, _, err := LoadLiveService("/path-must-not-be-read", false, false); err == nil {
		t.Fatal("unapproved constructor")
	}
	h := newLiveHarness(t)
	h.service.executionEnabled = false
	h.service.verificationEnabled = false
	if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("1", 32)).Code != 404 || liveRequest(h, "/verify_pairing", pairingRaw(), strings.Repeat("2", 32)).Code != 404 {
		t.Fatal("default activation gate")
	}
	if liveRequest(h, "/simulate", rawIntent("flash_lights", "{}"), strings.Repeat("3", 32)).Code != 200 || h.claims != 0 || h.reserves != 0 || h.sends != 0 {
		t.Fatal("disabled mode did not retain safe mock")
	}
}

func TestLiveActualSDKColdAndCachedCommandsReserveEveryAttempt(t *testing.T) {
	h := newLiveHarness(t)
	for _, id := range []string{strings.Repeat("1", 32), strings.Repeat("2", 32)} {
		w := liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), id)
		var result map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result["accepted"] != true || result["submitted"] != true || result["vehicle_execution_verified"] != false || strings.Contains(w.Body.String(), target) || strings.Contains(w.Body.String(), "synthetic-local-bearer") {
			t.Fatal("live result invalid or private")
		}
	}
	if h.claims != 2 || h.sends != 6 || h.reserves != 6 || strings.Join(h.kinds, ",") != "state_handshake,state_query,command,state_handshake,state_query,command" {
		t.Fatal("preflight/action SDK accounting")
	}
	if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("1", 32)).Code != 409 || h.sends != 6 {
		t.Fatal("durable authority replay")
	}
}

func TestLivePairingRequiresAuthenticatedFreshSecurityHandshakeOnly(t *testing.T) {
	h := newLiveHarness(t)
	h.facts.Paired = false
	h.facts.SigningReady = false
	// Even with an existing cached session, verification must use a new handshake.
	h.service.sessions = cached(t, um.Domain_DOMAIN_VEHICLE_SECURITY)
	w := liveRequest(h, "/verify_pairing", pairingRaw(), strings.Repeat("a", 32))
	var result map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result["pairing_verified"] != true || result["execution_enabled"] != false || h.sends != 1 || h.reserves != 1 || h.receipts != 1 || len(h.domains) != 1 || h.domains[0] != um.Domain_DOMAIN_VEHICLE_SECURITY || h.kinds[0] != "handshake" {
		t.Fatal("fresh matched-key verification failed")
	}
}

func TestLivePairingBadAuthenticationCannotRetryOrStoreReceipt(t *testing.T) {
	h := newLiveHarness(t)
	h.badTag = true
	w := liveRequest(h, "/verify_pairing", pairingRaw(), strings.Repeat("b", 32))
	if w.Code != 409 || h.sends != 1 || h.reserves != 1 || h.receipts != 0 {
		t.Fatal("unauthenticated pairing accepted or retried")
	}
}

func TestLiveNavigationOneIndependentRESTAttempt(t *testing.T) {
	h := newLiveHarness(t)
	payload := `{"locale":"en-US","timestamp_ms":"1791650000000","type":"share_ext_content_raw","value":{"android.intent.ACTION":"android.intent.action.SEND","android.intent.TEXT":"Synthetic address","android.intent.TYPE":"text/plain","android.intent.extra.TEXT":"Synthetic address"}}`
	w := liveRequest(h, "/execute", rawIntent("navigation_send", payload), strings.Repeat("c", 32))
	if w.Code != 200 || h.sends != 1 || h.reserves != 1 || len(h.domains) != 0 || h.kinds[0] != "navigation" || strings.Contains(w.Body.String(), "Synthetic address") {
		t.Fatal("navigation extra handshake/fallback or private result")
	}
}

func TestLiveMissingFreshFactsConsumesClaimWithoutAttempt(t *testing.T) {
	for _, change := range []func(*Facts){func(f *Facts) { f.Paired = false }, func(f *Facts) { f.SigningReady = false }, func(f *Facts) { f.ProtocolKnown = false }, func(f *Facts) { f.Observed = time.Now().Add(-61 * time.Second) }} {
		h := newLiveHarness(t)
		change(&h.facts)
		w := liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("d", 32))
		if w.Code != 409 || h.claims != 1 || h.reserves != 0 || h.sends != 0 {
			t.Fatal("missing trusted facts attempted command")
		}
	}
}

func TestLiveReservationRefusalAndUncertaintyCannotRetry(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		h := newLiveHarness(t)
		h.uncertain = uncertain
		h.rejectReserve = !uncertain
		w := liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("e", 32))
		wantSends := 2
		if uncertain {
			wantSends = 3
		}
		if w.Code != 409 || h.sends != wantSends || h.reserves != 3 || strings.Contains(w.Body.String(), "synthetic-private") {
			t.Fatal("budget rejection/uncertainty retried or leaked")
		}
	}
}

func TestLiveBridgeStrictClaimFailsBeforeFleet(t *testing.T) {
	h := newLiveHarness(t)
	h.badClaim = true
	if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("f", 32)).Code != 409 || h.sends != 0 || h.reserves != 0 {
		t.Fatal("malformed bridge authority accepted")
	}
}

func TestPairingOperationCannotAuthorizePhysicalPayloadOrCommandReservation(t *testing.T) {
	h := newLiveHarness(t)
	raw := pairingRaw()
	claim, _, err := h.service.bridge.claim(context.Background(), strings.Repeat("a", 32), raw, "verify_pairing", h.service.keyHash)
	if err != nil || claim.Consume(strings.Repeat("a", 32), sha256.Sum256(raw)) != nil {
		t.Fatal("synthetic claim failed")
	}
	if claim.ReserveAttempt("commands", "command") == nil || h.reserves != 0 {
		t.Fatal("pairing authority granted physical reservation")
	}
	if liveRequest(h, "/verify_pairing", rawIntent("flash_lights", "{}"), strings.Repeat("b", 32)).Code != 403 {
		t.Fatal("physical intent reached pairing path")
	}
}

func TestLiveExplicitSDKParkOverridesUnknownRESTGearAndRejectsMissingOrStaleGear(t *testing.T) {
	h := newLiveHarness(t)
	h.facts.Parked = false // An unknown/null Fleet gear is never assumed Park.
	if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("1", 32)).Code != 200 || h.stateReceipts != 1 {
		t.Fatal("explicit SDK Park not used")
	}
	for _, change := range []func(*liveHarness){func(h *liveHarness) { h.badDrive = true }, func(h *liveHarness) { h.staleDrive = true }, func(h *liveHarness) { h.futureDrive = true }} {
		h := newLiveHarness(t)
		change(h)
		if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("2", 32)).Code != 409 || h.sends != 2 || h.reserves != 2 || h.stateReceipts != 0 {
			t.Fatal("unverified or stale gear reached physical action")
		}
	}
}

func TestLiveSDKParkCannotPredateRESTDriveObservation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		offset   time.Duration
		accepted bool
	}{
		{"older_by_one_millisecond", -time.Millisecond, false},
		{"equal_timestamp", 0, true},
		{"newer_timestamp", time.Millisecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLiveHarness(t)
			h.facts.Observed = time.Now().Add(-2 * time.Second).Truncate(time.Millisecond)
			h.facts.DriveObserved = h.facts.Observed.Add(time.Second)
			h.facts.Parked = false // Unknown REST gear still requires explicit SDK Park.
			h.mutateDrive = func(drive *cs.DriveState) {
				drive.Timestamp = timestamppb.New(h.facts.DriveObserved.Add(tc.offset))
			}
			id := strings.Repeat("9", 32)
			w := liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), id)
			if tc.accepted {
				if w.Code != 200 || h.stateReceipts != 1 || h.sends != 3 || h.reserves != 3 {
					t.Fatal("fresh explicit SDK Park did not authorize exact action")
				}
			} else {
				if w.Code != 409 || h.stateReceipts != 0 || h.sends != 2 || h.reserves != 2 {
					t.Fatal("older SDK Park reached state receipt or physical action")
				}
				if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), id).Code != 409 || h.sends != 2 || h.reserves != 2 {
					t.Fatal("refused old Park observation was retried")
				}
			}
		})
	}
}

func TestLiveMissingOrInvalidRESTDriveObservationFailsBeforeFleet(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Facts)
	}{
		{"absent", func(f *Facts) { f.DriveObserved = time.Time{} }},
		{"older_than_earliest_facts", func(f *Facts) { f.DriveObserved = f.Observed.Add(-time.Millisecond) }},
		{"future", func(f *Facts) { f.DriveObserved = time.Now().Add(time.Second) }},
		{"stale", func(f *Facts) {
			f.Observed = time.Now().Add(-62 * time.Second)
			f.DriveObserved = f.Observed.Add(time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLiveHarness(t)
			tc.change(&h.facts)
			if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("a", 32)).Code != 409 || h.sends != 0 || h.reserves != 0 {
				t.Fatal("invalid REST drive timestamp reached Fleet preflight")
			}
		})
	}
}

func TestLiveSDKParkRejectsEveryContradictorySpeedRepresentation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*cs.DriveState)
	}{
		{"integer_moving", func(d *cs.DriveState) { d.OptionalSpeed = &cs.DriveState_Speed{Speed: 1} }},
		{"integer_maximum", func(d *cs.DriveState) { d.OptionalSpeed = &cs.DriveState_Speed{Speed: math.MaxUint32} }},
		{"float_moving", func(d *cs.DriveState) { d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{SpeedFloat: 0.001} }},
		{"float_negative", func(d *cs.DriveState) { d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{SpeedFloat: -0.001} }},
		{"float_nan", func(d *cs.DriveState) {
			d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{SpeedFloat: float32(math.NaN())}
		}},
		{"float_positive_infinity", func(d *cs.DriveState) {
			d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{SpeedFloat: float32(math.Inf(1))}
		}},
		{"float_negative_infinity", func(d *cs.DriveState) {
			d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{SpeedFloat: float32(math.Inf(-1))}
		}},
		{"integer_zero_float_moving", func(d *cs.DriveState) {
			d.OptionalSpeed = &cs.DriveState_Speed{}
			d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{SpeedFloat: 1}
		}},
		{"float_zero_integer_moving", func(d *cs.DriveState) {
			d.OptionalSpeed = &cs.DriveState_Speed{Speed: 1}
			d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{}
		}},
		{"unknown_speed_wire_type", func(d *cs.DriveState) { d.ProtoReflect().SetUnknown([]byte{0xb2, 0x06, 0x01, 0x00}) }},
		{"drive_gear_despite_zero_speed", func(d *cs.DriveState) {
			d.ShiftState = &cs.ShiftState{Type: &cs.ShiftState_D{D: &cs.Void{}}}
			d.OptionalSpeed = &cs.DriveState_Speed{}
		}},
		{"neutral_gear_despite_zero_speed", func(d *cs.DriveState) {
			d.ShiftState = &cs.ShiftState{Type: &cs.ShiftState_N{N: &cs.Void{}}}
			d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{}
		}},
		{"reverse_gear_despite_zero_speed", func(d *cs.DriveState) {
			d.ShiftState = &cs.ShiftState{Type: &cs.ShiftState_R{R: &cs.Void{}}}
			d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLiveHarness(t)
			h.mutateDrive = tc.mutate
			id := strings.Repeat("b", 32)
			if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), id).Code != 409 || h.stateReceipts != 0 || h.sends != 2 || h.reserves != 2 {
				t.Fatal("contradictory SDK state reached receipt or physical action")
			}
			if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), id).Code != 409 || h.sends != 2 || h.reserves != 2 {
				t.Fatal("refused contradictory SDK state was retried")
			}
		})
	}
}

func TestLiveSDKExplicitParkAcceptsAbsentAndZeroSpeeds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*cs.DriveState)
	}{
		{"absent", func(d *cs.DriveState) {}},
		{"integer_zero", func(d *cs.DriveState) { d.OptionalSpeed = &cs.DriveState_Speed{} }},
		{"float_zero", func(d *cs.DriveState) { d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{} }},
		{"both_zero", func(d *cs.DriveState) {
			d.OptionalSpeed = &cs.DriveState_Speed{}
			d.OptionalSpeedFloat = &cs.DriveState_SpeedFloat{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLiveHarness(t)
			h.facts.Parked = false
			h.mutateDrive = tc.mutate
			if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("c", 32)).Code != 200 || h.stateReceipts != 1 || h.sends != 3 || h.reserves != 3 {
				t.Fatal("stationary explicit Park refused")
			}
		})
	}
}

func TestSDKSpeedStationaryRejectsMalformedOptionalPresence(t *testing.T) {
	var integer *cs.DriveState_Speed
	var floating *cs.DriveState_SpeedFloat
	if sdkSpeedStationary(nil) || sdkSpeedStationary(&cs.DriveState{OptionalSpeed: integer}) || sdkSpeedStationary(&cs.DriveState{OptionalSpeedFloat: floating}) {
		t.Fatal("nil/malformed optional speed became zero")
	}
}

func TestLivePairingDiagnosticDoesNotRequireDriveTimestamp(t *testing.T) {
	h := newLiveHarness(t)
	h.facts.DriveObserved = time.Time{}
	if liveRequest(h, "/verify_pairing", pairingRaw(), strings.Repeat("d", 32)).Code != 200 || h.sends != 1 || h.reserves != 1 || h.receipts != 1 {
		t.Fatal("separate nonphysical pairing diagnostic required Park facts")
	}
}

func TestCatalogParkClassificationIsExplicitAndClosed(t *testing.T) {
	expected := map[string]bool{
		"climate_start": false, "climate_stop": false, "set_temperature": false, "navigation_send": false,
		"charge_start": false, "charge_stop": false, "set_charge_limit": false, "set_charging_amps": false,
		"charge_port_open": true, "charge_port_close": false, "lock": false, "unlock": false,
		"front_trunk": false, "rear_trunk": false, "flash_lights": true, "honk_horn": true,
	}
	if len(legacyTestCatalog()) != len(expected) || !actionRequiresPark("unknown_action") {
		t.Fatal("action safety policy omitted catalog action or opened unknown action")
	}
	for action, park := range expected {
		if actual, ok := catalog[action]; !ok || actual.requiresPark != park || actionRequiresPark(action) != park {
			t.Fatalf("incorrect Park classification for %s", action)
		}
	}
}

func TestLiveNonParkActionsHaveOnlyDocumentedHardwareGatesAndNoParkQuery(t *testing.T) {
	params := map[string]string{
		"set_temperature":  `{"driver_temp":20,"passenger_temp":20}`,
		"set_charge_limit": `{"percent":80}`, "set_charging_amps": `{"charging_amps":16}`,
		"front_trunk": `{"which_trunk":"front"}`, "rear_trunk": `{"which_trunk":"rear"}`,
		"navigation_send": `{"locale":"en-US","timestamp_ms":"1791650000000","type":"share_ext_content_raw","value":{"android.intent.ACTION":"android.intent.action.SEND","android.intent.TEXT":"Synthetic address","android.intent.TYPE":"text/plain","android.intent.extra.TEXT":"Synthetic address"}}`,
	}
	for action, spec := range legacyTestCatalog() {
		if spec.requiresPark {
			continue
		}
		t.Run(action, func(t *testing.T) {
			h := newLiveHarness(t)
			h.facts.Parked = false
			h.facts.Awake = false
			h.facts.Cable = action == "charge_start"
			h.facts.MotorizedPort = action == "charge_port_close"
            h.facts.CableAbsent = action == "charge_port_close"
			h.facts.DriveObserved = time.Time{}
			delete(h.facts.Scopes, "vehicle_device_data")
			h.mutateDrive = func(*cs.DriveState) { t.Fatal("unrequired SDK preflight query sent") }
			payload := params[action]
			if payload == "" {
				payload = "{}"
			}
			raw := rawIntent(action, payload)
			id := strings.Repeat("e", 32)
			w := liveRequest(h, "/execute", raw, id)
			wantAttempts := 2
			wantKinds := "handshake,command"
			if action == "navigation_send" {
				wantAttempts = 1
				wantKinds = "navigation"
			}
			var result map[string]any
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result["accepted"] != true || result["gross_reserved_microdollars"] != float64(wantAttempts*1000) || h.reserves != wantAttempts || h.sends != wantAttempts || h.stateReceipts != 0 || strings.Join(h.kinds, ",") != wantKinds {
				t.Fatal("non-Park action added state gate or changed exact paid request shape")
			}
			if action == "navigation_send" {
				if len(h.domains) != 0 || len(h.commandPayloads) != 0 {
					t.Fatal("navigation added a signed command/handshake")
				}
			} else if len(h.domains) != 2 || h.domains[0] != spec.domain || h.domains[1] != spec.domain || len(h.commandPayloads) != 1 {
				t.Fatal("non-Park action changed required domain or sent multiple commands")
			}
			if liveRequest(h, "/execute", raw, id).Code != 409 || h.sends != wantAttempts || h.reserves != wantAttempts {
				t.Fatal("non-Park operation was replayed")
			}
			if action == "set_temperature" {
				var action cs.Action
				if proto.Unmarshal(h.commandPayloads[0], &action) != nil {
					t.Fatal("invalid temperature command protobuf")
				}
				temperature := action.GetVehicleAction().GetHvacTemperatureAdjustmentAction()
				if temperature == nil || temperature.DriverTempCelsius != 20 || temperature.PassengerTempCelsius != 20 {
					t.Fatal("20C setpoint did not send exactly temperature adjustment")
				}
			}
		})
	}
}

func TestLiveNonParkSignedActionsUseFreshSessionsEvenAfterPriorCommands(t *testing.T) {
	h := newLiveHarness(t)
	h.facts.Parked = false
	h.facts.Awake = false
	h.facts.DriveObserved = time.Time{}
	delete(h.facts.Scopes, "vehicle_device_data")
	h.service.sessions = cached(t, um.Domain_DOMAIN_INFOTAINMENT)
	for _, id := range []string{strings.Repeat("f", 32), strings.Repeat("0", 32)} {
		if liveRequest(h, "/execute", rawIntent("climate_start", "{}"), id).Code != 200 {
			t.Fatal("non-Park signed action failed with unrelated cached session")
		}
	}
	if h.sends != 4 || h.reserves != 4 || h.stateReceipts != 0 || strings.Join(h.kinds, ",") != "handshake,command,handshake,command" {
		t.Fatal("cache changed fresh non-Park action reservation shape")
	}
}

func TestLiveNonParkUncertaintyOrReservationRefusalCannotRetry(t *testing.T) {
	for _, action := range []string{"set_temperature", "lock"} {
		for _, tc := range []struct {
			name                    string
			rejectReserveAt         int
			uncertain               bool
			wantSends, wantReserves int
		}{
			{"handshake_reservation_refused", 1, false, 0, 1},
			{"command_reservation_refused", 2, false, 1, 2},
			{"command_transport_uncertain", 0, true, 2, 2},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				h := newLiveHarness(t)
				h.uncertain = tc.uncertain
				h.rejectReserveAt = tc.rejectReserveAt
				id := strings.Repeat("2", 32)
				payload := "{}"
				if action == "set_temperature" {
					payload = `{"driver_temp":20,"passenger_temp":20}`
				}
				raw := rawIntent(action, payload)
				w := liveRequest(h, "/execute", raw, id)
				if w.Code != 409 || h.sends != tc.wantSends || h.reserves != tc.wantReserves || h.stateReceipts != 0 || strings.Contains(w.Body.String(), "synthetic-private") {
					t.Fatal("non-Park uncertainty/reservation refusal retried or leaked")
				}
				if liveRequest(h, "/execute", raw, id).Code != 409 || h.sends != tc.wantSends || h.reserves != tc.wantReserves {
					t.Fatal("uncertain non-Park command was replayed")
				}
			})
		}
	}
}

func TestLiveParkActionsRequireDeviceDataScopeBeforeFleetPreflight(t *testing.T) {
	for _, action := range []string{"honk_horn", "flash_lights", "charge_port_open"} {
		h := newLiveHarness(t)
		delete(h.facts.Scopes, "vehicle_device_data")
		if liveRequest(h, "/execute", rawIntent(action, "{}"), strings.Repeat("3", 32)).Code != 409 || h.reserves != 0 || h.sends != 0 || h.stateReceipts != 0 {
			t.Fatal("Park action queried Fleet without required data scope")
		}
	}
}

func TestLiveParkQueryDoesNotTrustRESTSleepApproximation(t *testing.T) {
	h := newLiveHarness(t)
	h.facts.Awake = false
	if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("1", 32)).Code != 200 || h.sends != 3 || h.reserves != 3 || h.stateReceipts != 1 {
		t.Fatal("REST sleep approximation blocked fresh authenticated SDK Park")
	}
}

func TestLiveExplicitActionStatusRequiredAfterEncryptedSDKResponse(t *testing.T) {
	h := newLiveHarness(t)
	h.badCommandStatus = true
	if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("3", 32)).Code != 409 || h.sends != 3 || h.reserves != 3 {
		t.Fatal("missing command status accepted or retried")
	}
}

func TestLiveAuthenticatedNonOKSessionRejectedBeforeSDKReadyRace(t *testing.T) {
	h := newLiveHarness(t)
	h.nonOKSession = true
	if liveRequest(h, "/verify_pairing", pairingRaw(), strings.Repeat("4", 32)).Code != 409 || h.sends != 1 || h.reserves != 1 || h.receipts != 0 {
		t.Fatal("authenticated non-OK session accepted")
	}
}

func TestLiveSecurityActionHasOnlyRequiredDomainAndTwoReservations(t *testing.T) {
	h := newLiveHarness(t)
	if liveRequest(h, "/execute", rawIntent("lock", "{}"), strings.Repeat("5", 32)).Code != 200 || h.sends != 2 || h.reserves != 2 || strings.Join(h.kinds, ",") != "handshake,command" || len(h.domains) != 2 || h.domains[0] != um.Domain_DOMAIN_VEHICLE_SECURITY || h.domains[1] != um.Domain_DOMAIN_VEHICLE_SECURITY {
		t.Fatal("security action domain/accounting")
	}
}

func TestSDKDriveQueryOnlyCannotContainPhysicalOrBroadRead(t *testing.T) {
	query := &cs.Action{ActionMsg: &cs.Action_VehicleAction{VehicleAction: &cs.VehicleAction{VehicleActionMsg: &cs.VehicleAction_GetVehicleData{GetVehicleData: &cs.GetVehicleData{GetDriveState: &cs.GetDriveState{}}}}}}
	raw, _ := proto.Marshal(query)
	if !driveQueryOnly(raw) {
		t.Fatal("exact SDK drive query denied")
	}
	query.GetVehicleAction().GetGetVehicleData().GetChargeState = &cs.GetChargeState{}
	raw, _ = proto.Marshal(query)
	if driveQueryOnly(raw) {
		t.Fatal("expanded state read admitted")
	}
	query.GetVehicleAction().VehicleActionMsg = &cs.VehicleAction_VehicleControlHonkHornAction{VehicleControlHonkHornAction: &cs.VehicleControlHonkHornAction{}}
	raw, _ = proto.Marshal(query)
	if driveQueryOnly(raw) {
		t.Fatal("physical preflight admitted")
	}
}

func TestLiveMalformedEncryptedNonceRefusedWithoutPanicOrRetry(t *testing.T) {
	h := newLiveHarness(t)
	h.badNonce = true
	if liveRequest(h, "/execute", rawIntent("flash_lights", "{}"), strings.Repeat("6", 32)).Code != 409 || h.sends != 2 || h.reserves != 2 || h.stateReceipts != 0 {
		t.Fatal("malformed encrypted response accepted or retried")
	}
}

func TestLiveAuthenticatedPositiveRepliesPermitOptionalOuterStatus(t *testing.T) {
	for _, action := range []string{"climate_start", "lock"} {
		h := newLiveHarness(t)
		h.omitOuterStatus = true
		if liveRequest(h, "/execute", rawIntent(action, "{}"), strings.Repeat("7", 32)).Code != 200 {
			t.Fatal("genuine authenticated positive reply denied for optional outer status")
		}
	}
}

func TestLiveNonOKOuterPairingStatusCannotWinSDKReadyRace(t *testing.T) {
	h := newLiveHarness(t)
	h.nonOKOuterStatus = true
	if liveRequest(h, "/verify_pairing", pairingRaw(), strings.Repeat("8", 32)).Code != 409 || h.sends != 1 || h.reserves != 1 || h.receipts != 0 {
		t.Fatal("non-OK outer session status accepted")
	}
}
