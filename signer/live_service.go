package restricted

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/cache"
	"github.com/teslamotors/vehicle-command/pkg/connector"
)

// The caller (60s), fixed gateway (65s) and TLS writer (55s) outlive
// the handler. Vehicle work ends at45s, retaining4s for local final evidence
// and1s to emit the bounded response. No deadline permits a retry.
const (
	LiveHandlerTimeout      = 50 * time.Second
	LiveTLSWriteTimeout     = 55 * time.Second
	liveWorkTimeout         = 45 * time.Second
	liveFinalizationTimeout = 4 * time.Second
)

// LiveService is separately enabled trusted local composition. The existing
// mock CLI never constructs this type; no request or environment input enables
// either gate. Only its authenticated fixed-loopback broker supplies authority,
// fresh facts, bearer authorization and durable all-attempt reservations.
type LiveService struct {
	mu                  sync.Mutex
	mock                *MockService
	bridge              *bridgeClient
	verificationEnabled bool
	executionEnabled    bool
	infotainmentEnabled bool
	keyHash             string
	sessions            *cache.SessionCache
	// nil selects the restricted fixed-origin Fleet client. Tests inject fake
	// transport, never a caller URL, alternate origin or environment proxy.
	fleetClient *http.Client
}

func LoadLiveService(path string, verificationEnabled, executionEnabled bool, infotainmentGate ...bool) (*LiveService, ServiceConfig, error) {
	// Refuse before any protected reads unless the owner explicitly selects a gate.
	if len(infotainmentGate) > 1 {
		return nil, ServiceConfig{}, refused
	}
	infotainmentEnabled := len(infotainmentGate) == 1 && infotainmentGate[0]
	// Diagnostic is a separate gate; refuse to combine it with physical or
	// security verification modes, even through trusted misconfiguration.
	if infotainmentEnabled && (verificationEnabled || executionEnabled) {
		return nil, ServiceConfig{}, refused
	}
	if !verificationEnabled && !executionEnabled && !infotainmentEnabled {
		return nil, ServiceConfig{}, refused
	}
	mock, config, err := LoadMockService(path)
	if err != nil {
		return nil, config, refused
	}
	digest := sha256.Sum256(mock.existingKey.PublicBytes())
	return &LiveService{mock: mock, bridge: &bridgeClient{token: bridgeCapability(mock.token), client: RestrictedHTTPClient()}, verificationEnabled: verificationEnabled, executionEnabled: executionEnabled, infotainmentEnabled: infotainmentEnabled, keyHash: hex.EncodeToString(digest[:]), sessions: cache.New(1)}, config, nil
}

func (s *LiveService) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(status int) {
		w.WriteHeader(status)
		io.WriteString(w, `{"error":"Local signing operation refused or uncertain; no automatic retry"}`)
	}
	handlerContext, cancelHandler := context.WithTimeout(request.Context(), LiveHandlerTimeout)
	defer cancelHandler()
	if s == nil || s.mock == nil || request.Host != LocalSignerAddress || request.URL.RawQuery != "" {
		fail(401)
		return
	}
	value, expected := request.Header.Get("Authorization"), "Bearer "+s.mock.token
	if len(value) != len(expected) || !constantBytes([]byte(value), []byte(expected)) {
		fail(401)
		return
	}
	if request.URL.Path == "/simulate" {
		s.mock.ServeHTTP(w, request)
		return
	}
	if request.URL.Path == "/health" && request.Method == "GET" {
		json.NewEncoder(w).Encode(map[string]any{"status": "ready", "mode": "restricted-live-capable", "execution_enabled": s.executionEnabled, "pairing_verification_enabled": s.verificationEnabled, "infotainment_diagnostic_enabled": s.infotainmentEnabled, "existing_signing_key_matches_public": s.mock.existingKey != nil, "sdk_commit": SDKCommit, "fleet_network_enabled": s.executionEnabled || s.verificationEnabled || s.infotainmentEnabled, "budget_reservation_enabled": true})
		return
	}
	mode := ""
	if request.URL.Path == "/execute" && s.executionEnabled {
		mode = "execute"
	}
	if request.URL.Path == "/verify_pairing" && s.verificationEnabled {
		mode = "verify_pairing"
	}
	if request.URL.Path == "/verify_infotainment" && s.infotainmentEnabled && !s.executionEnabled && !s.verificationEnabled {
		mode = "verify_infotainment"
	}
	if mode == "" || request.Method != "POST" || strings.Split(request.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(404)
		return
	}
	if handlerContext.Err() != nil {
		fail(409)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 16385))
	if err != nil || len(raw) > 16384 || handlerContext.Err() != nil {
		fail(400)
		return
	}
	var operation struct {
		OperationID string          `json:"operation_id"`
		Intent      json.RawMessage `json:"intent"`
	}
	if strictJSON(raw, &operation) != nil {
		fail(400)
		return
	}
	action := mode
	if mode == "execute" {
		i, _, _, err := parseIntent(operation.Intent)
		if err != nil || i.Principal != s.mock.owner || i.Target != s.mock.target {
			fail(403)
			return
		}
		action = i.Action
	} else {
		parse := parsePairingIntent
		if mode == "verify_infotainment" {
			parse = parseInfotainmentIntent
		}
		i, err := parse(operation.Intent)
		if err != nil || i.Principal != s.mock.owner || i.Target != s.mock.target {
			fail(403)
			return
		}
	}
	// A busy signer refuses before claim, durable debit or vehicle contact.
	// A mutex wait may not consume the caller's response/finalization window.
	if handlerContext.Err() != nil || !s.mu.TryLock() {
		fail(409)
		return
	}
	defer s.mu.Unlock()
	handlerDeadline, _ := handlerContext.Deadline()
	ctx, cancel := context.WithDeadline(handlerContext,
		handlerDeadline.Add(-(LiveHandlerTimeout - liveWorkTimeout)))
	defer cancel()
	if ctx.Err() != nil {
		fail(409)
		return
	}
	claim, facts, err := s.bridge.claim(ctx, operation.OperationID, operation.Intent, mode, s.keyHash)
	if err != nil {
		fail(409)
		return
	}
	diagnostic := newDiagnostic(claim.diagnosticSink)
	if diagnostic.emit(ctx, "operation_started") != nil {
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]any{"error": "Local signing operation refused or uncertain; no automatic retry", "diagnostic": diagnostic.snapshot()})
		return
	}
	client := s.fleetClient
	if client == nil {
		client = RestrictedHTTPClient()
	}
	engine := &Engine{Owner: s.mock.owner, Target: s.mock.target, Authority: claim, Budget: claim, Key: s.mock.existingKey, Sessions: s.sessions, RESTClient: client, Bearer: claim.Bearer, diagnostic: diagnostic, NewConnector: func(target string) connector.Connector {
		wire := NewHTTPConnector(target, client, claim.Bearer)
		wire.key = s.mock.existingKey
		wire.sessions = s.sessions
		wire.diagnostic = diagnostic
		return wire
	}}
	if mode == "verify_infotainment" {
		err = engine.VerifyInfotainment(ctx, operation.Intent, operation.OperationID, facts)
	} else if mode == "verify_pairing" {
		err = engine.VerifyPairing(ctx, operation.Intent, operation.OperationID, facts)
		if err == nil {
			err = claim.pairingReceipt(ctx, s.keyHash)
		}
	} else if actionRequiresPark(action) {
		// The broker refuses contradictory REST motion first. Unknown REST gear
		// is never Park; require fresh explicit SDK P at least as recent as the
		// REST drive observation through the query-only connector.
		preflight := &Engine{Owner: engine.Owner, Target: engine.Target, Authority: preflightAuthority{claim}, Budget: preflightBudget{claim}, Key: engine.Key, Sessions: engine.Sessions, NewConnector: engine.NewConnector, diagnostic: diagnostic}
		observed, queryErr := preflight.ReadParked(ctx, operation.Intent, operation.OperationID, facts)
		err = queryErr
		if err == nil {
			err = claim.stateReceipt(ctx, s.keyHash, observed)
		}
		if err == nil {
			facts.Parked = true
			facts.Awake = true // A fresh authenticated SDK reply proves responsiveness.
			// Keep the earlier REST timestamp for all trusted facts' freshness.
			err = engine.Run(ctx, operation.Intent, operation.OperationID, facts)
		}
	} else {
		// Only exact catalog-classified actions skip Park. Use a fresh signed
		// session for each signed action; no stale cached session
		// changes the durable two-attempt budget shape.
		engine.Sessions = nil
		err = engine.Run(ctx, operation.Intent, operation.OperationID, facts)
	}
	// Work cancellation never creates a new request window. Only the terminal
	// local journal uses the still-live original handler context; parent
	// cancellation remains authoritative and no detached context is introduced.
	finalContext, cancelFinal := context.WithTimeout(handlerContext, liveFinalizationTimeout)
	err = diagnostic.finish(finalContext, err)
	cancelFinal()
	if err != nil {
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]any{"error": "Local signing operation refused or uncertain; no automatic retry", "diagnostic": diagnostic.snapshot()})
		return
	}
	if mode == "verify_infotainment" {
		json.NewEncoder(w).Encode(map[string]any{"infotainment_verified": true, "execution_enabled": false, "vehicle_execution_verified": false, "sdk_commit": SDKCommit, "fleet_network_requests": claim.attempt, "gross_reserved_microdollars": 1000 * claim.attempt, "diagnostic": diagnostic.snapshot()})
		return
	}
	if mode == "verify_pairing" {
		json.NewEncoder(w).Encode(map[string]any{"pairing_verified": true, "execution_enabled": false, "vehicle_execution_verified": false, "sdk_commit": SDKCommit, "fleet_network_requests": claim.attempt, "gross_reserved_microdollars": 1000 * claim.attempt})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"action": action, "simulated": false, "submitted": true, "accepted": true, "vehicle_execution_verified": false, "execution_enabled": true, "sdk_commit": SDKCommit, "fleet_network_requests": claim.attempt, "gross_reserved_microdollars": 1000 * claim.attempt})
}
