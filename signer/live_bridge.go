package restricted

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const brokerBridgeOrigin = "http://127.0.0.1:8765"
const bridgeClaimTimeout = 25 * time.Second
const bridgeJournalTimeout = time.Second
const bridgeDeadlineHeader = "X-Connector-Signer-Deadline-Ms"

func bridgeCapability(serviceToken string) string {
	mac := hmac.New(sha256.New, []byte(serviceToken))
	mac.Write([]byte("tesla-connector-signer-bridge-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

// bridgeClient is intentionally private: production construction supplies the
// fixed loopback origin and restricted transport. Tests replace only transport.
type bridgeClient struct {
	token  string
	client *http.Client
}

func encodeJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if enc.Encode(value) != nil {
		return nil, refused
	}
	return bytes.TrimSpace(out.Bytes()), nil
}

// Delegate deadline and cancellation to the original context while hiding
// Fleet's trace value. A loopback checkpoint write must never re-enter or
// impersonate a Fleet write. No Background/WithoutCancel replacement is used.
type bridgeContext struct{ context.Context }

func (c bridgeContext) Value(key any) any {
	value := c.Context.Value(key)
	if _, traced := value.(*httptrace.ClientTrace); traced {
		return nil
	}
	return value
}

func (b *bridgeClient) post(ctx context.Context, path string, value, out any) error {
	ctx = bridgeContext{ctx}
	if b == nil || b.client == nil || len(b.token) < 32 || len(b.token) > 4096 || strings.ContainsAny(b.token, "\r\n\t ") || (path != "/internal/signer/claim" && path != "/internal/signer/reserve" && path != "/internal/signer/pairing" && path != "/internal/signer/state" && path != "/internal/signer/diagnostic") {
		return refused
	}
	limit := bridgeJournalTimeout
	if path == "/internal/signer/claim" {
		limit = bridgeClaimTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	if ctx.Err() != nil {
		return refused
	}
	raw, err := encodeJSON(value)
	if err != nil || len(raw) > 16384 {
		return refused
	}
	req, err := http.NewRequestWithContext(ctx, "POST", brokerBridgeOrigin+path, bytes.NewReader(raw))
	if err != nil {
		return refused
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil {
		return refused
	}
	// Bound the broker's local durability/prerequisite work to this exact RPC.
	// Parent deadlines always shorten this value; it cannot grant extra time.
	req.Header.Set(bridgeDeadlineHeader, strconv.FormatInt(deadline.UnixMilli(), 10))
	req.Header.Set("Authorization", "Bearer "+b.token)
	client := *b.client
	client.Timeout = limit
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return refused }
	response, err := client.Do(req)
	if err != nil {
		return refused
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || ctx.Err() != nil || len(body) > 16384 || response.StatusCode != 200 || strings.Split(response.Header.Get("Content-Type"), ";")[0] != "application/json" || strictJSON(body, out) != nil {
		return refused
	}
	return nil
}

type bridgeFacts struct {
 CableAbsent bool `json:"cable_absent"`
 ClimateActive bool `json:"climate_active"`
 UserPresent bool `json:"user_present"`
 MobileAccess bool `json:"mobile_access"`
	Scopes              []string `json:"scopes"`
	Paired              bool     `json:"paired"`
	SigningReady        bool     `json:"signing_ready"`
	ProtocolKnown       bool     `json:"protocol_known"`
	Parked              bool     `json:"parked"`
	Awake               bool     `json:"awake"`
	Cable               bool     `json:"cable"`
	MotorizedPort       bool     `json:"motorized_port"`
	ObservedUnixMS      int64    `json:"observed_unix_ms"`
	DriveObservedUnixMS int64    `json:"drive_observed_unix_ms"`
}

type claimResponse struct {
	Bearer string      `json:"bearer"`
	Facts  bridgeFacts `json:"facts"`
}

type claimRequest struct {
	OperationID      string          `json:"operation_id"`
	Intent           json.RawMessage `json:"intent"`
	Mode             string          `json:"mode"`
	SigningKeySHA256 string          `json:"signing_key_sha256"`
}

type reserveRequest struct {
	OperationID   string `json:"operation_id"`
	BindingSHA256 string `json:"binding_sha256"`
	Category      string `json:"category"`
	Kind          string `json:"kind"`
	Attempt       int    `json:"attempt"`
}

// operationClaim is created only after the broker durably consumes its prepared
// exact operation. It never accepts authorization, facts or bearer from MCP.
type operationClaim struct {
	mu               sync.Mutex
	bridge           *bridgeClient
	ticket           string
	binding          [32]byte
	mode             string
	action           string
	bearer           string
	used             bool
	closed           bool
	attempt          int
	kinds            map[string]bool
	preflightStarted bool
	stateVerified    bool
	parentContext    context.Context
}

func (b *bridgeClient) claim(ctx context.Context, ticket string, raw []byte, mode, keyHash string) (*operationClaim, Facts, error) {
	var result claimResponse
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(ticket) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(keyHash) || (mode != "execute" && mode != "verify_pairing" && mode != "verify_infotainment") {
		return nil, Facts{}, refused
	}
	if b.post(ctx, "/internal/signer/claim", claimRequest{ticket, raw, mode, keyHash}, &result) != nil || len(result.Bearer) < 1 || len(result.Bearer) > 16000 || !regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`).MatchString(result.Bearer) || len(result.Facts.Scopes) > 16 || result.Facts.ObservedUnixMS <= 0 {
		return nil, Facts{}, refused
	}
	f := Facts{CableAbsent: result.Facts.CableAbsent, ClimateActive: result.Facts.ClimateActive, UserPresent: result.Facts.UserPresent, MobileAccess: result.Facts.MobileAccess, Scopes: map[string]bool{}, Paired: result.Facts.Paired, SigningReady: result.Facts.SigningReady, ProtocolKnown: result.Facts.ProtocolKnown, Parked: result.Facts.Parked, Awake: result.Facts.Awake, Cable: result.Facts.Cable, MotorizedPort: result.Facts.MotorizedPort, Observed: time.UnixMilli(result.Facts.ObservedUnixMS)}
	if result.Facts.DriveObservedUnixMS > 0 {
		f.DriveObserved = time.UnixMilli(result.Facts.DriveObservedUnixMS)
	}
	for _, scope := range result.Facts.Scopes {
		if scope == "" || len(scope) > 64 || hasControl(scope) || f.Scopes[scope] {
			return nil, Facts{}, refused
		}
		f.Scopes[scope] = true
	}
	action := mode
	if mode == "execute" {
		i, _, _, err := parseIntent(raw)
		if err != nil {
			return nil, Facts{}, refused
		}
		action = i.Action
		if actionRequiresPark(action) && (result.Facts.DriveObservedUnixMS <= 0 || result.Facts.DriveObservedUnixMS < result.Facts.ObservedUnixMS) {
			return nil, Facts{}, refused
		}
	}
	return &operationClaim{bridge: b, ticket: ticket, binding: sha256.Sum256(raw), mode: mode, action: action, bearer: result.Bearer, kinds: map[string]bool{}, parentContext: ctx}, f, nil
}

func (c *operationClaim) Consume(ticket string, binding [32]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.used || c.closed {
		return refused
	}
	c.used = true
	if ticket != c.ticket || binding != c.binding || (c.mode == "execute" && actionRequiresPark(c.action) && !c.stateVerified) {
		c.closed = true
		return refused
	}
	return nil
}

func (c *operationClaim) Bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || (!c.used && !c.preflightStarted) || c.closed {
		return "", refused
	}
	return c.bearer, nil
}

func (c *operationClaim) Reserve(category string) error { return refused }

func (c *operationClaim) ReserveAttempt(category, kind string) error {
	return c.ReserveAttemptContext(c.parentContext, category, kind)
}

func (c *operationClaim) ReserveAttemptContext(ctx context.Context, category, kind string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil || c.parentContext == nil || ctx.Err() != nil || c.parentContext.Err() != nil {
		c.closed = true // A failed phase cannot be reopened with a fresh context.
		return refused
	}
	if (!c.used && !c.preflightStarted) || c.closed || category != "commands" || c.kinds[kind] {
		return refused
	}
	valid := false
	if c.mode == "verify_pairing" || c.mode == "verify_infotainment" {
		valid = kind == "handshake" && c.attempt == 0
	} else if !actionRequiresPark(c.action) {
		if c.used && !c.preflightStarted && !c.stateVerified {
			if c.action == "navigation_send" {
				valid = kind == "navigation" && c.attempt == 0
			} else {
				valid = (kind == "handshake" && c.attempt == 0) || (kind == "command" && c.attempt == 1 && c.kinds["handshake"])
			}
		}
	} else {
		valid = !c.used && !c.stateVerified && ((kind == "state_handshake" && c.attempt == 0) || (kind == "state_query" && c.attempt == 1 && c.kinds["state_handshake"]))
		if c.used && c.stateVerified {
			// All Park-classified actions use infotainment, whose fresh session
			// was established by preflight. No extra handshake is authorized.
			valid = kind == "command" && c.attempt == 2
		}
	}
	if !valid {
		c.closed = true
		return refused
	}
	// Mark before the callback: uncertainty cannot authorize a second reservation.
	c.attempt++
	c.kinds[kind] = true
	var response struct {
		Reserved bool `json:"reserved"`
	}
	// Preserve both the phase deadline and original work cancellation even if
	// a trusted caller accidentally supplies a context from another lineage.
	bounded, cancel := context.WithCancel(ctx)
	stopParent := context.AfterFunc(c.parentContext, cancel)
	defer stopParent()
	defer cancel()
	if deadline, ok := c.parentContext.Deadline(); ok {
		var stopDeadline context.CancelFunc
		bounded, stopDeadline = context.WithDeadline(bounded, deadline)
		defer stopDeadline()
	}
	if c.bridge.post(bounded, "/internal/signer/reserve", reserveRequest{c.ticket, hex.EncodeToString(c.binding[:]), category, kind, c.attempt}, &response) != nil || !response.Reserved {
		c.closed = true
		return refused
	}
	return nil
}

type preflightAuthority struct{ claim *operationClaim }

func (a preflightAuthority) Consume(ticket string, binding [32]byte) error {
	c := a.claim
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.used || c.preflightStarted || c.mode != "execute" || !actionRequiresPark(c.action) || ticket != c.ticket || binding != c.binding {
		return refused
	}
	c.preflightStarted = true
	return nil
}

type preflightBudget struct{ claim *operationClaim }

func (b preflightBudget) Reserve(string) error { return refused }
func (b preflightBudget) ReserveAttempt(category, kind string) error {
	return b.ReserveAttemptContext(b.claim.parentContext, category, kind)
}
func (b preflightBudget) ReserveAttemptContext(ctx context.Context, category, kind string) error {
	if kind == "handshake" {
		return b.claim.ReserveAttemptContext(ctx, category, "state_handshake")
	}
	if kind == "command" {
		return b.claim.ReserveAttemptContext(ctx, category, "state_query")
	}
	return refused
}

func (c *operationClaim) stateReceipt(ctx context.Context, keyHash string, observed time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != "execute" || c.used || c.closed || !c.preflightStarted || c.stateVerified || c.attempt != 2 || !c.kinds["state_handshake"] || !c.kinds["state_query"] {
		return refused
	}
	request := struct {
		OperationID      string `json:"operation_id"`
		BindingSHA256    string `json:"binding_sha256"`
		SigningKeySHA256 string `json:"signing_key_sha256"`
		Parked           bool   `json:"parked"`
		Awake            bool   `json:"awake"`
		ObservedUnixMS   int64  `json:"observed_unix_ms"`
		SDKCommit        string `json:"sdk_commit"`
	}{c.ticket, hex.EncodeToString(c.binding[:]), keyHash, true, true, observed.UnixMilli(), SDKCommit}
	var response struct {
		Stored bool `json:"stored"`
	}
	if c.bridge.post(ctx, "/internal/signer/state", request, &response) != nil || !response.Stored {
		c.closed = true
		return refused
	}
	c.stateVerified = true
	return nil
}

func (c *operationClaim) pairingReceipt(ctx context.Context, keyHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != "verify_pairing" || !c.used || c.closed || c.attempt != 1 || !c.kinds["handshake"] {
		return refused
	}
	request := struct {
		OperationID      string `json:"operation_id"`
		BindingSHA256    string `json:"binding_sha256"`
		SigningKeySHA256 string `json:"signing_key_sha256"`
		PairingVerified  bool   `json:"pairing_verified"`
		SDKCommit        string `json:"sdk_commit"`
	}{c.ticket, hex.EncodeToString(c.binding[:]), keyHash, true, SDKCommit}
	var response struct {
		Stored bool `json:"stored"`
	}
	if c.bridge.post(ctx, "/internal/signer/pairing", request, &response) != nil || !response.Stored {
		c.closed = true
		return refused
	}
	return nil
}

func (c *operationClaim) diagnosticSink(ctx context.Context, sequence int, diagnostic Diagnostic) error {
	request := diagnosticRequest{OperationID: c.ticket, BindingSHA256: hex.EncodeToString(c.binding[:]), Sequence: sequence, Diagnostic: diagnostic}
	var response struct {
		Stored bool `json:"stored"`
	}
	if c.bridge.post(ctx, "/internal/signer/diagnostic", request, &response) != nil || !response.Stored {
		return refused
	}
	return nil
}
