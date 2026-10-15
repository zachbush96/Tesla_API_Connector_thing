// Package restricted embeds an unmodified pinned Tesla SDK behind an exact
// owner-authenticated operation boundary. Default CLI/service modes do not enable it.
package restricted

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/teslamotors/vehicle-command/pkg/cache"
	"github.com/teslamotors/vehicle-command/pkg/connector"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/proxy"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
	"google.golang.org/protobuf/proto"
)

const SDKCommit = "49977a18fd68567501d59e16a6c9e4a8b9348544"
const fleetOrigin = "https://fleet-api.prd.na.vn.cloud.tesla.com"
const fleetNetworkTimeout = 10 * time.Second
const sdkMaximumLatency = 10 * time.Second
const enginePhysicalTimeout = 30 * time.Second
const engineHandshakeTimeout = 16 * time.Second
const minimumAttemptWindow = 13 * time.Second

type fullNetworkWindowKey struct{}

var refused = errors.New("restricted action refused")

func terminal() error {
	return protocol.NewError("restricted transmission refused; no retry", true, false)
}

// Authority must be supplied by the trusted owner process, never request input.
// It consumes an expiring exact operation binding before connector/budget access.
// An operation ID is replay protection, not proof of human consent. The host
// enforces ordinary chat request/confirmation policy before calling Run.
type Authority interface {
	Consume(ticket string, binding [32]byte) error
}
type Budget interface{ Reserve(category string) error }

// AttemptBudget lets the trusted bridge account for the exact wire shape before
// each attempt. Existing synthetic Budget implementations remain usable.
type AttemptBudget interface {
	ReserveAttempt(category, kind string) error
}

// ContextAttemptBudget is the production bridge's scoped reservation API.
// Existing synthetic Budget/AttemptBudget implementations retain their contract.
// The actual phase context governs the durable callback, not a wider parent.
type ContextAttemptBudget interface {
	ReserveAttemptContext(context.Context, string, string) error
}

func productionAttemptContext(ctx context.Context, b Budget, diagnostic *diagnosticRecorder) (context.Context, bool) {
	if ctx.Err() != nil {
		diagnostic.sdkFailure(ctx.Err())
		return ctx, false
	}
	if _, scoped := b.(ContextAttemptBudget); !scoped {
		return ctx, true // Legacy synthetic engines do not call the live bridge.
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < minimumAttemptWindow {
		stage := "operation_started"
		if diagnostic != nil {
			stage = diagnostic.snapshot().Stage
		}
		diagnostic.noteFailure("context_deadline", "context", "none", stage)
		return ctx, false
	}
	return context.WithValue(ctx, fullNetworkWindowKey{}, true), true
}

func reserveAttempt(ctx context.Context, b Budget, kind string) error {
	if b == nil || ctx.Err() != nil {
		return refused
	}
	if scoped, ok := b.(ContextAttemptBudget); ok {
		return scoped.ReserveAttemptContext(ctx, "commands", kind)
	}
	if detailed, ok := b.(AttemptBudget); ok {
		return detailed.ReserveAttempt("commands", kind)
	}
	return b.Reserve("commands")
}

// BearerProvider is trusted local integration code, never an MCP argument.
// This module does not load real credentials. Production activation is disabled.
type BearerProvider func(context.Context) (string, error)

func bearerValue(ctx context.Context, p BearerProvider) (string, error) {
	if p == nil {
		return "", refused
	}
	v, e := p(ctx)
	if e != nil || len(v) < 1 || len(v) > 16384 || !regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`).MatchString(v) {
		return "", refused
	}
	return v, nil
}

type Facts struct {
	Scopes                                                                   map[string]bool
	Paired, SigningReady, ProtocolKnown, Parked, Awake, Cable, MotorizedPort bool
	Observed, DriveObserved                                                  time.Time
 CableAbsent, ClimateActive, UserPresent, MobileAccess bool
}
type Intent struct {
	Version   int    `json:"version"`
	Principal string `json:"principal"`
	Target    string `json:"target"`
	Action    string `json:"action"`
	Command   string `json:"command"`
	Payload   string `json:"payload"`
}

func stringValue(x any) string { s, _ := x.(string); return s }
func hasControl(s string) bool {
	for _, c := range s {
		if c < 32 || c == 127 {
			return true
		}
	}
	return false
}

type spec struct {
	command, scope string
	domain         um.Domain
	requiresPark   bool
}

var catalog = map[string]spec{
	"climate_start":     {"auto_conditioning_start", "vehicle_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"climate_stop":      {"auto_conditioning_stop", "vehicle_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"set_temperature":   {"set_temps", "vehicle_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"navigation_send":   {"navigation_request", "vehicle_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"charge_start":      {"charge_start", "vehicle_charging_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"charge_stop":       {"charge_stop", "vehicle_charging_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"set_charge_limit":  {"set_charge_limit", "vehicle_charging_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"set_charging_amps": {"set_charging_amps", "vehicle_charging_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"charge_port_open":  {"charge_port_door_open", "vehicle_charging_cmds", um.Domain_DOMAIN_INFOTAINMENT, true},
	"charge_port_close": {"charge_port_door_close", "vehicle_charging_cmds", um.Domain_DOMAIN_INFOTAINMENT, false},
	"lock":              {"door_lock", "vehicle_cmds", um.Domain_DOMAIN_VEHICLE_SECURITY, false},
	"unlock":            {"door_unlock", "vehicle_cmds", um.Domain_DOMAIN_VEHICLE_SECURITY, false},
	"front_trunk":       {"actuate_trunk", "vehicle_cmds", um.Domain_DOMAIN_VEHICLE_SECURITY, false},
	"rear_trunk":        {"actuate_trunk", "vehicle_cmds", um.Domain_DOMAIN_VEHICLE_SECURITY, false},
	"flash_lights":      {"flash_lights", "vehicle_cmds", um.Domain_DOMAIN_INFOTAINMENT, true},
	"honk_horn":         {"honk_horn", "vehicle_cmds", um.Domain_DOMAIN_INFOTAINMENT, true},
}

func actionRequiresPark(action string) bool {
	s, known := catalog[action]
	return !known || s.requiresPark
}

var vinPattern = regexp.MustCompile(`^[A-HJ-NPR-Z0-9]{17}$`)

// strictJSON rejects duplicate keys recursively and trailing documents.
func strictJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 16384 || !jsonUnicodeScalars(raw) {
		return refused
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func() error
	value = func() error {
		t, e := d.Token()
		if e != nil {
			return refused
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					s, ok := key.(string)
					if e != nil || !ok || seen[s] {
						return refused
					}
					seen[s] = true
					if value() != nil {
						return refused
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return refused
				}
			case '[':
				for d.More() {
					if value() != nil {
						return refused
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return refused
				}
			default:
				return refused
			}
		}
		return nil
	}
	if value() != nil {
		return refused
	}
	if _, e := d.Token(); e != io.EOF {
		return refused
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return refused
	}
	return nil
}
func parseIntent(raw []byte) (Intent, spec, map[string]any, error) {
	var i Intent
	if strictJSON(raw, &i) != nil {
		return i, spec{}, nil, refused
	}
	s, ok := catalog[i.Action]
	if !ok || i.Version != 2 || i.Principal == "" || len(i.Principal) > 256 || !vinPattern.MatchString(i.Target) || s.command != i.Command {
		return i, s, nil, refused
	}
	var p map[string]any
	if strictJSON([]byte(i.Payload), &p) != nil || p == nil {
		return i, s, nil, refused
	}
	eq := func(keys ...string) bool {
		if len(keys) != len(p) {
			return false
		}
		for _, k := range keys {
			if _, ok := p[k]; !ok {
				return false
			}
		}
		return true
	}
	num := func(k string, min, max float64, integer bool) bool {
		n, ok := p[k].(float64)
		return ok && n >= min && n <= max && (!integer || n == float64(int64(n)))
	}
	if _,existing := map[string]bool{"charge_port_close":true,"charge_port_open":true,"charge_start":true,"charge_stop":true,"climate_start":true,"climate_stop":true,"flash_lights":true,"front_trunk":true,"honk_horn":true,"lock":true,"navigation_send":true,"rear_trunk":true,"set_charge_limit":true,"set_charging_amps":true,"set_temperature":true,"unlock":true}[i.Action];!existing {if !additionalPayload(i.Action,p){return i,s,nil,refused};return i,s,p,nil}
	switch i.Action {
	case "set_temperature":
		if !eq("driver_temp", "passenger_temp") || p["driver_temp"] != p["passenger_temp"] || !num("driver_temp", 15, 28, false) {
			return i, s, nil, refused
		}
	case "set_charge_limit":
		if !eq("percent") || !num("percent", 50, 100, true) {
			return i, s, nil, refused
		}
	case "set_charging_amps":
		if !eq("charging_amps") || !num("charging_amps", 1, 48, true) {
			return i, s, nil, refused
		}
	case "front_trunk", "rear_trunk":
		which := "rear"
		if i.Action == "front_trunk" {
			which = "front"
		}
		if !eq("which_trunk") || p["which_trunk"] != which {
			return i, s, nil, refused
		}
	case "navigation_send":
		v, ok := p["value"].(map[string]any)
		if !eq("type", "value", "locale", "timestamp_ms") || !ok || len(v) != 4 || p["type"] != "share_ext_content_raw" || p["locale"] != "en-US" || !regexp.MustCompile(`^[0-9]{13}$`).MatchString(stringValue(p["timestamp_ms"])) {
			return i, s, nil, refused
		}
		dest, ok := v["android.intent.TEXT"].(string)
		if !ok || !utf8.ValidString(dest) || len(dest) == 0 || utf8.RuneCountInString(dest) > 300 || strings.TrimSpace(dest) == "" || hasControl(dest) || v["android.intent.extra.TEXT"] != dest || v["android.intent.ACTION"] != "android.intent.action.SEND" || v["android.intent.TYPE"] != "text/plain" {
			return i, s, nil, refused
		}
	default:
		if !eq() {
			return i, s, nil, refused
		}
	}
	return i, s, p, nil
}

type guardConnector struct {
	connector.Connector
	mu                         sync.Mutex
	domain                     um.Domain
	public                     []byte
	budget                     Budget
	handshake, command, closed bool
	handshakeOnly              bool
	payloadAllowed             func([]byte) bool
	diagnostic                 *diagnosticRecorder
	diagnosticPrefix           string
}

func (g *guardConnector) Send(ctx context.Context, raw []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ctx.Err() != nil {
		g.diagnostic.sdkFailure(ctx.Err())
		g.closed = true
		return terminal()
	}
	// The SDK registers its handler before calling Send. Capture the local
	// start before reservations and protected checkpoint latency, rather than
	// measuring only the later HTTP round trip. The earlier Engine deadline
	// remains the hard bound; the SDK's exact private timestamp is unexposed.
	var attemptStarted time.Time
	if c, ok := g.Connector.(*HTTPConnector); ok {
		attemptStarted = c.clockNow()
	}
	var m um.RoutableMessage
	if g.closed || len(raw) > 16384 || proto.Unmarshal(raw, &m) != nil || len(m.ProtoReflect().GetUnknown()) != 0 || m.GetToDestination().GetDomain() != g.domain {
		g.closed = true
		return terminal()
	}
	kind := "command"
	if m.GetSessionInfoRequest() != nil {
		kind = "handshake"
		if g.handshake || g.command || m.GetSignatureData() != nil || !bytes.Equal(m.GetSessionInfoRequest().GetPublicKey(), g.public) {
			if g.handshake && g.diagnostic != nil {
				g.diagnostic.noteFailure("guard_handshake_retry_blocked", "local", "none", g.diagnostic.snapshot().Stage)
			}
			g.closed = true
			return terminal()
		}
		g.handshake = true
	} else {
		signature := m.GetSignatureData()
		if g.handshakeOnly || g.command || len(m.GetProtobufMessageAsBytes()) == 0 || signature == nil || signature.GetHMAC_PersonalizedData() == nil || len(signature.GetHMAC_PersonalizedData().GetTag()) != 32 || !bytes.Equal(signature.GetSignerIdentity().GetPublicKey(), g.public) || (g.payloadAllowed != nil && !g.payloadAllowed(m.GetProtobufMessageAsBytes())) {
			g.closed = true
			return terminal()
		}
		g.command = true
	}
	var windowReady bool
	ctx, windowReady = productionAttemptContext(ctx, g.budget, g.diagnostic)
	if !windowReady {
		g.closed = true
		return terminal()
	}
	diagnosticKind := g.diagnosticPrefix + kind
	if diagnosticKind == "state_command" {
		diagnosticKind = "state_query"
	}
	if g.diagnostic.beginAttempt(ctx, diagnosticKind) != nil {
		g.closed = true
		return terminal()
	}
	if c, ok := g.Connector.(*HTTPConnector); ok {
		c.markAttemptStart(attemptStarted)
	}
	if reserveAttempt(ctx, g.budget, kind) != nil {
		g.diagnostic.noteFailure("bridge_refused", "bridge", "none", "reservation_attempted")
		g.closed = true
		return terminal()
	}
	if g.diagnostic.milestone(ctx, "reservation_acknowledged", 0) != nil {
		g.closed = true
		return terminal()
	}
	if sendErr := g.Connector.Send(ctx, raw); sendErr != nil {
		g.diagnostic.sdkFailure(sendErr)
		g.closed = true
		return terminal()
	}
	return nil
}

// Engine has no listener or credential loader. Only the separately gated trusted
// live service supplies broker-claimed authorization and per-attempt reservations.
type Engine struct {
	mu            sync.Mutex
	Owner, Target string
	Authority     Authority
	Budget        Budget
	Now           func() time.Time
	Key           protocol.ECDHPrivateKey
	Sessions      *cache.SessionCache
	NewConnector  func(target string) connector.Connector
	RESTClient    *http.Client
	Bearer        BearerProvider
	diagnostic    *diagnosticRecorder
}

func (e *Engine) Run(ctx context.Context, raw []byte, ticket string, f Facts) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		e.diagnostic.sdkFailure(ctx.Err())
		return refused
	}
	i, s, p, err := parseIntent(raw)
	if err != nil || i.Principal != e.Owner || i.Target != e.Target || e.Authority == nil {
		return refused
	}
	if e.Authority.Consume(ticket, sha256.Sum256(raw)) != nil {
		return refused
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	age := now.Sub(f.Observed)
	if age < 0 || age > 60*time.Second || !f.Scopes[s.scope] || !f.Paired || !f.SigningReady || !f.ProtocolKnown || (s.requiresPark && (!f.Parked || !f.Awake)) || e.Budget == nil {
		return refused
	}
	if !requiredCatalogFacts(i.Action,f) {
		return refused
	}
	ctx, cancel := context.WithTimeout(ctx, enginePhysicalTimeout)
	defer cancel()
	if i.Action == "navigation_send" {
		if e.RESTClient == nil {
			return refused
		}
		var windowReady bool
		ctx, windowReady = productionAttemptContext(ctx, e.Budget, e.diagnostic)
		if !windowReady {
			return refused
		}
		if e.diagnostic.beginAttempt(ctx, "navigation") != nil {
			return refused
		}
		if reserveAttempt(ctx, e.Budget, "navigation") != nil {
			e.diagnostic.noteFailure("bridge_refused", "bridge", "none", "reservation_attempted")
			return refused
		}
		if e.diagnostic.milestone(ctx, "reservation_acknowledged", 0) != nil {
			return refused
		}
		return sendREST(ctx, e.RESTClient, i.Target, i.Command, []byte(i.Payload), e.Bearer, e.diagnostic)
	}
	if e.Key == nil || e.NewConnector == nil {
		return refused
	}
	c := e.NewConnector(i.Target)
	if c == nil || c.VIN() != i.Target {
		return refused
	}
	guard := &guardConnector{Connector: c, domain: s.domain, public: e.Key.PublicBytes(), budget: e.Budget, diagnostic: e.diagnostic}
	car, err := vehicle.NewVehicle(guard, e.Key, e.Sessions)
	if err != nil {
		guard.Close()
		e.diagnostic.sdkFailure(err)
		return refused
	}
	defer car.Disconnect()
	if e.Sessions != nil {
		defer car.UpdateCachedSessions(e.Sessions)
	}
	if err = car.Connect(ctx); err == nil {
		err = car.StartSession(ctx, []um.Domain{s.domain})
	}
	if err != nil {
		e.diagnostic.sdkFailure(err)
		return refused
	}
	if e.diagnostic.milestone(ctx, "authenticated_session_ready", 0) != nil {
		return refused
	}
	action, err := proxy.ExtractCommandAction(ctx, i.Command, proxy.RequestParameters(p))
	if err != nil {
		return refused
	}
	if err = action(car); err != nil {
		e.diagnostic.sdkFailure(err)
		return refused
	}
	return nil
}

// RestrictedHTTPClient is inert until explicitly used. No insecure TLS/proxy,
// keepalive, HTTP/2, redirect or live origin customization is supported.
func RestrictedHTTPClient() *http.Client {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	return &http.Client{Transport: tr, Timeout: fleetNetworkTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return refused }}
}
func roundTrip(ctx context.Context, client *http.Client, target, path string, body []byte, provider BearerProvider, diagnostics ...*diagnosticRecorder) ([]byte, error) {
	var diagnostic *diagnosticRecorder
	if len(diagnostics) == 1 {
		diagnostic = diagnostics[0]
	}
	if client == nil || !vinPattern.MatchString(target) || len(body) > 16384 {
		return nil, refused
	}
	if diagnostic != nil {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				_ = diagnostic.milestone(ctx, "request_written", 0)
			}
		}})
	}
	request, err := http.NewRequestWithContext(ctx, "POST", fleetOrigin+"/api/1/vehicles/"+target+path, bytes.NewReader(body))
	if err != nil {
		diagnostic.noteFailure("local_refused", "local", "none", "reservation_acknowledged")
		return nil, refused
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	token, err := bearerValue(ctx, provider)
	if err != nil {
		diagnostic.noteFailure("local_refused", "local", "none", "reservation_acknowledged")
		return nil, refused
	}
	request.Header.Set("Authorization", "Bearer "+token)
	controlled := *client
	if diagnostic != nil {
		transport := client.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		controlled.Transport = diagnosticTransport{transport, diagnostic}
	}
	controlled.CheckRedirect = func(*http.Request, []*http.Request) error { return refused }
	controlled.Timeout = fleetNetworkTimeout
	// Reserve the full client-Do bound, not10s of vehicle wire time. Trace
	// journaling consumes some of it, and the independent SDK freshness guard
	// still includes all pre-send and validation overhead in its10s age limit.
	if requireWindow, _ := ctx.Value(fullNetworkWindowKey{}).(bool); requireWindow {
		deadline, ok := ctx.Deadline()
		if ctx.Err() != nil || !ok || time.Until(deadline) < fleetNetworkTimeout {
			diagnostic.noteFailure("context_deadline", "context", "none", "reservation_acknowledged")
			return nil, terminal()
		}
	}
	response, err := controlled.Do(request)
	if response != nil {
		// A known non-200 status is already the primary HTTP cause. Record it
		// before persistence so a rejected checkpoint cannot erase that cause.
		if response.StatusCode != 200 {
			diagnostic.noteFailure("http_status", "http", "none", "response_received")
		}
		if response.Body != nil {
			defer response.Body.Close()
		}
		if diagnostic.milestone(ctx, "response_received", response.StatusCode) != nil {
			return nil, terminal()
		}
	}
	if err != nil {
		exception, category := safeException(err)
		stage := "http_initiated"
		if diagnostic != nil {
			stage = diagnostic.snapshot().Stage
		}
		if response != nil && response.StatusCode != 200 {
			exception, category = "http_status", "http"
		}
		diagnostic.noteFailure(exception, category, "none", stage)
		return nil, terminal()
	}
	if response == nil || response.Body == nil {
		diagnostic.noteFailure("json_invalid", "response", "malformed_response", "response_received")
		return nil, terminal()
	}
	if response.StatusCode != 200 {
		// The status is sufficient; never inspect a free-form error body.
		diagnostic.noteFailure("http_status", "http", "none", "response_received")
		return nil, terminal()
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 100001))
	if err != nil {
		exception, category := safeException(err)
		if exception == "network_error" {
			exception, category = "response_read_error", "response"
		}
		diagnostic.noteFailure(exception, category, "none", "response_received")
		return nil, terminal()
	}
	if len(raw) > 100000 {
		diagnostic.noteFailure("response_too_large", "response", "malformed_response", "response_received")
		return nil, terminal()
	}
	if strings.Split(response.Header.Get("Content-Type"), ";")[0] != "application/json" {
		diagnostic.noteFailure("response_content_type", "response", "malformed_response", "response_received")
		return nil, terminal()
	}
	return raw, nil
}
func sendREST(ctx context.Context, client *http.Client, target, command string, payload []byte, provider BearerProvider, diagnostics ...*diagnosticRecorder) error {
	var diagnostic *diagnosticRecorder
	if len(diagnostics) == 1 {
		diagnostic = diagnostics[0]
	}
	if command != "navigation_request" {
		return refused
	}
	raw, err := roundTrip(ctx, client, target, "/command/navigation_request", payload, provider, diagnostic)
	if err != nil {
		return refused
	}
	var value struct {
		Response struct {
			Result *bool  `json:"result"`
			Reason string `json:"reason"`
		} `json:"response"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if strictJSON(raw, &value) != nil || value.Response.Result == nil {
		diagnostic.noteFailure("json_invalid", "response", "malformed_response", "response_received")
		return refused
	}
	if !*value.Response.Result || value.Error != "" {
		diagnostic.noteFailure("vehicle_rejected", "vehicle", "rejected", "response_received")
		return refused
	}
	return diagnostic.emit(ctx, "response_validated")
}

// HTTPConnector implements the SDK wire protocol with one fixed-origin POST.
// It intentionally does not implement FleetAPIConnector/Wakeup or fallback.
type HTTPConnector struct {
	target       string
	client       *http.Client
	inbox        chan []byte
	mu           sync.Mutex
	closed       bool
	bearer       BearerProvider
	key          protocol.ECDHPrivateKey
	sessions     *cache.SessionCache
	remotePublic []byte
	diagnostic   *diagnosticRecorder
	// Optional clock is only used for the SDK's bounded response-age guard.
	// No elapsed timestamp or duration is retained in diagnostics.
	now            func() time.Time
	attemptStarted time.Time
}

func (c *HTTPConnector) clockNow() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *HTTPConnector) markAttemptStart(start time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attemptStarted = start
}

func (c *HTTPConnector) sessionResponseFresh(ctx context.Context, request *um.RoutableMessage, start time.Time) bool {
	if ctx.Err() != nil {
		c.diagnostic.sdkFailure(ctx.Err())
		return false
	}
	if request.GetSessionInfoRequest() != nil && c.clockNow().Sub(start) > c.AllowedLatency() {
		stage := "response_received"
		if c.diagnostic != nil {
			stage = c.diagnostic.snapshot().Stage
		}
		c.diagnostic.noteFailure("session_info_late", "authentication", "none", stage)
		return false
	}
	return true
}

func NewHTTPConnector(target string, client *http.Client, providers ...BearerProvider) *HTTPConnector {
	var p BearerProvider
	if len(providers) == 1 {
		p = providers[0]
	}
	return &HTTPConnector{target: target, client: client, inbox: make(chan []byte, 5), bearer: p}
}
func (c *HTTPConnector) VIN() string                               { return c.target }
func (c *HTTPConnector) PreferredAuthMethod() connector.AuthMethod { return connector.AuthMethodHMAC }
func (c *HTTPConnector) RetryInterval() time.Duration              { return time.Second }
func (c *HTTPConnector) AllowedLatency() time.Duration             { return sdkMaximumLatency }
func (c *HTTPConnector) Receive() <-chan []byte                    { return c.inbox }
func (c *HTTPConnector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.inbox)
	}
}
func (c *HTTPConnector) Send(ctx context.Context, raw []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.client == nil {
		return terminal()
	}
	body, _ := json.Marshal(map[string][]byte{"routable_message": raw})
	sentAt := c.attemptStarted
	c.attemptStarted = time.Time{}
	if sentAt.IsZero() {
		sentAt = c.clockNow()
	}
	var request um.RoutableMessage
	if proto.Unmarshal(raw, &request) == nil && !c.sessionResponseFresh(ctx, &request, sentAt) {
		return terminal()
	}
	response, err := roundTrip(ctx, c.client, c.target, "/signed_command", body, c.bearer, c.diagnostic)
	if err != nil {
		return terminal()
	}
	payload, err := decodeFleetEnvelope(response)
	if err != nil {
		c.diagnostic.replyFailure(err)
		return terminal()
	}
	if c.key != nil {
		if proto.Unmarshal(raw, &request) == nil && !c.sessionResponseFresh(ctx, &request, sentAt) {
			return terminal()
		}
		if err := c.checkReply(raw, payload); err != nil {
			c.diagnostic.replyFailure(err)
			return terminal()
		}
	}
	if c.diagnostic.emit(ctx, "response_validated") != nil {
		return terminal()
	}
	if proto.Unmarshal(raw, &request) == nil && !c.sessionResponseFresh(ctx, &request, sentAt) {
		return terminal()
	}
	select {
	case c.inbox <- payload:
		return nil
	case <-ctx.Done():
		c.diagnostic.sdkFailure(ctx.Err())
		return terminal()
	}
}
