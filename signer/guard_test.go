package restricted

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/teslamotors/vehicle-command/pkg/cache"
	"github.com/teslamotors/vehicle-command/pkg/connector"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	sig "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/signatures"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func syntheticBearer(context.Context) (string, error) { return "synthetic-test-bearer", nil }

const target = "AAAAAAAAAAAAAAAAA"

type authority struct {
	mu      sync.Mutex
	binding [32]byte
	used    bool
}

func (a *authority) Consume(ticket string, b [32]byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used {
		return refused
	}
	a.used = true
	if ticket != "synthetic-owner-ticket" || b != a.binding {
		return refused
	}
	return nil
}

type budget struct {
	mu           sync.Mutex
	calls, limit int
}

func (b *budget) Reserve(category string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if category != "commands" || b.calls >= b.limit {
		return refused
	}
	b.calls++
	return nil
}

type fakeConnector struct {
	inbox  chan []byte
	mu     sync.Mutex
	calls  int
	error  error
	drop   bool
	closed bool
	last   *um.RoutableMessage
}

func (f *fakeConnector) VIN() string            { return target }
func (f *fakeConnector) Receive() <-chan []byte { return f.inbox }
func (f *fakeConnector) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.inbox)
	}
}
func (f *fakeConnector) PreferredAuthMethod() connector.AuthMethod { return connector.AuthMethodHMAC }
func (f *fakeConnector) RetryInterval() time.Duration              { return time.Millisecond }
func (f *fakeConnector) AllowedLatency() time.Duration             { return time.Second }
func (f *fakeConnector) Send(_ context.Context, raw []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	m := &um.RoutableMessage{}
	if proto.Unmarshal(raw, m) != nil {
		return refused
	}
	f.last = m
	if f.error != nil {
		return f.error
	}
	if f.drop {
		return nil
	}
	response := &um.RoutableMessage{ToDestination: m.FromDestination, FromDestination: m.ToDestination, RequestUuid: m.Uuid, Uuid: bytes.Repeat([]byte{7}, 16), Payload: &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: []byte{}}, SignedMessageStatus: &um.MessageStatus{}}
	encoded, _ := proto.Marshal(response)
	f.inbox <- encoded
	return nil
}
func key(t *testing.T) protocol.ECDHPrivateKey {
	t.Helper()
	k, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return protocol.UnmarshalECDHPrivateKey(k.Bytes())
}
func cached(t *testing.T, domain um.Domain) *cache.SessionCache {
	t.Helper()
	k, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	info, _ := proto.Marshal(&sig.SessionInfo{PublicKey: k.PublicKey().Bytes(), Epoch: bytes.Repeat([]byte{2}, 16)})
	data, _ := json.Marshal(map[string]any{"MaxEntries": 1, "vehicles": map[string]any{target: []map[string]any{{"CreatedAt": time.Now(), "Domain": int(domain), "data": info}}}})
	c, e := cache.Import(bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func rawIntent(action, payload string) []byte {
	i := Intent{2, "synthetic-owner", target, action, catalog[action].command, payload}
	r, _ := json.Marshal(i)
	return r
}
func facts() Facts {
	observed := time.Now()
	return Facts{Scopes: map[string]bool{"vehicle_cmds": true, "vehicle_charging_cmds": true}, Paired: true, SigningReady: true, ProtocolKnown: true, Parked: true, Awake: true, Cable: true, MotorizedPort: true, Observed: observed, DriveObserved: observed}
}
func engine(t *testing.T, raw []byte, f *fakeConnector) (*Engine, *budget) {
	t.Helper()
	b := &budget{limit: 10}
	e := &Engine{Owner: "synthetic-owner", Target: target, Authority: &authority{binding: sha256.Sum256(raw)}, Budget: b, Key: key(t), NewConnector: func(string) connector.Connector { return f }}
	return e, b
}
func conn() *fakeConnector { return &fakeConnector{inbox: make(chan []byte, 20)} }
func TestActualSDKSigningAndOwnerSingleUse(t *testing.T) {
	raw := rawIntent("climate_start", "{}")
	c := conn()
	e, b := engine(t, raw, c)
	e.Sessions = cached(t, um.Domain_DOMAIN_INFOTAINMENT)
	if err := e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()); err != nil {
		t.Fatalf("synthetic signed SDK action failed: %v", err)
	}
	if c.calls != 1 || b.calls != 1 || c.last.GetSignatureData().GetHMAC_PersonalizedData() == nil || len(c.last.GetSignatureData().GetHMAC_PersonalizedData().GetTag()) != 32 {
		t.Fatal("expected one actual SDK HMAC command/reservation")
	}
	if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) == nil || c.calls != 1 {
		t.Fatal("approval replay accepted")
	}
}
func TestActualSDKHandshakeTimeoutCannotRetransmit(t *testing.T) {
	raw := rawIntent("climate_start", "{}")
	c := conn()
	c.drop = true
	e, b := engine(t, raw, c)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e.Run(ctx, raw, "synthetic-owner-ticket", facts()) == nil {
		t.Fatal("missing handshake accepted")
	}
	if c.calls != 1 || b.calls != 1 || c.last.GetSessionInfoRequest() == nil {
		t.Fatal("SDK repeated handshake reached connector")
	}
}
func TestActualSDKTemporarySendErrorBecomesTerminal(t *testing.T) {
	for _, cachedSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "handshake", true: "signed-command"}[cachedSession], func(t *testing.T) {
			raw := rawIntent("climate_start", "{}")
			c := conn()
			c.error = protocol.NewError("synthetic-private", false, true)
			e, b := engine(t, raw, c)
			if cachedSession {
				e.Sessions = cached(t, um.Domain_DOMAIN_INFOTAINMENT)
			}
			if err := e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()); err == nil || strings.Contains(err.Error(), "synthetic-private") {
				t.Fatal("private/temporary failure escaped")
			}
			if c.calls != 1 || b.calls != 1 {
				t.Fatal("SDK send retried")
			}
		})
	}
}
func TestActualSDKResponseTimeoutCannotRetransmitPhysicalCommand(t *testing.T) {
	raw := rawIntent("climate_start", "{}")
	c := conn()
	c.drop = true
	e, b := engine(t, raw, c)
	e.Sessions = cached(t, um.Domain_DOMAIN_INFOTAINMENT)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if e.Run(ctx, raw, "synthetic-owner-ticket", facts()) == nil {
		t.Fatal("uncertain command succeeded")
	}
	if c.calls != 1 || b.calls != 1 {
		t.Fatal("repeat physical action")
	}
}
func TestCanonicalBindingChangedActionRefusedBeforeSDK(t *testing.T) {
	raw := rawIntent("climate_start", "{}")
	c := conn()
	e, b := engine(t, raw, c)
	changed := rawIntent("climate_stop", "{}")
	if e.Run(context.Background(), changed, "synthetic-owner-ticket", facts()) == nil {
		t.Fatal("changed action authorized")
	}
	if c.calls != 0 || b.calls != 0 {
		t.Fatal("binding failure contacted SDK")
	}
	if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) == nil {
		t.Fatal("mismatched approval not burned")
	}
}
func TestPrerequisiteFailuresConsumeGrantBeforeAnyReservation(t *testing.T) {
	for _, change := range []func(*Facts){func(f *Facts) { f.Paired = false }, func(f *Facts) { f.Parked = false }, func(f *Facts) { f.Awake = false }, func(f *Facts) { f.SigningReady = false }, func(f *Facts) { f.Observed = time.Now().Add(-61 * time.Second) }, func(f *Facts) { f.Scopes = map[string]bool{} }} {
		raw := rawIntent("flash_lights", "{}")
		c := conn()
		e, b := engine(t, raw, c)
		f := facts()
		change(&f)
		if e.Run(context.Background(), raw, "synthetic-owner-ticket", f) == nil {
			t.Fatal("missing prerequisite accepted")
		}
		if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) == nil {
			t.Fatal("grant not burned")
		}
		if c.calls != 0 || b.calls != 0 {
			t.Fatal("prerequisite spent or transmitted")
		}
	}
}
func TestBudgetFailureBeforeAnySDKTransmission(t *testing.T) {
	raw := rawIntent("climate_start", "{}")
	c := conn()
	e, b := engine(t, raw, c)
	b.limit = 0
	if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) == nil || c.calls != 0 || b.calls != 0 {
		t.Fatal("unbudgeted transmission")
	}
}
func TestConcurrentSameApprovalUsesOneSDKAction(t *testing.T) {
	raw := rawIntent("climate_start", "{}")
	c := conn()
	e, b := engine(t, raw, c)
	e.Sessions = cached(t, um.Domain_DOMAIN_INFOTAINMENT)
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 || c.calls != 1 || b.calls != 1 {
		t.Fatal("duplicate owner action")
	}
}
func TestUnknownAndDuplicateIntentRefused(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"action":"wake_up"}`), []byte(`{"version":2,"version":2}`), rawIntent("set_temperature", `{"driver_temp":22,"passenger_temp":23}`), rawIntent("set_charge_limit", `{"percent":true}`), rawIntent("lock", `{"confirmed":true}`)} {
		if _, _, _, err := parseIntent(raw); err == nil {
			t.Fatal("invalid intent accepted")
		}
	}
}
func TestGuardRejectsUnsignedWrongDomainAndUnknownProtobuf(t *testing.T) {
	for _, raw := range [][]byte{[]byte{255}, func() []byte {
		r, _ := proto.Marshal(&um.RoutableMessage{ToDestination: &um.Destination{SubDestination: &um.Destination_Domain{Domain: um.Domain_DOMAIN_INFOTAINMENT}}, Payload: &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: []byte("unsigned")}})
		return r
	}()} {
		c := conn()
		b := &budget{limit: 10}
		g := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_INFOTAINMENT, budget: b}
		if g.Send(context.Background(), raw) == nil || c.calls != 0 || b.calls != 0 {
			t.Fatal("unsigned/malformed wire transmitted")
		}
	}
}

type fakeRT func(*http.Request) (*http.Response, error)

func (f fakeRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
func TestHTTPConnectorExactOriginNoPrivateErrors(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != fleetOrigin+"/api/1/vehicles/"+target+"/signed_command" || r.GetBody != nil {
			t.Fatal("bad fixed HTTP wire")
		}
		return nil, errors.New("synthetic-private")
	})}
	c := NewHTTPConnector(target, client, syntheticBearer)
	err := c.Send(context.Background(), []byte("synthetic-wire"))
	if err == nil || protocol.ShouldRetry(err) || strings.Contains(err.Error(), "synthetic-private") || calls != 1 {
		t.Fatal("wire error not terminal/private")
	}
}
func TestFactoryHasVerifiedTLSNoProxyHTTP2OrReuse(t *testing.T) {
	c := RestrictedHTTPClient()
	tr := c.Transport.(*http.Transport)
	if tr.Proxy != nil || !tr.DisableKeepAlives || tr.ForceAttemptHTTP2 || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion == 0 || len(tr.TLSNextProto) != 0 || c.CheckRedirect(nil, nil) == nil {
		t.Fatal("unsafe HTTP factory")
	}
}
func TestNavigationUsesExactRESTWithoutSDKOrRetry(t *testing.T) {
	payload := `{"locale":"en-US","timestamp_ms":"1791650000000","type":"share_ext_content_raw","value":{"android.intent.ACTION":"android.intent.action.SEND","android.intent.TEXT":"Synthetic address","android.intent.TYPE":"text/plain","android.intent.extra.TEXT":"Synthetic address"}}`
	raw := rawIntent("navigation_send", payload)
	c := conn()
	e, b := engine(t, raw, c)
	calls := 0
	e.Bearer = syntheticBearer
	e.RESTClient = &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != fleetOrigin+"/api/1/vehicles/"+target+"/command/navigation_request" {
			t.Fatal("arbitrary REST path")
		}
		return response(200, `{"response":{"result":true}}`), nil
	})}
	if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) != nil || calls != 1 || c.calls != 0 || b.calls != 1 {
		t.Fatal("navigation did not use one exact REST attempt")
	}
}
func TestSDKDirectGuardIsTerminalAfterRepeatedHandshake(t *testing.T) {
	c := conn()
	c.drop = true
	b := &budget{limit: 10}
	k := key(t)
	g := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_INFOTAINMENT, public: k.PublicBytes(), budget: b}
	car, err := vehicle.NewVehicle(g, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer car.Disconnect()
	if car.Connect(ctx) != nil {
		t.Fatal("SDK dispatcher startup")
	}
	err = car.StartSession(ctx, []um.Domain{um.Domain_DOMAIN_INFOTAINMENT})
	if err == nil || protocol.ShouldRetry(err) || c.calls != 1 || b.calls != 1 {
		t.Fatal("SDK handshake loop bypassed guard")
	}
}
func TestAllSignedCatalogActionsUseOnlyTheirRequiredDomain(t *testing.T) {
	params := map[string]string{"set_temperature": `{"driver_temp":22,"passenger_temp":22}`, "set_charge_limit": `{"percent":80}`, "set_charging_amps": `{"charging_amps":16}`, "front_trunk": `{"which_trunk":"front"}`, "rear_trunk": `{"which_trunk":"rear"}`}
	for action, s := range legacyTestCatalog() {
		if action == "navigation_send" {
			continue
		}
		t.Run(action, func(t *testing.T) {
			p := params[action]
			if p == "" {
				p = "{}"
			}
			raw := rawIntent(action, p)
			c := conn()
			e, b := engine(t, raw, c)
			e.Sessions = cached(t, s.domain)
			f:=facts()
            if action=="charge_port_close" {f.Cable=false;f.CableAbsent=true}
            if e.Run(context.Background(), raw, "synthetic-owner-ticket", f) != nil {
				t.Fatal("allowed SDK catalog action failed")
			}
			if c.calls != 1 || b.calls != 1 || c.last.GetToDestination().GetDomain() != s.domain {
				t.Fatal("unnecessary domain/duplicate operation")
			}
		})
	}
}
func TestRESTRedirectCannotSendSecondRequest(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		calls++
		resp := response(307, `{}`)
		resp.Header.Set("Location", fleetOrigin+"/api/1/vehicles/"+target+"/command/navigation_request")
		return resp, nil
	})}
	if sendREST(context.Background(), client, target, "navigation_request", []byte(`{}`), syntheticBearer) == nil || calls != 1 {
		t.Fatal("REST redirect retried")
	}
}
func TestHTTPStatusMalformedOversizeAndDuplicateResponsesRefused(t *testing.T) {
	for _, item := range []struct {
		status int
		body   string
	}{{401, `{"response":"c2VjcmV0"}`}, {421, `{}`}, {503, `{}`}, {200, `{"response":"c2VjcmV0","response":"b3RoZXI="}`}, {200, `{"response":"bad base64"}`}, {200, strings.Repeat("x", 100001)}} {
		t.Run(item.body[:min(len(item.body), 25)], func(t *testing.T) {
			calls := 0
			c := NewHTTPConnector(target, &http.Client{Transport: fakeRT(func(*http.Request) (*http.Response, error) { calls++; return response(item.status, item.body), nil })}, syntheticBearer)
			err := c.Send(context.Background(), []byte("synthetic"))
			if err == nil || protocol.ShouldRetry(err) || calls != 1 {
				t.Fatal("malformed/error HTTP outcome allowed or retried")
			}
		})
	}
}

func TestNoCredentialProviderCannotTransmit(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: fakeRT(func(*http.Request) (*http.Response, error) { calls++; return response(200, `{}`), nil })}
	for _, p := range []BearerProvider{nil, func(context.Context) (string, error) { return "bad\r\nAuthorization:value", nil }, func(context.Context) (string, error) { return "", errors.New("synthetic-private") }} {
		c := NewHTTPConnector(target, client, p)
		if c.Send(context.Background(), []byte("synthetic")) == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	if calls != 0 {
		t.Fatal("unauthenticated transmission")
	}
}
func TestActualSDKThroughHTTPConnectorWithSyntheticBearer(t *testing.T) {
	raw := rawIntent("climate_start", "{}")
	calls := 0
	b := &budget{limit: 5}
	client := &http.Client{Transport: fakeRT(func(r *http.Request) (*http.Response, error) {
		calls++
		if b.calls != calls || r.Header.Get("Authorization") != "Bearer synthetic-test-bearer" || r.URL.String() != fleetOrigin+"/api/1/vehicles/"+target+"/signed_command" {
			t.Fatal("reservation/auth/origin mismatch")
		}
		var body struct {
			Message []byte `json:"routable_message"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("wire JSON")
		}
		m := &um.RoutableMessage{}
		if proto.Unmarshal(body.Message, m) != nil || m.GetSignatureData().GetHMAC_PersonalizedData() == nil {
			t.Fatal("not SDK signed wire")
		}
		answer := &um.RoutableMessage{ToDestination: m.FromDestination, FromDestination: m.ToDestination, RequestUuid: m.Uuid, Uuid: bytes.Repeat([]byte{7}, 16), Payload: &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: []byte{}}, SignedMessageStatus: &um.MessageStatus{}}
		encoded, _ := proto.Marshal(answer)
		j, _ := json.Marshal(map[string][]byte{"response": encoded})
		return response(200, string(j)), nil
	})}
	e := &Engine{Owner: "synthetic-owner", Target: target, Authority: &authority{binding: sha256.Sum256(raw)}, Budget: b, Key: key(t), Sessions: cached(t, um.Domain_DOMAIN_INFOTAINMENT), NewConnector: func(v string) connector.Connector { return NewHTTPConnector(v, client, syntheticBearer) }}
	if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) != nil || calls != 1 || b.calls != 1 {
		t.Fatal("real SDK HTTP integration failed")
	}
}

func TestPythonCanonicalBindingsAndCatalog(t *testing.T) {
	data, err := os.ReadFile("testdata/python-bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Raw, Binding string }
	if json.Unmarshal(data, &cases) != nil || len(cases) != 43 {
		t.Fatal("canonical fixture missing")
	}
	for _, c := range cases {
		if _, _, _, err := parseIntent([]byte(c.Raw)); err != nil {
			t.Fatal("Python intent refused")
		}
		hash := sha256.Sum256([]byte(c.Raw))
		if hex.EncodeToString(hash[:]) != c.Binding {
			t.Fatal("Python/Go binding mismatch")
		}
	}
}

func TestCachedSDKCounterAdvancesAcrossIndependentOperations(t *testing.T) {
	raw := rawIntent("climate_start", "{}")
	first := conn()
	e, b := engine(t, raw, first)
	e.Sessions = cached(t, um.Domain_DOMAIN_INFOTAINMENT)
	if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) != nil {
		t.Fatal("first operation failed")
	}
	counter := first.last.GetSignatureData().GetHMAC_PersonalizedData().GetCounter()
	second := conn()
	e.Authority = &authority{binding: sha256.Sum256(raw)}
	e.NewConnector = func(string) connector.Connector { return second }
	if e.Run(context.Background(), raw, "synthetic-owner-ticket", facts()) != nil {
		t.Fatal("second independent operation failed")
	}
	if second.last.GetSignatureData().GetHMAC_PersonalizedData().GetCounter() <= counter || b.calls != 2 {
		t.Fatal("cached session counter reused")
	}
}
