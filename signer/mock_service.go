package restricted

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/cache"
	"github.com/teslamotors/vehicle-command/pkg/connector"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	sig "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/signatures"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/proto"
)

const LocalSignerAddress = "127.0.0.1:8766"

// This build has no physical execution switch. Config, request and environment
// inputs cannot activate Fleet network transports. All SDK sends are in-process.
const physicalExecutionEnabled = false

type ServiceConfig struct {
	Owner              string `json:"owner"`
	Target             string `json:"target"`
	TokenFile          string `json:"token_file"`
	SigningPrivateFile string `json:"signing_private_file"`
	SigningPublicFile  string `json:"signing_public_file"`
	TLSCertificateFile string `json:"tls_certificate_file"`
	TLSPrivateFile     string `json:"tls_private_file"`
}

// ProtectedRead rejects symlinks, unsafe ownership/permissions and oversized
// files before any credential read. Parent is an owner-private directory.
func ProtectedRead(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, refused
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return nil, refused
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() {
		return nil, refused
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, refused
	}
	p, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || int(p.Uid) != os.Getuid() {
		return nil, refused
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 65536 {
		return nil, refused
	}
	return data, nil
}

type MockService struct {
	mu                   sync.Mutex
	owner, target, token string
	existingKey          protocol.ECDHPrivateKey // Approved existing key; never used by simulations.
	used                 map[string]time.Time
	now                  func() time.Time
}

func LoadMockService(path string) (*MockService, ServiceConfig, error) {
	var c ServiceConfig
	raw, err := ProtectedRead(path)
	if err != nil || strictJSON(raw, &c) != nil || c.Owner == "" || len(c.Owner) > 256 || hasControl(c.Owner) || !vinPattern.MatchString(c.Target) {
		return nil, c, refused
	}
	token, err := ProtectedRead(c.TokenFile)
	if err != nil || len(token) < 32 || len(token) > 4096 || strings.ContainsAny(string(token), "\r\n\t ") {
		return nil, c, refused
	}
	for _, path := range []string{c.SigningPrivateFile, c.SigningPublicFile, c.TLSCertificateFile, c.TLSPrivateFile} {
		if _, err := ProtectedRead(path); err != nil {
			return nil, c, refused
		}
	}
	pubRaw, err := ProtectedRead(c.SigningPublicFile)
	if err != nil {
		return nil, c, refused
	}
	block, rest := pem.Decode(pubRaw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, c, refused
	}
	key, err := protocol.LoadPrivateKey(c.SigningPrivateFile)
	if err != nil {
		return nil, c, refused
	}
	pub, err := protocol.LoadPublicKey(c.SigningPublicFile)
	if err != nil || !bytes.Equal(key.PublicBytes(), pub.Bytes()) {
		return nil, c, refused
	}
	return &MockService{owner: c.Owner, target: c.Target, token: string(token), existingKey: key, used: map[string]time.Time{}, now: time.Now}, c, nil
}
func (s *MockService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(status int) {
		w.WriteHeader(status)
		io.WriteString(w, `{"error":"Local signing operation refused; no vehicle request"}`)
	}
	value := r.Header.Get("Authorization")
	expected := "Bearer " + s.token
	if r.Host != LocalSignerAddress || len(value) != len(expected) || !constantBytes([]byte(value), []byte(expected)) || r.URL.RawQuery != "" {
		fail(401)
		return
	}
	if r.URL.Path == "/health" && r.Method == "GET" {
		json.NewEncoder(w).Encode(map[string]any{"status": "ready", "mode": "sdk-mock-only", "execution_enabled": physicalExecutionEnabled, "infotainment_diagnostic_enabled": false, "existing_signing_key_matches_public": s.existingKey != nil, "sdk_commit": SDKCommit, "fleet_network_enabled": false, "budget_reservation_enabled": false})
		return
	}
	if r.URL.Path != "/simulate" || r.Method != "POST" || strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(404)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(raw) > 16384 {
		fail(400)
		return
	}
	var request struct {
		OperationID string          `json:"operation_id"`
		Intent      json.RawMessage `json:"intent"`
	}
	if strictJSON(raw, &request) != nil || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(request.OperationID) {
		fail(400)
		return
	}
	intent, _, _, err := parseIntent(request.Intent)
	if err != nil || intent.Principal != s.owner || intent.Target != s.target {
		fail(403)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, t := range s.used {
		if now.Sub(t) > 300*time.Second {
			delete(s.used, id)
		}
	}
	if _, ok := s.used[request.OperationID]; ok || len(s.used) >= 1024 {
		fail(409)
		return
	}
	s.used[request.OperationID] = now
	attempts, err := simulateSDK(r.Context(), request.Intent, request.OperationID, s.owner, s.target)
	if err != nil {
		fail(400)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"action": intent.Action, "simulated": true, "executed": false, "vehicle_execution_verified": false, "execution_enabled": false, "sdk_commit": SDKCommit, "synthetic_sdk_requests": attempts, "fleet_network_requests": 0, "gross_reserved_microdollars": 0})
}
func constantBytes(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

type mockClaim struct {
	ticket  string
	binding [32]byte
	used    bool
}

func (a *mockClaim) Consume(ticket string, b [32]byte) error {
	if a.used {
		return refused
	}
	a.used = true
	if ticket != a.ticket || b != a.binding {
		return refused
	}
	return nil
}

type mockBudget struct{ count int }

func (b *mockBudget) Reserve(category string) error {
	if category != "commands" || b.count >= 2 {
		return refused
	}
	b.count++
	return nil
}

type mockWire struct {
	target string
	inbox  chan []byte
	closed bool
	mu     sync.Mutex
}

func (c *mockWire) VIN() string                               { return c.target }
func (c *mockWire) PreferredAuthMethod() connector.AuthMethod { return connector.AuthMethodHMAC }
func (c *mockWire) RetryInterval() time.Duration              { return time.Millisecond }
func (c *mockWire) AllowedLatency() time.Duration             { return time.Second }
func (c *mockWire) Receive() <-chan []byte                    { return c.inbox }
func (c *mockWire) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.inbox)
	}
}
func (c *mockWire) Send(_ context.Context, raw []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return terminal()
	}
	var m um.RoutableMessage
	if proto.Unmarshal(raw, &m) != nil || m.GetSignatureData().GetHMAC_PersonalizedData() == nil {
		return terminal()
	}
	response := &um.RoutableMessage{ToDestination: m.FromDestination, FromDestination: m.ToDestination, RequestUuid: m.Uuid, Uuid: bytes.Repeat([]byte{7}, 16), Payload: &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: []byte{}}, SignedMessageStatus: &um.MessageStatus{}}
	encoded, err := proto.Marshal(response)
	if err != nil {
		return terminal()
	}
	c.inbox <- encoded
	return nil
}

type mockREST struct{}

func (mockREST) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"response":{"result":true}}`))}, nil
}
func simulateSDK(ctx context.Context, raw []byte, ticket, owner, target string) (int, error) {
	intent, spec, _, err := parseIntent(raw)
	if err != nil {
		return 0, refused
	}
	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return 0, refused
	}
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return 0, refused
	}
	info, err := proto.Marshal(&sig.SessionInfo{PublicKey: peer.PublicKey().Bytes(), Epoch: bytes.Repeat([]byte{2}, 16)})
	if err != nil {
		return 0, refused
	}
	encoded, err := json.Marshal(map[string]any{"MaxEntries": 1, "vehicles": map[string]any{target: []map[string]any{{"CreatedAt": time.Now(), "Domain": int(spec.domain), "data": info}}}})
	if err != nil {
		return 0, refused
	}
	sessions, err := cache.Import(bytes.NewReader(encoded))
	if err != nil {
		return 0, refused
	}
	budget := &mockBudget{}
	wire := &mockWire{target: target, inbox: make(chan []byte, 5)}
	engine := &Engine{Owner: owner, Target: target, Authority: &mockClaim{ticket: ticket, binding: sha256.Sum256(raw)}, Budget: budget, Key: protocol.UnmarshalECDHPrivateKey(local.Bytes()), Sessions: sessions, NewConnector: func(string) connector.Connector { return wire }, RESTClient: &http.Client{Transport: mockREST{}}, Bearer: func(context.Context) (string, error) { return "synthetic-local-mock", nil }}
	facts := Facts{Scopes: map[string]bool{catalog[intent.Action].scope: true}, Paired: true, SigningReady: true, ProtocolKnown: true, Parked: true, Awake: true, Cable: intent.Action != "charge_port_close", CableAbsent: true, ClimateActive: true, UserPresent: true, MobileAccess: true, MotorizedPort: true, Observed: time.Now()}
	err = engine.Run(ctx, raw, ticket, facts)
	return budget.count, err
}
