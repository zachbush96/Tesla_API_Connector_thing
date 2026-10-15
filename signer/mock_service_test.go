package restricted

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mockToken = "synthetic-local-owner-token-abcdefghijklmnopqrstuvwxyz1234567890"

func testService(t *testing.T) *MockService {
	return &MockService{owner: "synthetic-owner", target: target, token: mockToken, existingKey: key(t), used: map[string]time.Time{}, now: time.Now}
}
func serviceRequest(s *MockService, method, path string, body []byte, authorized bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+LocalSignerAddress+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if authorized {
		r.Header.Set("Authorization", "Bearer "+mockToken)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func simulateRequest(raw []byte, id string) []byte {
	body, _ := json.Marshal(map[string]any{"operation_id": id, "intent": json.RawMessage(raw)})
	return body
}
func TestLocalSignerAuthorizationAndNoActionHealth(t *testing.T) {
	s := testService(t)
	if serviceRequest(s, "GET", "/health", nil, false).Code != 401 {
		t.Fatal("unauthenticated health")
	}
	w := serviceRequest(s, "GET", "/health", nil, true)
	var v map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v["execution_enabled"] != false || v["fleet_network_enabled"] != false || v["existing_signing_key_matches_public"] != true {
		t.Fatal("bad no-action health")
	}
	if len(s.used) != 0 {
		t.Fatal("health simulated action")
	}
}
func TestLocalSignerAllCatalogActionsUseActualSDKWithoutFleet(t *testing.T) {
	s := testService(t)
	params := map[string]string{"set_temperature": `{"driver_temp":22,"passenger_temp":22}`, "set_charge_limit": `{"percent":80}`, "set_charging_amps": `{"charging_amps":16}`, "front_trunk": `{"which_trunk":"front"}`, "rear_trunk": `{"which_trunk":"rear"}`, "navigation_send": `{"locale":"en-US","timestamp_ms":"1791650000000","type":"share_ext_content_raw","value":{"android.intent.ACTION":"android.intent.action.SEND","android.intent.TEXT":"Synthetic address","android.intent.TYPE":"text/plain","android.intent.extra.TEXT":"Synthetic address"}}`}
	n := 0
	for action := range legacyTestCatalog() {
		n++
		p := params[action]
		if p == "" {
			p = "{}"
		}
		w := serviceRequest(s, "POST", "/simulate", simulateRequest(rawIntent(action, p), fmt.Sprintf("%032x", n)), true)
		var v map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v["action"] != action || v["simulated"] != true || v["executed"] != false || v["execution_enabled"] != false || v["synthetic_sdk_requests"] != float64(1) || v["fleet_network_requests"] != float64(0) || v["gross_reserved_microdollars"] != float64(0) || strings.Contains(w.Body.String(), "Synthetic address") || strings.Contains(w.Body.String(), target) {
			t.Fatalf("mock SDK catalog action failed: %s status %d", action, w.Code)
		}
	}
}
func TestLocalSignerReplayChangedOwnerAndTargetRefused(t *testing.T) {
	s := testService(t)
	id := strings.Repeat("a", 32)
	raw := rawIntent("lock", "{}")
	if serviceRequest(s, "POST", "/simulate", simulateRequest(raw, id), true).Code != 200 {
		t.Fatal("first simulation")
	}
	if serviceRequest(s, "POST", "/simulate", simulateRequest(raw, id), true).Code != 409 {
		t.Fatal("replay")
	}
	if serviceRequest(s, "POST", "/simulate", simulateRequest(rawIntent("unlock", "{}"), id), true).Code != 409 {
		t.Fatal("changed replay")
	}
	for _, field := range []string{"principal", "target"} {
		var i map[string]any
		json.Unmarshal(raw, &i)
		i[field] = "other"
		altered, _ := json.Marshal(i)
		if serviceRequest(s, "POST", "/simulate", simulateRequest(altered, strings.Repeat("b", 32)), true).Code != 403 {
			t.Fatal("foreign binding accepted")
		}
	}
}
func TestLocalSignerDuplicateApprovalAndAlternatePathsRefused(t *testing.T) {
	s := testService(t)
	good := simulateRequest(rawIntent("lock", "{}"), strings.Repeat("a", 32))
	for _, raw := range [][]byte{bytes.Replace(good, []byte(`"operation_id":`), []byte(`"approved":true,"operation_id":`), 1), bytes.Replace(good, []byte(`"operation_id":`), []byte(`"operation_id":"bad","operation_id":`), 1), []byte(strings.Repeat("x", 16385))} {
		if serviceRequest(s, "POST", "/simulate", raw, true).Code != 400 {
			t.Fatal("invalid mock body accepted")
		}
	}
	for _, path := range []string{"/execute", "/wake", "/command/door_unlock"} {
		if serviceRequest(s, "POST", path, good, true).Code != 404 {
			t.Fatal("alternate live path")
		}
	}
	r := httptest.NewRequest("GET", "https://foreign.invalid/health", nil)
	r.Header.Set("Authorization", "Bearer "+mockToken)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("foreign host")
	}
}
func TestProtectedConfigExistingPairAndNoActivationOption(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if os.WriteFile(p, b, 0600) != nil {
			t.Fatal("fixture write")
		}
		return p
	}
	k := key(t)
	priv := filepath.Join(dir, "signing.pem")
	if protocol.SavePrivateKey(k, priv) != nil {
		t.Fatal("fixture private key")
	}
	pub, _ := ecdh.P256().NewPublicKey(k.PublicBytes())
	der, _ := x509.MarshalPKIXPublicKey(pub)
	public := write("public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	c := ServiceConfig{Owner: "synthetic-owner", Target: target, TokenFile: write("token", []byte(mockToken)), SigningPrivateFile: priv, SigningPublicFile: public, TLSCertificateFile: write("tls.cert", []byte("synthetic")), TLSPrivateFile: write("tls.key", []byte("synthetic"))}
	raw, _ := json.Marshal(c)
	config := write("config.json", raw)
	s, _, err := LoadMockService(config)
	if err != nil || s.existingKey == nil || physicalExecutionEnabled {
		t.Fatal("valid protected matching pair refused")
	}
	os.Chmod(c.TokenFile, 0644)
	if _, _, err = LoadMockService(config); err == nil {
		t.Fatal("unsafe token mode")
	}
	os.Chmod(c.TokenFile, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(c.TokenFile, link)
	if _, err = ProtectedRead(link); err == nil {
		t.Fatal("credential symlink")
	}
	raw = bytes.Replace(raw, []byte(`"owner":`), []byte(`"execution_enabled":true,"owner":`), 1)
	write("config.json", raw)
	if _, _, err = LoadMockService(config); err == nil {
		t.Fatal("configuration activated execution")
	}
}
