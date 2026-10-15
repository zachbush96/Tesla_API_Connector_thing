package restricted

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/teslamotors/vehicle-command/pkg/connector"
)

func TestChargingRequiredFactsRefusedBeforeSDKOrBudget(t *testing.T) {
	for _, action := range []string{"charge_start", "charge_port_close"} {
		t.Run(action, func(t *testing.T) {
			f := facts()
			if action == "charge_start" {
				f.Cable = false
			} else {
				f.MotorizedPort = false
			}
			// Bool zero represents both unavailable evidence and a negative fact.
			raw := rawIntent(action, "{}")
			wire := conn()
			e, b := engine(t, raw, wire)
			connectorCalls, restCalls := 0, 0
			e.NewConnector = func(string) connector.Connector { connectorCalls++; return wire }
			e.RESTClient = &http.Client{Transport: fakeRT(func(*http.Request) (*http.Response, error) { restCalls++; return nil, refused })}
			if e.Run(context.Background(), raw, "synthetic-owner-ticket", f) == nil {
				t.Fatal("missing required charging fact accepted")
			}
			if b.calls != 0 || connectorCalls != 0 || wire.calls != 0 || restCalls != 0 {
				t.Fatal("missing charging fact reached budget, SDK or transport")
			}
		})
	}
}

func TestChargingRequiredTrueFactsCompleteSDKMock(t *testing.T) {
	for _, action := range []string{"charge_start", "charge_port_close"} {
		t.Run(action, func(t *testing.T) {
			count, err := simulateSDK(context.Background(), rawIntent(action, "{}"), "synthetic-owner-ticket", "synthetic-owner", target)
			if err != nil || count != 1 {
				t.Fatal("known charging prerequisite failed the complete SDK mock path")
			}
		})
	}
}

func TestChargingRequirementsAreActionSpecificWithoutParkReads(t *testing.T) {
	for _, action := range []string{"charge_start", "charge_port_close"} {
		t.Run(action, func(t *testing.T) {
			h := newLiveHarness(t)
			h.facts.Cable = action == "charge_start"
			h.facts.MotorizedPort = action == "charge_port_close"
            h.facts.CableAbsent = action == "charge_port_close"
			h.facts.Parked = false
			h.facts.Awake = false
			delete(h.facts.Scopes, "vehicle_device_data")
			w := liveRequest(h, "/execute", rawIntent(action, "{}"), strings.Repeat("a", 32))
			if w.Code != 200 || h.sends != 2 || h.reserves != 2 || h.stateReceipts != 0 || strings.Join(h.kinds, ",") != "handshake,command" {
				t.Fatal("charging required unrelated hardware, Park or an extra request")
			}
		})
	}
}
