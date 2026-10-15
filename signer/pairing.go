package restricted

import (
	"context"
	"crypto/sha256"
	"time"

	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
)

// PairingIntent grants only a fresh authenticated security-session handshake.
// It has no physical action, command parameters, cached session or wake path.
type PairingIntent struct {
	Version   int    `json:"version"`
	Principal string `json:"principal"`
	Target    string `json:"target"`
	Action    string `json:"action"`
}

func parsePairingIntent(raw []byte) (PairingIntent, error) {
	var i PairingIntent
	if strictJSON(raw, &i) != nil || i.Version != 1 || i.Action != "verify_pairing" || i.Principal == "" || len(i.Principal) > 256 || hasControl(i.Principal) || !vinPattern.MatchString(i.Target) {
		return i, refused
	}
	return i, nil
}

// VerifyPairing authenticates the vehicle's fresh challenge response using the
// configured private key. A mere key count or local public/private match cannot
// satisfy this check. Authority is consumed before any connector or budget use.
func (e *Engine) VerifyPairing(ctx context.Context, raw []byte, ticket string, f Facts) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		e.diagnostic.sdkFailure(ctx.Err())
		return refused
	}
	i, err := parsePairingIntent(raw)
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
	if age < 0 || age > 60*time.Second || !f.Scopes["vehicle_cmds"] || !f.ProtocolKnown || !f.Awake || e.Budget == nil || e.Key == nil || e.NewConnector == nil {
		return refused
	}
	ctx, cancel := context.WithTimeout(ctx, engineHandshakeTimeout)
	defer cancel()
	c := e.NewConnector(i.Target)
	if c == nil || c.VIN() != i.Target {
		return refused
	}
	guard := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_VEHICLE_SECURITY, public: e.Key.PublicBytes(), budget: e.Budget, handshakeOnly: true, diagnostic: e.diagnostic}
	car, err := vehicle.NewVehicle(guard, e.Key, nil)
	if err != nil {
		guard.Close()
		e.diagnostic.sdkFailure(err)
		return refused
	}
	defer car.Disconnect()
	if err = car.Connect(ctx); err == nil {
		err = car.StartSession(ctx, []um.Domain{um.Domain_DOMAIN_VEHICLE_SECURITY})
	}
	if err != nil {
		e.diagnostic.sdkFailure(err)
		return refused
	}
	if e.diagnostic.milestone(ctx, "authenticated_session_ready", 0) != nil {
		return refused
	}
	return nil
}
