package restricted

import (
	"context"
	"crypto/sha256"
	"time"

	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
)

func parseInfotainmentIntent(raw []byte) (PairingIntent, error) {
	var i PairingIntent
	if strictJSON(raw, &i) != nil || i.Version != 1 || i.Action != "verify_infotainment" || i.Principal == "" || len(i.Principal) > 256 || hasControl(i.Principal) || !vinPattern.MatchString(i.Target) {
		return i, refused
	}
	return i, nil
}

// VerifyInfotainment consumes its separate diagnostic authority and performs
// exactly one fresh INFOTAINMENT handshake. Its guard rejects every physical
// payload and every state query before reservation or transmission. There is
// no cached session, wake path, pairing receipt or physical-grant interaction.
func (e *Engine) VerifyInfotainment(ctx context.Context, raw []byte, ticket string, f Facts) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		e.diagnostic.sdkFailure(ctx.Err())
		return refused
	}
	i, err := parseInfotainmentIntent(raw)
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
	if age < 0 || age > 60*time.Second || !f.Scopes["vehicle_cmds"] || !f.ProtocolKnown || !f.Paired || !f.SigningReady || e.Budget == nil || e.Key == nil || e.NewConnector == nil {
		return refused
	}
	ctx, cancel := context.WithTimeout(ctx, engineHandshakeTimeout)
	defer cancel()
	c := e.NewConnector(i.Target)
	if c == nil || c.VIN() != i.Target {
		return refused
	}
	guard := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_INFOTAINMENT, public: e.Key.PublicBytes(), budget: e.Budget, handshakeOnly: true, diagnostic: e.diagnostic}
	car, err := vehicle.NewVehicle(guard, e.Key, nil)
	if err != nil {
		guard.Close()
		e.diagnostic.sdkFailure(err)
		return refused
	}
	defer car.Disconnect()
	if err = car.Connect(ctx); err == nil {
		err = car.StartSession(ctx, []um.Domain{um.Domain_DOMAIN_INFOTAINMENT})
	}
	if err != nil {
		e.diagnostic.sdkFailure(err)
		return refused
	}
	return e.diagnostic.milestone(ctx, "authenticated_session_ready", 0)
}
