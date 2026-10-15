package restricted

import (
	"context"
	"crypto/sha256"
	"time"

	cs "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
	"google.golang.org/protobuf/proto"
)

func driveQueryOnly(raw []byte) bool {
	var action cs.Action
	if proto.Unmarshal(raw, &action) != nil {
		return false
	}
	expected := &cs.Action{ActionMsg: &cs.Action_VehicleAction{VehicleAction: &cs.VehicleAction{VehicleActionMsg: &cs.VehicleAction_GetVehicleData{GetVehicleData: &cs.GetVehicleData{GetDriveState: &cs.GetDriveState{}}}}}}
	return proto.Equal(&action, expected)
}

// ReadParked is the preflight phase of an exact already-claimed physical intent.
// Its connector admits only one fresh infotainment handshake and exactly the
// SDK Drive-state query. Park must be explicit and at least as recent as the
// REST drive observation. Absent speed is allowed only with explicit Park;
// zero speed never substitutes for Park or overrides contradictory movement.
func (e *Engine) ReadParked(ctx context.Context, raw []byte, ticket string, f Facts) (time.Time, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		e.diagnostic.sdkFailure(ctx.Err())
		return time.Time{}, refused
	}
	i, s, _, err := parseIntent(raw)
	if err != nil || i.Principal != e.Owner || i.Target != e.Target || e.Authority == nil {
		return time.Time{}, refused
	}
	if e.Authority.Consume(ticket, sha256.Sum256(raw)) != nil {
		return time.Time{}, refused
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	age := now.Sub(f.Observed)
	driveAge := now.Sub(f.DriveObserved)
	if !s.requiresPark || age < 0 || age > 60*time.Second || f.DriveObserved.IsZero() || driveAge < 0 || driveAge > 60*time.Second || f.DriveObserved.Before(f.Observed) || !f.Scopes[s.scope] || !f.Scopes["vehicle_device_data"] || !f.Paired || !f.SigningReady || !f.ProtocolKnown || e.Budget == nil || e.Key == nil || e.NewConnector == nil {
		return time.Time{}, refused
	}
	ctx, cancel := context.WithTimeout(ctx, enginePhysicalTimeout)
	defer cancel()
	c := e.NewConnector(i.Target)
	if c == nil || c.VIN() != i.Target {
		return time.Time{}, refused
	}
	guard := &guardConnector{Connector: c, domain: um.Domain_DOMAIN_INFOTAINMENT, public: e.Key.PublicBytes(), budget: e.Budget, payloadAllowed: driveQueryOnly, diagnostic: e.diagnostic, diagnosticPrefix: "state_"}
	car, err := vehicle.NewVehicle(guard, e.Key, nil)
	if err != nil {
		guard.Close()
		e.diagnostic.sdkFailure(err)
		return time.Time{}, refused
	}
	defer car.Disconnect()
	if err = car.Connect(ctx); err == nil {
		err = car.StartSession(ctx, []um.Domain{um.Domain_DOMAIN_INFOTAINMENT})
	}
	if err != nil {
		e.diagnostic.sdkFailure(err)
		return time.Time{}, refused
	}
	if e.diagnostic.milestone(ctx, "authenticated_session_ready", 0) != nil {
		return time.Time{}, refused
	}
	data, err := car.GetState(ctx, vehicle.StateCategoryDrive)
	if err != nil || data == nil || data.GetDriveState() == nil {
		if err != nil {
			e.diagnostic.sdkFailure(err)
		}
		return time.Time{}, refused
	}
	drive := data.GetDriveState()
	park, ok := drive.GetShiftState().GetType().(*cs.ShiftState_P)
	stamp := drive.GetTimestamp()
	if !ok || park == nil || park.P == nil || stamp == nil || stamp.CheckValid() != nil || len(drive.ProtoReflect().GetUnknown()) != 0 || len(drive.GetShiftState().ProtoReflect().GetUnknown()) != 0 || !sdkSpeedStationary(drive) {
		return time.Time{}, refused
	}
	observed := stamp.AsTime()
	now = time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	age = now.Sub(observed)
	if age < 0 || age > 60*time.Second || observed.Before(f.DriveObserved) {
		return time.Time{}, refused
	}
	if e.Sessions == nil || car.UpdateCachedSessions(e.Sessions) != nil {
		return time.Time{}, refused
	}
	return observed, nil
}

// The pinned protobuf exposes integer and float speed as independent optional
// fields. Checking getters alone would silently treat absence/malformed values
// as zero; require every present representation to be exactly stationary.
func sdkSpeedStationary(drive *cs.DriveState) bool {
	if drive == nil {
		return false
	}
	switch speed := drive.GetOptionalSpeed().(type) {
	case nil:
	case *cs.DriveState_Speed:
		if speed == nil || speed.Speed != 0 {
			return false
		}
	default:
		return false
	}
	switch speed := drive.GetOptionalSpeedFloat().(type) {
	case nil:
	case *cs.DriveState_SpeedFloat:
		// != 0 also rejects negative values, infinities and NaN.
		if speed == nil || speed.SpeedFloat != 0 {
			return false
		}
	default:
		return false
	}
	return true
}
