package restricted

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"
	"syscall"

	"github.com/teslamotors/vehicle-command/pkg/protocol"
	sig "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/signatures"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/proto"
)

// Diagnostic is deliberately a closed vocabulary, not an error string, type
// name, response, URL, identifier, or transport header. Booleans describe the
// current wire kind; request_written proves a completed client write only.
type Diagnostic struct {
	Stage                       string `json:"stage"`
	FailureStage                string `json:"failure_stage"`
	Kind                        string `json:"kind"`
	ExceptionType               string `json:"exception_type"`
	Category                    string `json:"category"`
	HTTPStatus                  int    `json:"http_status"`
	VehicleError                string `json:"vehicle_error"`
	ReservationAcknowledged     bool   `json:"reservation_acknowledged"`
	HTTPInitiated               bool   `json:"http_initiated"`
	RequestWritten              bool   `json:"request_written"`
	ResponseReceived            bool   `json:"response_received"`
	AuthenticatedSessionReady   bool   `json:"authenticated_session_ready"`
	CheckpointPersistenceFailed bool   `json:"checkpoint_persistence_failed"`
	LocalFinalizationFailed     bool   `json:"local_finalization_failed"`
}

type diagnosticRequest struct {
	OperationID   string `json:"operation_id"`
	BindingSHA256 string `json:"binding_sha256"`
	Sequence      int    `json:"sequence"`
	Diagnostic
}

// The sink stores only operation-bound enum/boolean checkpoints. Every new
// pre-transmission checkpoint must be acknowledged before transmission; a
// missing acknowledgement can never authorize a retry or a second reservation.
type diagnosticRecorder struct {
	mu       sync.Mutex
	value    Diagnostic
	sequence int
	seen     map[string]bool
	failed   bool
	sink     func(context.Context, int, Diagnostic) error
}

func newDiagnostic(sink func(context.Context, int, Diagnostic) error) *diagnosticRecorder {
	return &diagnosticRecorder{value: Diagnostic{Stage: "operation_started", FailureStage: "none", Kind: "operation", ExceptionType: "none", Category: "none", VehicleError: "none"}, seen: map[string]bool{}, sink: sink}
}

func (d *diagnosticRecorder) snapshot() Diagnostic {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.value
}

func (d *diagnosticRecorder) emit(ctx context.Context, stage string) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.emitLocked(ctx, stage)
}

func (d *diagnosticRecorder) emitLocked(ctx context.Context, stage string) error {
	if !diagnosticWord(diagnosticStages, stage) || !diagnosticWord(diagnosticKinds, d.value.Kind) {
		d.failed = true
		// A programming error may not turn caller-supplied text into output.
		d.value.Stage, d.value.FailureStage, d.value.Kind = "operation_failed", "operation_started", "operation"
		d.value.ExceptionType, d.value.Category, d.value.VehicleError = "local_refused", "local", "none"
		return refused
	}
	key := stage + ":" + d.value.Kind
	if d.seen[key] {
		return nil
	}
	if d.failed || d.sequence >= 32 {
		return refused
	}
	d.seen[key] = true
	d.sequence++
	d.value.Stage = stage
	if d.sink != nil && d.sink(ctx, d.sequence, d.value) != nil {
		d.failed = true
		d.value.CheckpointPersistenceFailed = true
		// A failure to persist the final checkpoint must not replace the
		// already classified Fleet/protocol/SDK cause. Neither failure permits
		// another transmission or reservation.
		if d.value.ExceptionType == "none" {
			d.value.FailureStage = stage
			d.value.ExceptionType = "bridge_refused"
			d.value.Category = "bridge"
			d.value.VehicleError = "none"
		}
		return refused
	}
	return nil
}

func (d *diagnosticRecorder) beginAttempt(ctx context.Context, kind string) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed || d.value.ExceptionType != "none" {
		return refused
	}
	d.value.Kind = kind
	d.value.HTTPStatus = 0
	d.value.ReservationAcknowledged = false
	d.value.HTTPInitiated = false
	d.value.RequestWritten = false
	d.value.ResponseReceived = false
	return d.emitLocked(ctx, "reservation_attempted")
}

func (d *diagnosticRecorder) milestone(ctx context.Context, stage string, status int) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch stage {
	case "reservation_acknowledged":
		d.value.ReservationAcknowledged = true
	case "http_initiated":
		d.value.HTTPInitiated = true
	case "request_written":
		d.value.RequestWritten = true
	case "response_received":
		d.value.ResponseReceived = true
		if status >= 100 && status <= 599 {
			d.value.HTTPStatus = status
		}
	case "authenticated_session_ready":
		d.value.AuthenticatedSessionReady = true
	}
	return d.emitLocked(ctx, stage)
}

func (d *diagnosticRecorder) noteFailure(exception, category, vehicle, stage string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if exception == "none" || category == "none" || !diagnosticWord(diagnosticExceptions, exception) || !diagnosticWord(diagnosticCategories, category) || !diagnosticWord(diagnosticVehicleErrors, vehicle) || !diagnosticWord(diagnosticStages, stage) {
		exception, category, vehicle, stage = "local_refused", "local", "none", "operation_started"
	}
	if d.value.ExceptionType == "none" {
		d.value.ExceptionType, d.value.Category, d.value.VehicleError = exception, category, vehicle
		d.value.FailureStage = stage
	}
}

func (d *diagnosticRecorder) finish(ctx context.Context, err error) error {
	if d == nil {
		return err
	}
	if err != nil {
		v := d.snapshot()
		d.noteFailure("local_refused", "local", "none", v.Stage)
		_ = d.emit(ctx, "operation_failed")
		return refused
	}
	if d.emit(ctx, "operation_succeeded") != nil {
		d.mu.Lock()
		d.value.Stage = "operation_failed"
		d.mu.Unlock()
		return refused
	}
	return nil
}

func safeException(err error) (string, string) {
	if errors.Is(err, context.DeadlineExceeded) {
		return "context_deadline", "context"
	}
	if errors.Is(err, context.Canceled) {
		return "context_canceled", "context"
	}
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verification *tls.CertificateVerificationError
	if errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &verification) {
		return "tls_certificate", "tls"
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return "tls_handshake", "tls"
	}
	var network net.Error
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "network_dns", "transport"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "network_refused", "transport"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "network_reset", "transport"
	}
	if errors.As(err, &network) {
		if network.Timeout() {
			return "network_timeout", "transport"
		}
		return "network_error", "transport"
	}
	return "network_error", "transport"
}

func (d *diagnosticRecorder) sdkFailure(err error) {
	if d == nil || err == nil {
		return
	}
	exception, category := safeException(err)
	if category == "transport" && exception == "network_error" {
		exception, category = "sdk_error", "sdk"
		for _, candidate := range []struct {
			err       error
			exception string
		}{
			{protocol.ErrKeyNotPaired, "sdk_key_not_paired"},
			{protocol.ErrInvalidPublicKey, "sdk_invalid_public_key"},
			{protocol.ErrBadResponse, "sdk_bad_response"},
			{protocol.ErrNoSession, "sdk_no_session"},
			{protocol.ErrNotConnected, "sdk_not_connected"},
			{protocol.ErrRequiresKey, "sdk_requires_key"},
			{protocol.ErrProtocolNotSupported, "sdk_protocol_unsupported"},
			{protocol.ErrReplayedResponse, "sdk_replayed_response"},
			{protocol.ErrUnpexpectedPublicKey, "sdk_unexpected_public_key"},
			{protocol.ErrNoDecryptionContext, "sdk_no_decryption_context"},
			{protocol.ErrRequiresEncryption, "sdk_requires_encryption"},
			{protocol.ErrRequiresBLE, "sdk_requires_ble"},
			{protocol.ErrBusy, "sdk_busy"},
			{protocol.ErrUnknown, "sdk_unknown"},
		} {
			if errors.Is(err, candidate.err) {
				exception = candidate.exception
				break
			}
		}
		var fault *protocol.RoutableMessageError
		if errors.As(err, &fault) {
			v := d.snapshot()
			d.noteFailure("sdk_routable_fault", "sdk", safeMessageFault(fault.Code), v.Stage)
			return
		}
		if protocol.IsNominalError(err) {
			exception = "sdk_nominal_error"
		}
		var nominal *protocol.NominalVCSECError
		if errors.As(err, &nominal) {
			exception = "sdk_nominal_error"
		}
	}
	v := d.snapshot()
	d.noteFailure(exception, category, "none", v.Stage)
}

type diagnosticTransport struct {
	base       http.RoundTripper
	diagnostic *diagnosticRecorder
}

func (t diagnosticTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// Do has entered its transport. This checkpoint does not assert that bytes
	// were sent; only WroteRequest (with nil error) establishes a complete write.
	if t.diagnostic.milestone(request.Context(), "http_initiated", 0) != nil {
		return nil, refused
	}
	return t.base.RoundTrip(request)
}

// Vehicle status is an unauthenticated classification hint until the SDK has
// authenticated the session. Never persist inner payloads or free-form reasons.
func safeVehicleError(raw []byte) string {
	var reply um.RoutableMessage
	if proto.Unmarshal(raw, &reply) != nil {
		return "malformed_response"
	}
	if fault := safeMessageFault(reply.GetSignedMessageStatus().GetSignedMessageFault()); fault != "none" {
		return fault
	}
	if reply.GetSessionInfo() != nil {
		var info sig.SessionInfo
		if proto.Unmarshal(reply.GetSessionInfo(), &info) != nil {
			return "malformed_response"
		}
		if info.Status == sig.Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST {
			return "not_whitelisted"
		}
	}
	return "unclassified"
}

// Do not use protobuf enum String(): unknown numeric values and raw messages
// must never escape. All hints remain unauthenticated until SDK session ready.
func safeMessageFault(fault um.MessageFault_E) string {
	switch fault {
	case um.MessageFault_E_MESSAGEFAULT_ERROR_BUSY:
		return "busy"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_TIMEOUT:
		return "timeout"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_UNKNOWN_KEY_ID:
		return "unknown_key"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INACTIVE_KEY:
		return "inactive_key"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_KEY_HANDLE:
		return "invalid_key_handle"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_SIGNATURE:
		return "invalid_signature"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER:
		return "invalid_counter"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INCORRECT_EPOCH:
		return "incorrect_epoch"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_REPEATED_COUNTER:
		return "repeated_counter"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_TIME_EXPIRED:
		return "request_expired"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_NONE:
		return "none"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INSUFFICIENT_PRIVILEGES:
		return "insufficient_privileges"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_DOMAINS:
		return "invalid_domain"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_COMMAND:
		return "invalid_command"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_DECODING:
		return "decoding"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_INTERNAL:
		return "internal"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_WRONG_PERSONALIZATION:
		return "wrong_personalization"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_BAD_PARAMETER:
		return "bad_parameter"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_KEYCHAIN_IS_FULL:
		return "keychain_full"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_IV_INCORRECT_LENGTH:
		return "invalid_iv"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_NOT_PROVISIONED_WITH_IDENTITY:
		return "identity_missing"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_COULD_NOT_HASH_METADATA:
		return "metadata_hash"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_TIME_TO_LIVE_TOO_LONG:
		return "expiry_too_long"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_REMOTE_ACCESS_DISABLED:
		return "remote_access_disabled"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_REMOTE_SERVICE_ACCESS_DISABLED:
		return "remote_service_access_disabled"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_COMMAND_REQUIRES_ACCOUNT_CREDENTIALS:
		return "account_credentials_required"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_REQUEST_MTU_EXCEEDED:
		return "request_mtu"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_RESPONSE_MTU_EXCEEDED:
		return "response_mtu"
	case um.MessageFault_E_MESSAGEFAULT_ERROR_REQUIRES_RESPONSE_ENCRYPTION:
		return "response_encryption_required"
	default:
		return "unknown_fault"
	}
}
