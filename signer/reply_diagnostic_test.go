package restricted

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/cache"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	cs "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	sig "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/signatures"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Every key, address, UUID and payload in these fixtures is generated locally
// for this test. No connector transport, protected file or runtime is used.
type replyDiagnosticFixture struct {
	local, peer protocol.ECDHPrivateKey
	request     *um.RoutableMessage
	response    *um.RoutableMessage
	info        *sig.SessionInfo
}

func replyDiagnosticRouting(t *testing.T, value []byte) *um.Destination {
	t.Helper()
	d := &um.Destination{}
	f := d.ProtoReflect().Descriptor().Fields().ByName("routing_address")
	if f == nil {
		t.Fatal("pinned routing-address field missing")
	}
	d.ProtoReflect().Set(f, protoreflect.ValueOfBytes(append([]byte(nil), value...)))
	return d
}

func replyDiagnosticMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(message)
	if err != nil {
		t.Fatal("synthetic protobuf construction failed")
	}
	return raw
}

func replyDiagnosticUnknown(message proto.Message) {
	unknown := protowire.AppendTag(nil, 19000, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte(redactionSentinel))
	message.ProtoReflect().SetUnknown(unknown)
}

func newReplyDiagnosticFixture(t *testing.T) *replyDiagnosticFixture {
	t.Helper()
	f := &replyDiagnosticFixture{local: key(t), peer: key(t)}
	if len(f.peer.PublicBytes()) != 65 || f.peer.PublicBytes()[0] != 4 {
		t.Fatal("synthetic peer must use an uncompressed P256 public key")
	}
	f.request = &um.RoutableMessage{
		ToDestination:   &um.Destination{SubDestination: &um.Destination_Domain{Domain: um.Domain_DOMAIN_INFOTAINMENT}},
		FromDestination: replyDiagnosticRouting(t, bytes.Repeat([]byte{0x31}, 16)),
		Uuid:            bytes.Repeat([]byte{0x42}, 16),
	}
	// Construct the pinned SDK's request message without inventing an alternate
	// wire schema. The generated descriptor supplies the concrete payload type.
	requestField := f.request.ProtoReflect().Descriptor().Fields().ByName("session_info_request")
	if requestField == nil {
		t.Fatal("pinned session-info request field missing")
	}
	requestInfo := f.request.ProtoReflect().Mutable(requestField).Message()
	publicField := requestInfo.Descriptor().Fields().ByName("public_key")
	if publicField == nil {
		t.Fatal("pinned session-info public-key field missing")
	}
	requestInfo.Set(publicField, protoreflect.ValueOfBytes(f.local.PublicBytes()))
	f.response = &um.RoutableMessage{
		ToDestination:       proto.Clone(f.request.FromDestination).(*um.Destination),
		FromDestination:     proto.Clone(f.request.ToDestination).(*um.Destination),
		RequestUuid:         append([]byte(nil), f.request.Uuid...),
		Uuid:                bytes.Repeat([]byte{0x53}, 16),
		SignedMessageStatus: &um.MessageStatus{},
	}
	f.setInfo(t, &sig.SessionInfo{PublicKey: f.peer.PublicBytes(), Epoch: bytes.Repeat([]byte{0x64}, 16), Status: sig.Session_Info_Status_SESSION_INFO_STATUS_OK})
	return f
}

func (f *replyDiagnosticFixture) setInfo(t *testing.T, info *sig.SessionInfo) {
	t.Helper()
	f.info = proto.Clone(info).(*sig.SessionInfo)
	f.setInfoRaw(t, replyDiagnosticMarshal(t, f.info))
}

func (f *replyDiagnosticFixture) setInfoRaw(t *testing.T, raw []byte) {
	t.Helper()
	session, err := f.peer.Exchange(f.local.PublicBytes())
	if err != nil {
		t.Fatal("synthetic shared-secret construction failed")
	}
	tag, err := session.SessionInfoHMAC([]byte(target), f.request.Uuid, raw)
	if err != nil {
		t.Fatal("synthetic session-info HMAC construction failed")
	}
	f.response.Payload = &um.RoutableMessage_SessionInfo{SessionInfo: append([]byte(nil), raw...)}
	f.response.SubSigData = &um.RoutableMessage_SignatureData{SignatureData: &sig.SignatureData{SigType: &sig.SignatureData_SessionInfoTag{SessionInfoTag: &sig.HMAC_Signature_Data{Tag: tag}}}}
}

func TestReplyDiagnosticValidSessionHMAC(t *testing.T) {
	for _, omitOuterStatus := range []bool{false, true} {
		t.Run(map[bool]string{false: "outer_status_present", true: "outer_status_absent"}[omitOuterStatus], func(t *testing.T) {
			f := newReplyDiagnosticFixture(t)
			if omitOuterStatus {
				f.response.SignedMessageStatus = nil
			}
			c := &HTTPConnector{target: target, key: f.local}
			if c.checkReply(replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response)) != nil {
				t.Fatal("valid synthetic authenticated handshake refused")
			}
			if !bytes.Equal(c.remotePublic, f.peer.PublicBytes()) {
				t.Fatal("valid handshake did not retain the authenticated peer key")
			}
		})
	}
}

func assertReplyDiagnosticFailure(t *testing.T, c *HTTPConnector, request, response []byte, exception, category, vehicle string) {
	t.Helper()
	before := append([]byte(nil), c.remotePublic...)
	err := c.checkReply(request, response)
	var failure *replyFailure
	if err == nil || !errors.As(err, &failure) {
		t.Fatal("reply was accepted or lost its fixed classification")
	}
	if failure.exception != exception || failure.category != category || failure.vehicle != vehicle {
		t.Fatal("reply classification differs from the explicit fixture contract")
	}
	if err.Error() != "restricted response refused" {
		t.Fatal("reply failure exposed nonfixed error text")
	}
	if !bytes.Equal(c.remotePublic, before) {
		t.Fatal("rejected reply changed the authenticated peer-key state")
	}
}

func TestReplyDiagnosticRoutingAndSessionBranches(t *testing.T) {
	cases := []struct {
		name, exception, category, vehicle string
		mutate                             func(*testing.T, *replyDiagnosticFixture)
		invalidRequest, invalidResponse    bool
	}{
		{name: "request_invalid_protobuf", exception: "routable_invalid_protobuf", category: "routable", vehicle: "malformed_response", invalidRequest: true},
		{name: "response_invalid_protobuf", exception: "routable_invalid_protobuf", category: "routable", vehicle: "malformed_response", invalidResponse: true},
		{name: "response_unknown_fields", exception: "routable_unknown_fields", category: "routable", vehicle: "malformed_response", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { replyDiagnosticUnknown(f.response) }},
		{name: "uuid_missing", exception: "routable_uuid_missing", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.RequestUuid = nil }},
		{name: "uuid_short", exception: "routable_uuid_length", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.RequestUuid = bytes.Repeat([]byte{0x42}, 15) }},
		{name: "uuid_long", exception: "routable_uuid_length", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.RequestUuid = bytes.Repeat([]byte{0x42}, 17) }},
		{name: "uuid_mismatch", exception: "routable_uuid_mismatch", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.RequestUuid = bytes.Repeat([]byte{0x43}, 16) }},
		{name: "source_missing", exception: "routable_source_missing", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.FromDestination = nil }},
		{name: "source_untyped", exception: "routable_source_type", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.FromDestination = &um.Destination{} }},
		{name: "source_routing_type", exception: "routable_source_type", category: "routable", vehicle: "none", mutate: func(t *testing.T, f *replyDiagnosticFixture) {
			f.response.FromDestination = replyDiagnosticRouting(t, bytes.Repeat([]byte{0x31}, 16))
		}},
		{name: "source_domain_mismatch", exception: "routable_domain_mismatch", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.FromDestination.SubDestination = &um.Destination_Domain{Domain: um.Domain_DOMAIN_VEHICLE_SECURITY}
		}},
		{name: "destination_missing", exception: "routable_destination_missing", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.ToDestination = nil }},
		{name: "destination_untyped", exception: "routable_destination_type", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.ToDestination = &um.Destination{} }},
		{name: "destination_domain_type", exception: "routable_destination_type", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.ToDestination = &um.Destination{SubDestination: &um.Destination_Domain{Domain: um.Domain_DOMAIN_INFOTAINMENT}}
		}},
		{name: "destination_short", exception: "routable_destination_length", category: "routable", vehicle: "none", mutate: func(t *testing.T, f *replyDiagnosticFixture) {
			f.response.ToDestination = replyDiagnosticRouting(t, bytes.Repeat([]byte{0x31}, 15))
		}},
		{name: "destination_long", exception: "routable_destination_length", category: "routable", vehicle: "none", mutate: func(t *testing.T, f *replyDiagnosticFixture) {
			f.response.ToDestination = replyDiagnosticRouting(t, bytes.Repeat([]byte{0x31}, 17))
		}},
		{name: "destination_mismatch", exception: "routable_destination_mismatch", category: "routable", vehicle: "none", mutate: func(t *testing.T, f *replyDiagnosticFixture) {
			f.response.ToDestination = replyDiagnosticRouting(t, bytes.Repeat([]byte{0x32}, 16))
		}},
		{name: "session_missing", exception: "session_info_missing", category: "authentication", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.Payload = nil }},
		{name: "session_invalid_protobuf", exception: "session_info_invalid_protobuf", category: "authentication", vehicle: "malformed_response", mutate: func(t *testing.T, f *replyDiagnosticFixture) { f.setInfoRaw(t, []byte{0xff}) }},
		{name: "session_unknown_fields_tampered", exception: "session_info_hmac_mismatch", category: "authentication", vehicle: "none", mutate: func(t *testing.T, f *replyDiagnosticFixture) { replyDiagnosticUnknown(f.info); f.response.Payload = &um.RoutableMessage_SessionInfo{SessionInfo: replyDiagnosticMarshal(t, f.info)} }},
		{name: "session_status_unknown", exception: "session_info_status_unknown", category: "authentication", vehicle: "none", mutate: func(t *testing.T, f *replyDiagnosticFixture) {
			f.info.Status = sig.Session_Info_Status(127)
			f.setInfo(t, f.info)
		}},
		{name: "session_not_whitelisted", exception: "vehicle_rejected", category: "vehicle", vehicle: "not_whitelisted", mutate: func(t *testing.T, f *replyDiagnosticFixture) {
			f.info.Status = sig.Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST
			f.setInfo(t, f.info)
		}},
		{name: "signature_missing", exception: "session_info_tag_missing", category: "authentication", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) { f.response.SubSigData = nil }},
		{name: "signature_wrong_type", exception: "session_info_tag_missing", category: "authentication", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.SubSigData = &um.RoutableMessage_SignatureData{SignatureData: &sig.SignatureData{SigType: &sig.SignatureData_HMAC_PersonalizedData{HMAC_PersonalizedData: &sig.HMAC_Personalized_Signature_Data{Tag: bytes.Repeat([]byte{0x75}, 32)}}}}
		}},
		{name: "tag_empty", exception: "session_info_tag_length", category: "authentication", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.GetSignatureData().GetSessionInfoTag().Tag = nil
		}},
		{name: "tag_short", exception: "session_info_tag_length", category: "authentication", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.GetSignatureData().GetSessionInfoTag().Tag = bytes.Repeat([]byte{0x75}, 31)
		}},
		{name: "tag_long", exception: "session_info_tag_length", category: "authentication", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.GetSignatureData().GetSessionInfoTag().Tag = bytes.Repeat([]byte{0x75}, 33)
		}},
		{name: "peer_key_missing", exception: "session_info_invalid_public_key", category: "authentication", vehicle: "none", mutate: func(t *testing.T, f *replyDiagnosticFixture) { f.info.PublicKey = nil; f.setInfo(t, f.info) }},
		{name: "peer_key_invalid_point", exception: "session_info_invalid_public_key", category: "authentication", vehicle: "none", mutate: func(t *testing.T, f *replyDiagnosticFixture) {
			f.info.PublicKey = make([]byte, 65)
			f.info.PublicKey[0] = 4
			f.setInfo(t, f.info)
		}},
		{name: "hmac_mismatch", exception: "session_info_hmac_mismatch", category: "authentication", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.GetSignatureData().GetSessionInfoTag().Tag[0] ^= 1
		}},
		{name: "outer_wait", exception: "routable_status_wait", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.SignedMessageStatus.OperationStatus = um.OperationStatus_E_OPERATIONSTATUS_WAIT
		}},
		{name: "outer_error", exception: "routable_status_error", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.SignedMessageStatus.OperationStatus = um.OperationStatus_E_OPERATIONSTATUS_ERROR
		}},
		{name: "outer_unknown", exception: "routable_status_unknown", category: "routable", vehicle: "none", mutate: func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.SignedMessageStatus.OperationStatus = um.OperationStatus_E(127)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newReplyDiagnosticFixture(t)
			if tc.mutate != nil {
				tc.mutate(t, f)
			}
			request, response := replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response)
			if tc.invalidRequest {
				request = []byte{0xff}
			}
			if tc.invalidResponse {
				response = []byte{0xff}
			}
			c := &HTTPConnector{target: target, key: f.local}
			assertReplyDiagnosticFailure(t, c, request, response, tc.exception, tc.category, tc.vehicle)
		})
	}
}

func TestReplyDiagnosticAllMessageFaults(t *testing.T) {
	cases := []struct {
		fault   um.MessageFault_E
		vehicle string
	}{
		{um.MessageFault_E_MESSAGEFAULT_ERROR_BUSY, "busy"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_TIMEOUT, "timeout"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_UNKNOWN_KEY_ID, "unknown_key"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INACTIVE_KEY, "inactive_key"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_KEY_HANDLE, "invalid_key_handle"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_SIGNATURE, "invalid_signature"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER, "invalid_counter"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INCORRECT_EPOCH, "incorrect_epoch"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_REPEATED_COUNTER, "repeated_counter"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_TIME_EXPIRED, "request_expired"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INSUFFICIENT_PRIVILEGES, "insufficient_privileges"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_DOMAINS, "invalid_domain"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INVALID_COMMAND, "invalid_command"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_DECODING, "decoding"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_INTERNAL, "internal"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_WRONG_PERSONALIZATION, "wrong_personalization"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_BAD_PARAMETER, "bad_parameter"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_KEYCHAIN_IS_FULL, "keychain_full"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_IV_INCORRECT_LENGTH, "invalid_iv"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_NOT_PROVISIONED_WITH_IDENTITY, "identity_missing"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_COULD_NOT_HASH_METADATA, "metadata_hash"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_TIME_TO_LIVE_TOO_LONG, "expiry_too_long"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_REMOTE_ACCESS_DISABLED, "remote_access_disabled"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_REMOTE_SERVICE_ACCESS_DISABLED, "remote_service_access_disabled"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_COMMAND_REQUIRES_ACCOUNT_CREDENTIALS, "account_credentials_required"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_REQUEST_MTU_EXCEEDED, "request_mtu"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_RESPONSE_MTU_EXCEEDED, "response_mtu"},
		{um.MessageFault_E_MESSAGEFAULT_ERROR_REQUIRES_RESPONSE_ENCRYPTION, "response_encryption_required"},
	}
	if len(cases) != 28 {
		t.Fatal("pinned non-NONE message-fault coverage incomplete")
	}
	cases = append(cases, struct {
		fault   um.MessageFault_E
		vehicle string
	}{um.MessageFault_E(32767), "unknown_fault"})
	for _, tc := range cases {
		t.Run(tc.vehicle, func(t *testing.T) {
			f := newReplyDiagnosticFixture(t)
			f.response.SignedMessageStatus.SignedMessageFault = tc.fault
			c := &HTTPConnector{target: target, key: f.local}
			assertReplyDiagnosticFailure(t, c, replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response), "vehicle_rejected", "vehicle", tc.vehicle)
		})
	}
}

func TestReplyDiagnosticSessionHMACFailureDoesNotRetainPeer(t *testing.T) {
	f := newReplyDiagnosticFixture(t)
	// Metadata fields have an encoded byte-length limit. A synthetic target
	// beyond that limit exercises the public SDK HMAC error without modifying
	// the SDK or inventing a private authentication.Session implementation.
	c := &HTTPConnector{target: strings.Repeat("x", 512), key: f.local}
	assertReplyDiagnosticFailure(t, c, replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response), "session_info_hmac_failed", "authentication", "none")
}

func TestReplyDiagnosticSessionHMACContextBinding(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *replyDiagnosticFixture, *HTTPConnector)
	}{
		{"request_uuid", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			f.request.Uuid = bytes.Repeat([]byte{0xa9}, 16)
			f.response.RequestUuid = append([]byte(nil), f.request.Uuid...)
		}},
		{"vehicle_personalization", func(_ *testing.T, _ *replyDiagnosticFixture, c *HTTPConnector) {
			c.target = "BBBBBBBBBBBBBBBBB"
		}},
		{"encoded_session_counter", func(t *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			message := f.info.ProtoReflect()
			field := message.Descriptor().Fields().ByName("counter")
			if field == nil || field.Kind() != protoreflect.Uint32Kind {
				t.Fatal("pinned session counter field missing")
			}
			message.Set(field, protoreflect.ValueOfUint32(1))
			// Keep the original tag: the complete encoded SessionInfo must be
			// authenticated, including its counter and clock metadata.
			f.response.Payload = &um.RoutableMessage_SessionInfo{SessionInfo: replyDiagnosticMarshal(t, f.info)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newReplyDiagnosticFixture(t)
			c := &HTTPConnector{target: target, key: f.local}
			tc.mutate(t, f, c)
			assertReplyDiagnosticFailure(t, c, replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response), "session_info_hmac_mismatch", "authentication", "none")
		})
	}
}

func replyDiagnosticCommandFixture(t *testing.T, encrypted bool) (*replyDiagnosticFixture, *HTTPConnector) {
	t.Helper()
	f := newReplyDiagnosticFixture(t)
	f.request.Payload = &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: []byte("synthetic-signed-command")}
	f.request.SubSigData = &um.RoutableMessage_SignatureData{SignatureData: &sig.SignatureData{
		SignerIdentity: &sig.KeyIdentity{IdentityType: &sig.KeyIdentity_PublicKey{PublicKey: f.local.PublicBytes()}},
		SigType:        &sig.SignatureData_HMAC_PersonalizedData{HMAC_PersonalizedData: &sig.HMAC_Personalized_Signature_Data{Tag: bytes.Repeat([]byte{0x76}, 32)}},
	}}
	result := &cs.Response{ActionStatus: &cs.ActionStatus{Result: cs.OperationStatus_E_OPERATIONSTATUS_OK}}
	plain := replyDiagnosticMarshal(t, result)
	f.response.Payload = &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: plain}
	f.response.SubSigData = nil
	c := &HTTPConnector{target: target, key: f.local, remotePublic: append([]byte(nil), f.peer.PublicBytes()...)}
	if encrypted {
		session, err := f.peer.Exchange(f.local.PublicBytes())
		if err != nil {
			t.Fatal("synthetic command exchange failed")
		}
		gcm := &sig.AES_GCM_Response_Signature_Data{Counter: 1}
		f.response.SubSigData = &um.RoutableMessage_SignatureData{SignatureData: &sig.SignatureData{SigType: &sig.SignatureData_AES_GCM_ResponseData{AES_GCM_ResponseData: gcm}}}
		associated, err := responseAssociatedData(target, f.request, f.response)
		if err != nil {
			t.Fatal("synthetic command metadata construction failed")
		}
		var ciphertext []byte
		gcm.Nonce, ciphertext, gcm.Tag, err = session.Encrypt(plain, associated)
		if err != nil {
			t.Fatal("synthetic command encryption failed")
		}
		f.response.Payload = &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: ciphertext}
	}
	return f, c
}

func replyDiagnosticSetCommandPayload(t *testing.T, f *replyDiagnosticFixture, result *cs.Response) {
	t.Helper()
	f.response.Payload = &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: replyDiagnosticMarshal(t, result)}
}

func replyDiagnosticCache(t *testing.T, domain um.Domain, raw []byte) *cache.SessionCache {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"MaxEntries": 1, "vehicles": map[string]any{target: []map[string]any{{"CreatedAt": time.Now(), "Domain": int(domain), "data": raw}}}})
	if err != nil {
		t.Fatal("synthetic cache construction failed")
	}
	value, err := cache.Import(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("synthetic cache import failed")
	}
	return value
}

func TestReplyDiagnosticCommandPlaintextStatusBranches(t *testing.T) {
	cases := []struct {
		name, exception, vehicle string
		mutate                   func(*testing.T, *replyDiagnosticFixture)
	}{
		{"payload_missing", "command_payload_missing", "none", func(_ *testing.T, f *replyDiagnosticFixture) { f.response.Payload = nil }},
		{"payload_invalid", "command_payload_invalid", "malformed_response", func(_ *testing.T, f *replyDiagnosticFixture) {
			f.response.Payload = &um.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: []byte{0xff}}
		}},
		{"status_missing", "command_status_missing", "none", func(t *testing.T, f *replyDiagnosticFixture) {
			replyDiagnosticSetCommandPayload(t, f, &cs.Response{ResponseMsg: &cs.Response_VehicleData{VehicleData: &cs.VehicleData{}}})
		}},
		{"status_rejected", "command_status_rejected", "rejected", func(t *testing.T, f *replyDiagnosticFixture) {
			replyDiagnosticSetCommandPayload(t, f, &cs.Response{ActionStatus: &cs.ActionStatus{Result: cs.OperationStatus_E(127)}})
		}},
		{"status_reason", "command_status_reason", "rejected", func(t *testing.T, f *replyDiagnosticFixture) {
			status := &cs.ActionStatus{Result: cs.OperationStatus_E_OPERATIONSTATUS_OK}
			message := status.ProtoReflect()
			var field protoreflect.FieldDescriptor
			fields := message.Descriptor().Fields()
			for n := 0; n < fields.Len(); n++ {
				if fields.Get(n).JSONName() == "resultReason" {
					field = fields.Get(n)
					break
				}
			}
			if field == nil || field.Kind() != protoreflect.MessageKind {
				t.Fatal("pinned command status reason missing")
			}
			replyDiagnosticUnknown(message.Mutable(field).Message().Interface())
			replyDiagnosticSetCommandPayload(t, f, &cs.Response{ActionStatus: status})
		}},
		{"status_unknown_fields", "command_status_unknown_fields", "malformed_response", func(t *testing.T, f *replyDiagnosticFixture) {
			status := &cs.ActionStatus{Result: cs.OperationStatus_E_OPERATIONSTATUS_OK}
			replyDiagnosticUnknown(status)
			replyDiagnosticSetCommandPayload(t, f, &cs.Response{ActionStatus: status})
		}},
		{"security_ack_missing", "command_ack_missing", "none", func(_ *testing.T, f *replyDiagnosticFixture) {
			f.request.ToDestination.SubDestination = &um.Destination_Domain{Domain: um.Domain_DOMAIN_VEHICLE_SECURITY}
			f.response.FromDestination.SubDestination = &um.Destination_Domain{Domain: um.Domain_DOMAIN_VEHICLE_SECURITY}
			f.response.SignedMessageStatus = nil
			f.response.Payload = nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := replyDiagnosticCommandFixture(t, false)
			tc.mutate(t, f)
			assertReplyDiagnosticFailure(t, c, replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response), tc.exception, "routable", tc.vehicle)
		})
	}
}

func TestReplyDiagnosticCommandEncryptedAuthenticationBranches(t *testing.T) {
	cases := []struct {
		name, exception string
		mutate          func(*testing.T, *replyDiagnosticFixture, *HTTPConnector)
	}{
		{"cache_missing", "command_cache_missing", func(_ *testing.T, _ *replyDiagnosticFixture, c *HTTPConnector) {
			c.remotePublic = nil
			c.sessions = nil
		}},
		{"cache_domain_missing", "command_cache_missing", func(t *testing.T, _ *replyDiagnosticFixture, c *HTTPConnector) {
			c.remotePublic = nil
			c.sessions = cached(t, um.Domain_DOMAIN_VEHICLE_SECURITY)
		}},
		{"cache_invalid_protobuf", "command_cache_invalid", func(t *testing.T, _ *replyDiagnosticFixture, c *HTTPConnector) {
			c.remotePublic = nil
			c.sessions = replyDiagnosticCache(t, um.Domain_DOMAIN_INFOTAINMENT, []byte{0xff})
		}},
		{"cache_status_invalid", "command_cache_invalid", func(t *testing.T, f *replyDiagnosticFixture, c *HTTPConnector) {
			c.remotePublic = nil
			f.info.Status = sig.Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST
			c.sessions = replyDiagnosticCache(t, um.Domain_DOMAIN_INFOTAINMENT, replyDiagnosticMarshal(t, f.info))
		}},
		{"exchange_failed", "command_exchange_failed", func(_ *testing.T, _ *replyDiagnosticFixture, c *HTTPConnector) {
			c.remotePublic = make([]byte, 65)
			c.remotePublic[0] = 4
		}},
		{"metadata_missing_signature", "command_metadata_invalid", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) { f.request.SubSigData = nil }},
		{"metadata_short_hmac", "command_metadata_invalid", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			f.request.GetSignatureData().GetHMAC_PersonalizedData().Tag = bytes.Repeat([]byte{0x76}, 31)
		}},
		{"nonce_short", "command_nonce_length", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			f.response.GetSignatureData().GetAES_GCM_ResponseData().Nonce = bytes.Repeat([]byte{0x87}, 11)
		}},
		{"nonce_long", "command_nonce_length", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			f.response.GetSignatureData().GetAES_GCM_ResponseData().Nonce = bytes.Repeat([]byte{0x87}, 13)
		}},
		{"tag_short", "command_tag_length", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			f.response.GetSignatureData().GetAES_GCM_ResponseData().Tag = bytes.Repeat([]byte{0x98}, 15)
		}},
		{"tag_long", "command_tag_length", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			f.response.GetSignatureData().GetAES_GCM_ResponseData().Tag = bytes.Repeat([]byte{0x98}, 17)
		}},
		{"decryption_failed", "command_decryption_failed", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			f.response.GetSignatureData().GetAES_GCM_ResponseData().Tag[0] ^= 1
		}},
		{"request_binding_changed", "command_decryption_failed", func(_ *testing.T, f *replyDiagnosticFixture, _ *HTTPConnector) {
			f.request.GetSignatureData().GetHMAC_PersonalizedData().Tag[0] ^= 1
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := replyDiagnosticCommandFixture(t, true)
			tc.mutate(t, f, c)
			assertReplyDiagnosticFailure(t, c, replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response), tc.exception, "authentication", "none")
		})
	}
}

func TestReplyDiagnosticValidCommandReplies(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plaintext", true: "aes_gcm"}[encrypted], func(t *testing.T) {
			f, c := replyDiagnosticCommandFixture(t, encrypted)
			before := append([]byte(nil), c.remotePublic...)
			if c.checkReply(replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response)) != nil {
				t.Fatal("valid synthetic command reply refused")
			}
			if !bytes.Equal(c.remotePublic, before) {
				t.Fatal("command reply changed peer key")
			}
		})
	}
}

// Extension bytes are covered by the original wire HMAC, never discarded or
// remarshal-normalized before verification. A stale tag must reject tampering.
func TestSessionInfoAuthenticatedExtensions(t *testing.T) {
 f := newReplyDiagnosticFixture(t)
 replyDiagnosticUnknown(f.info)
 f.setInfo(t, f.info)
 c := &HTTPConnector{target: target, key: f.local}
 if err := c.checkReply(replyDiagnosticMarshal(t, f.request), replyDiagnosticMarshal(t, f.response)); err != nil {
  t.Fatal("authenticated SessionInfo extension rejected")
 }
 f.info.ProtoReflect().SetUnknown(append(f.info.ProtoReflect().GetUnknown(), protowire.AppendVarint(protowire.AppendTag(nil, 19001, protowire.VarintType), 1)...))
 f.response.Payload = &um.RoutableMessage_SessionInfo{SessionInfo: replyDiagnosticMarshal(t, f.info)}
 c = &HTTPConnector{target: target, key: f.local}
 assertReplyDiagnosticFailure(t,c,replyDiagnosticMarshal(t,f.request),replyDiagnosticMarshal(t,f.response),"session_info_hmac_mismatch","authentication","none")
}
