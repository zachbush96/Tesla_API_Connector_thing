package restricted

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/teslamotors/vehicle-command/pkg/protocol"
	cs "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	sig "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/signatures"
	um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/proto"
)

// responseAssociatedData mirrors only the pinned SDK's documented response
// metadata serialization (internal/authentication/peer.go:responseMetadata).
// SDK Exchange/Decrypt performs cryptography; the original encrypted response
// also goes to the SDK for its independent authentication/replay-window checks.
func responseAssociatedData(target string, request, response *um.RoutableMessage) ([]byte, error) {
	gcm := response.GetSignatureData().GetAES_GCM_ResponseData()
	hmac := request.GetSignatureData().GetHMAC_PersonalizedData()
	if gcm == nil || hmac == nil || len(hmac.Tag) != 32 {
		return nil, refused
	}
	id := append([]byte{byte(sig.SignatureType_SIGNATURE_TYPE_HMAC_PERSONALIZED)}, hmac.Tag...)
	if request.GetToDestination().GetDomain() == um.Domain_DOMAIN_VEHICLE_SECURITY {
		id = id[:17]
	}
	hash := sha256.New()
	add := func(tag sig.Tag, value []byte) { hash.Write([]byte{byte(tag), byte(len(value))}); hash.Write(value) }
	add32 := func(tag sig.Tag, value uint32) {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], value)
		add(tag, raw[:])
	}
	add(sig.Tag_TAG_SIGNATURE_TYPE, []byte{byte(sig.SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE)})
	add(sig.Tag_TAG_DOMAIN, []byte{byte(response.GetFromDestination().GetDomain())})
	add(sig.Tag_TAG_PERSONALIZATION, []byte(target))
	add32(sig.Tag_TAG_COUNTER, gcm.Counter)
	add32(sig.Tag_TAG_FLAGS, response.Flags)
	add(sig.Tag_TAG_REQUEST_HASH, id)
	add32(sig.Tag_TAG_FAULT, uint32(response.GetSignedMessageStatus().GetSignedMessageFault()))
	hash.Write([]byte{byte(sig.Tag_TAG_END)})
	return hash.Sum(nil), nil
}

// replyFailure contains only fixed branch classifications, never decoded data
// or an underlying error. A routable status is an unauthenticated hint until
// the SDK independently establishes the session.
type replyFailure struct{ exception, category, vehicle string }

func (*replyFailure) Error() string { return "restricted response refused" }
func rejectReply(exception, category, vehicle string) error {
	return &replyFailure{exception, category, vehicle}
}

func outerReplyStatus(status *um.MessageStatus) error {
	if status == nil {
		return nil
	}
	switch status.OperationStatus {
	case um.OperationStatus_E_OPERATIONSTATUS_OK:
		return nil
	case um.OperationStatus_E_OPERATIONSTATUS_WAIT:
		return rejectReply("routable_status_wait", "routable", "none")
	case um.OperationStatus_E_OPERATIONSTATUS_ERROR:
		return rejectReply("routable_status_error", "routable", "none")
	default:
		return rejectReply("routable_status_unknown", "routable", "none")
	}
}

func (c *HTTPConnector) checkReply(requestRaw, responseRaw []byte) error {
	var request, response um.RoutableMessage
	if proto.Unmarshal(requestRaw, &request) != nil || proto.Unmarshal(responseRaw, &response) != nil {
		return rejectReply("routable_invalid_protobuf", "routable", "malformed_response")
	}
	if len(response.ProtoReflect().GetUnknown()) != 0 {
		return rejectReply("routable_unknown_fields", "routable", "malformed_response")
	}
	if len(response.RequestUuid) == 0 {
		return rejectReply("routable_uuid_missing", "routable", "none")
	}
	if len(response.RequestUuid) != 16 {
		return rejectReply("routable_uuid_length", "routable", "none")
	}
	if !bytes.Equal(request.Uuid, response.RequestUuid) {
		return rejectReply("routable_uuid_mismatch", "routable", "none")
	}
	if response.FromDestination == nil {
		return rejectReply("routable_source_missing", "routable", "none")
	}
	if _, ok := response.FromDestination.SubDestination.(*um.Destination_Domain); !ok {
		return rejectReply("routable_source_type", "routable", "none")
	}
	if request.GetToDestination().GetDomain() != response.GetFromDestination().GetDomain() {
		return rejectReply("routable_domain_mismatch", "routable", "none")
	}
	// The pinned dispatcher indexes a handler by this exact 16-byte routing
	// address. Reject the same silently dropped responses before its inbox;
	// this avoids losing the reason to a blocked SDK retry.
	if response.ToDestination == nil {
		return rejectReply("routable_destination_missing", "routable", "none")
	}
	if _, ok := response.ToDestination.SubDestination.(*um.Destination_RoutingAddress); !ok {
		return rejectReply("routable_destination_type", "routable", "none")
	}
	if len(response.ToDestination.GetRoutingAddress()) != 16 {
		return rejectReply("routable_destination_length", "routable", "none")
	}
	if !bytes.Equal(request.GetFromDestination().GetRoutingAddress(), response.ToDestination.GetRoutingAddress()) {
		return rejectReply("routable_destination_mismatch", "routable", "none")
	}
	if fault := safeMessageFault(response.GetSignedMessageStatus().GetSignedMessageFault()); fault != "none" {
		return rejectReply("vehicle_rejected", "vehicle", fault)
	}
	if request.GetSessionInfoRequest() != nil {
		var info sig.SessionInfo
		if response.GetSessionInfo() == nil {
			return rejectReply("session_info_missing", "authentication", "none")
		}
		if proto.Unmarshal(response.GetSessionInfo(), &info) != nil {
			return rejectReply("session_info_invalid_protobuf", "authentication", "malformed_response")
		}
		if info.Status == sig.Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST {
			return rejectReply("vehicle_rejected", "vehicle", "not_whitelisted")
		}
		if info.Status != sig.Session_Info_Status_SESSION_INFO_STATUS_OK {
			return rejectReply("session_info_status_unknown", "authentication", "none")
		}
		// SessionInfo is extensible protobuf. Mirror the pinned SDK: accept
		// fields it does not interpret only after authenticating the complete
		// original encoded message below, including those extension bytes.
		tag := response.GetSignatureData().GetSessionInfoTag()
		if tag == nil {
			return rejectReply("session_info_tag_missing", "authentication", "none")
		}
		if len(tag.Tag) != 32 {
			return rejectReply("session_info_tag_length", "authentication", "none")
		}
		if err := outerReplyStatus(response.SignedMessageStatus); err != nil {
			return err
		}
		// Mirror NewAuthenticatedSigner exactly using the public SDK crypto
		// interface. The unmodified SDK receives the original reply and still
		// performs its own authentication and replay-window checks.
		session, err := c.key.Exchange(info.PublicKey)
		if errors.Is(err, protocol.ErrInvalidPublicKey) {
			return rejectReply("session_info_invalid_public_key", "authentication", "none")
		}
		if err != nil || session == nil {
			return rejectReply("session_info_exchange_failed", "authentication", "none")
		}
		expected, err := session.SessionInfoHMAC([]byte(c.target), request.Uuid, response.GetSessionInfo())
		if err != nil {
			return rejectReply("session_info_hmac_failed", "authentication", "none")
		}
		if !hmac.Equal(expected, tag.Tag) {
			return rejectReply("session_info_hmac_mismatch", "authentication", "none")
		}
		c.remotePublic = append([]byte{}, info.PublicKey...)
		return nil
	}
	if err := outerReplyStatus(response.SignedMessageStatus); err != nil {
		return err
	}
	payload := response.GetProtobufMessageAsBytes()
	if response.GetSignatureData().GetAES_GCM_ResponseData() != nil {
		pub := c.remotePublic
		if len(pub) == 0 {
			if c.sessions == nil {
				return rejectReply("command_cache_missing", "authentication", "none")
			}
			entries, ok := c.sessions.GetEntry(c.target)
			if !ok {
				return rejectReply("command_cache_missing", "authentication", "none")
			}
			for _, entry := range entries {
				if entry.Domain == int(request.GetToDestination().GetDomain()) {
					var info sig.SessionInfo
					if proto.Unmarshal(entry.SessionInfo, &info) != nil || info.Status != sig.Session_Info_Status_SESSION_INFO_STATUS_OK {
						return rejectReply("command_cache_invalid", "authentication", "none")
					}
					pub = info.PublicKey
				}
			}
			if len(pub) == 0 {
				return rejectReply("command_cache_missing", "authentication", "none")
			}
		}
		session, err := c.key.Exchange(pub)
		if err != nil || session == nil {
			return rejectReply("command_exchange_failed", "authentication", "none")
		}
		associated, err := responseAssociatedData(c.target, &request, &response)
		if err != nil {
			return rejectReply("command_metadata_invalid", "authentication", "none")
		}
		gcm := response.GetSignatureData().GetAES_GCM_ResponseData()
		if len(gcm.Nonce) != 12 {
			return rejectReply("command_nonce_length", "authentication", "none")
		}
		if len(gcm.Tag) != 16 {
			return rejectReply("command_tag_length", "authentication", "none")
		}
		payload, err = session.Decrypt(gcm.Nonce, payload, associated, gcm.Tag)
		if err != nil {
			return rejectReply("command_decryption_failed", "authentication", "none")
		}
	}
	if request.GetToDestination().GetDomain() == um.Domain_DOMAIN_INFOTAINMENT {
		var result cs.Response
		if len(payload) == 0 {
			return rejectReply("command_payload_missing", "routable", "none")
		}
		if proto.Unmarshal(payload, &result) != nil {
			return rejectReply("command_payload_invalid", "routable", "malformed_response")
		}
		if result.ActionStatus == nil {
			return rejectReply("command_status_missing", "routable", "none")
		}
		if result.ActionStatus.Result != cs.OperationStatus_E_OPERATIONSTATUS_OK {
			return rejectReply("command_status_rejected", "routable", "rejected")
		}
		if result.ActionStatus.ResultReason != nil {
			return rejectReply("command_status_reason", "routable", "rejected")
		}
		if len(result.ActionStatus.ProtoReflect().GetUnknown()) != 0 {
			return rejectReply("command_status_unknown_fields", "routable", "malformed_response")
		}
	} else if response.SignedMessageStatus == nil && response.GetSignatureData().GetAES_GCM_ResponseData() == nil {
		// VCSEC legitimately terminates some commands without an inner command
		// status. Require an authenticated response or explicit outer positive
		// status rather than accepting a wholly absent acknowledgement.
		return rejectReply("command_ack_missing", "routable", "none")
	}
	return nil
}
