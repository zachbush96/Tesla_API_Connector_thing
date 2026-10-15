package restricted

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// decodeFleetEnvelope preserves the prior strict acceptance policy and the
// pinned SDK's []byte/base64 response format. Free-form Fleet fields are parsed
// only to recognize their presence; none becomes an error string or checkpoint.
func decodeFleetEnvelope(raw []byte) ([]byte, error) {
	if len(raw) > 16384 {
		return nil, rejectReply("fleet_envelope_too_large", "fleet", "malformed_response")
	}
	if !json.Valid(raw) {
		return nil, rejectReply("fleet_envelope_invalid_json", "fleet", "malformed_response")
	}
	var fields map[string]json.RawMessage
	if strictJSON(raw, &fields) != nil || fields == nil {
		return nil, rejectReply("fleet_envelope_invalid_shape", "fleet", "malformed_response")
	}
	for key := range fields {
		if key != "response" && key != "error" && key != "error_description" {
			return nil, rejectReply("fleet_envelope_invalid_shape", "fleet", "malformed_response")
		}
	}
	var payload []byte
	if value, ok := fields["response"]; ok {
		if err := json.Unmarshal(value, &payload); err != nil {
			var corrupt base64.CorruptInputError
			if errors.As(err, &corrupt) {
				return nil, rejectReply("fleet_envelope_invalid_base64", "fleet", "malformed_response")
			}
			return nil, rejectReply("fleet_envelope_invalid_shape", "fleet", "malformed_response")
		}
	}
	var fleetError string
	for _, key := range []string{"error", "error_description"} {
		var value string
		if field, ok := fields[key]; ok && json.Unmarshal(field, &value) != nil {
			return nil, rejectReply("fleet_envelope_invalid_shape", "fleet", "malformed_response")
		}
		if key == "error" {
			fleetError = value
		}
	}
	if fleetError != "" {
		return nil, rejectReply("fleet_envelope_error", "fleet", "unclassified")
	}
	if len(payload) == 0 {
		return nil, rejectReply("fleet_response_missing", "fleet", "malformed_response")
	}
	return payload, nil
}

func (d *diagnosticRecorder) replyFailure(err error) {
	var failure *replyFailure
	if errors.As(err, &failure) {
		d.noteFailure(failure.exception, failure.category, failure.vehicle, "response_received")
		return
	}
	d.noteFailure("sdk_error", "sdk", "none", "response_received")
}
