package server

import (
	"encoding/json"

	"github.com/gopcua/opcua/uasc"
)

const diagLogPrefix = "gopcua_diag:"

type diagPayload struct {
	Event                string `json:"event"`
	ServiceType          string `json:"service_type,omitempty"`
	RequestID            uint32 `json:"request_id,omitempty"`
	SecureChannelID      uint32 `json:"secure_channel_id,omitempty"`
	RemoteAddr           string `json:"remote_addr,omitempty"`
	EndpointURL          string `json:"endpoint_url,omitempty"`
	MatchedEndpointCount *int   `json:"matched_endpoint_count,omitempty"`
	DurationMs           *int64 `json:"duration_ms,omitempty"`
	ErrorText            string `json:"error,omitempty"`
	CloseCause           string `json:"close_cause,omitempty"`
	ChannelCount         *int   `json:"channel_count,omitempty"`
}

func emitDiagInfo(logger Logger, payload diagPayload) {
	emitDiag(logger, "info", payload)
}

func emitDiagWarn(logger Logger, payload diagPayload) {
	emitDiag(logger, "warn", payload)
}

func emitDiag(logger Logger, level string, payload diagPayload) {
	if logger == nil || payload.Event == "" {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := diagLogPrefix + " " + string(body)
	switch level {
	case "warn":
		logger.Warn(msg)
	default:
		logger.Info(msg)
	}
}

func secureChannelID(sc *uasc.SecureChannel) uint32 {
	if sc == nil {
		return 0
	}
	return sc.ID()
}

func remoteAddr(sc *uasc.SecureChannel) string {
	if sc == nil || sc.RemoteAddr() == nil {
		return ""
	}
	return sc.RemoteAddr().String()
}
