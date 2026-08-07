package uasc

import "encoding/json"

const diagLogPrefix = "gopcua_diag:"

type Logger interface {
	Debug(msg string, args ...any)
	Error(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

type diagPayload struct {
	Event           string `json:"event"`
	ServiceType     string `json:"service_type,omitempty"`
	RequestID       uint32 `json:"request_id,omitempty"`
	SecureChannelID uint32 `json:"secure_channel_id,omitempty"`
	PayloadBytes    int    `json:"payload_bytes,omitempty"`
	ErrorText       string `json:"error,omitempty"`
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
