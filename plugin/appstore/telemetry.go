// SPDX-License-Identifier: AGPL-3.0-or-later

package appstore

// TelemetryEvent captures one app-usage event that the supervisor emits
// after every successful (or failed) IPC call through callFrom. The
// daemon's telemetry client converts these to signed HTTP POSTs.
//
// Fields match what the telemetry endpoint expects for "app_usage" kind
// events. CallerID is empty for trusted daemon/pilotctl calls and
// non-empty for cross-app calls.
type TelemetryEvent struct {
	AppID    string `json:"app_id"`
	Method   string `json:"method"`
	CallerID string `json:"caller_id,omitempty"`
	OK       bool   `json:"ok"`
	DurMs    int64  `json:"dur_ms"`
	ErrMsg   string `json:"err_msg,omitempty"`
}

// TelemetryEmitter is the interface the supervisor calls to emit a usage
// event. The daemon wires a real implementation; the no-op default is set
// in newSupervisor so the supervisor never has to nil-check.
type TelemetryEmitter interface {
	Emit(event TelemetryEvent)
}

// noopEmitter discards every event. Used as the default when Deps does
// not provide a Telemetry field, and also when consent is off.
type noopEmitter struct{}

func (noopEmitter) Emit(TelemetryEvent) {}
