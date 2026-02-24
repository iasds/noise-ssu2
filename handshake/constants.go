package handshake

// HandshakePhase represents the phase of the handshake process
type HandshakePhase int

const (
	// PhaseInitial represents the initial phase of the handshake
	PhaseInitial HandshakePhase = iota
	// PhaseExchange represents the message exchange phase
	PhaseExchange
	// PhaseFinal represents the final phase of the handshake
	PhaseFinal
	// PhaseData represents the post-handshake data transport phase.
	// This distinguishes ongoing data exchange from the final handshake message,
	// enabling protocol-specific modifiers to handle them differently (e.g., SSU2).
	// Note: PhaseData > PhaseFinal, so existing "phase >= PhaseFinal" checks
	// in NTCP2 modifiers will correctly match both PhaseFinal and PhaseData.
	PhaseData
)

// String returns the string representation of the handshake phase
func (p HandshakePhase) String() string {
	switch p {
	case PhaseInitial:
		return "initial"
	case PhaseExchange:
		return "exchange"
	case PhaseFinal:
		return "final"
	case PhaseData:
		return "data"
	default:
		return "unknown"
	}
}
