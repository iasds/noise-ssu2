package handshake

// HandshakePhase represents the phase of the handshake process.
// Phases map to Noise handshake messages as follows:
//   - PhaseInitial  (0): Noise handshake message 1 (initiator → responder)
//   - PhaseExchange (1): Noise handshake message 2 (responder → initiator)
//   - PhaseFinal    (2): Noise handshake message 3 (initiator → responder, if pattern requires it)
//   - PhaseData     (3): Post-handshake data transport (after handshake completion)
//
// Ordering invariant: The numeric values of these constants are part of the
// stability contract. Downstream packages (e.g., ntcp2) rely on the ordering
// PhaseInitial < PhaseExchange < PhaseFinal < PhaseData. In particular,
// guards of the form "phase >= PhaseFinal" are used to match both PhaseFinal
// and PhaseData. New phase constants MUST NOT be inserted between PhaseFinal
// and PhaseData; they must be appended after PhaseData or inserted before
// PhaseInitial.
type HandshakePhase int

const (
	// PhaseInitial represents the initial phase of the handshake (message 1).
	PhaseInitial HandshakePhase = iota
	// PhaseExchange represents the message exchange phase (message 2).
	PhaseExchange
	// PhaseFinal represents the final phase of the handshake (message 3).
	PhaseFinal
	// PhaseData represents the post-handshake data transport phase.
	// This distinguishes ongoing data exchange from the final handshake message,
	// enabling protocol-specific modifiers to handle them differently (e.g., SSU2).
	//
	// Stability: PhaseData MUST remain strictly greater than PhaseFinal.
	// The ntcp2 package uses "phase >= PhaseFinal" guards that depend on this
	// ordering. Inserting a new constant between PhaseFinal and PhaseData will
	// silently break those modifiers.
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
