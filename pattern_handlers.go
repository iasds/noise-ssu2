package noise

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// patternHandlerFunc is the signature for a Noise handshake pattern handler.
type patternHandlerFunc func(nc *NoiseConn, ctx context.Context) error

// initiatorHandlers maps pattern names to their initiator handshake implementations.
var initiatorHandlers = map[string]patternHandlerFunc{
	"N":  (*NoiseConn).performNInitiator,
	"K":  (*NoiseConn).performKInitiator,
	"X":  (*NoiseConn).performXInitiator,
	"NN": (*NoiseConn).performNNInitiator,
	"NK": (*NoiseConn).performNKInitiator,
	"NX": (*NoiseConn).performNXInitiator,
	"XN": (*NoiseConn).performXNInitiator,
	"XK": (*NoiseConn).performXKInitiator,
	"XX": (*NoiseConn).performXXInitiator,
	"KN": (*NoiseConn).performKNInitiator,
	"KK": (*NoiseConn).performKKInitiator,
	"KX": (*NoiseConn).performKXInitiator,
	"IN": (*NoiseConn).performINInitiator,
	"IK": (*NoiseConn).performIKInitiator,
	"IX": (*NoiseConn).performIXInitiator,
}

// responderHandlers maps pattern names to their responder handshake implementations.
var responderHandlers = map[string]patternHandlerFunc{
	"N":  (*NoiseConn).performNResponder,
	"K":  (*NoiseConn).performKResponder,
	"X":  (*NoiseConn).performXResponder,
	"NN": (*NoiseConn).performNNResponder,
	"NK": (*NoiseConn).performNKResponder,
	"NX": (*NoiseConn).performNXResponder,
	"XN": (*NoiseConn).performXNResponder,
	"XK": (*NoiseConn).performXKResponder,
	"XX": (*NoiseConn).performXXResponder,
	"KN": (*NoiseConn).performKNResponder,
	"KK": (*NoiseConn).performKKResponder,
	"KX": (*NoiseConn).performKXResponder,
	"IN": (*NoiseConn).performINResponder,
	"IK": (*NoiseConn).performIKResponder,
	"IX": (*NoiseConn).performIXResponder,
}

// normalizePattern extracts the short pattern name from a full Noise protocol
// name (e.g., "Noise_XK_25519_AESGCM_SHA256" → "XK") or returns short names unchanged.
func normalizePattern(pattern string) string {
	if hp, err := parseHandshakePattern(pattern); err == nil {
		return hp.Name
	}
	return pattern
}

// performInitiatorHandshake handles the initiator side of the handshake.
func (nc *NoiseConn) performInitiatorHandshake(ctx context.Context) error {
	pattern := nc.config.Pattern
	nc.logger.WithFields(i2plogger.Fields{
		"pkg":         "noise",
		"func":        "NoiseConn.performInitiatorHandshake",
		"pattern":     pattern,
		"role":        "initiator",
		"local_addr":  nc.LocalAddr().String(),
		"remote_addr": nc.RemoteAddr().String(),
	}).Debug("performing handshake as initiator")

	normalized := normalizePattern(pattern)
	if handler, ok := initiatorHandlers[normalized]; ok {
		return handler(nc, ctx)
	}
	return oops.
		Code("UNSUPPORTED_PATTERN").
		In("noise").
		Errorf("unsupported handshake pattern: %s", pattern)
}

// performResponderHandshake handles the responder side of the handshake.
func (nc *NoiseConn) performResponderHandshake(ctx context.Context) error {
	pattern := nc.config.Pattern
	nc.logger.WithFields(i2plogger.Fields{
		"pkg":         "noise",
		"func":        "NoiseConn.performResponderHandshake",
		"pattern":     pattern,
		"role":        "responder",
		"local_addr":  nc.LocalAddr().String(),
		"remote_addr": nc.RemoteAddr().String(),
	}).Debug("performing handshake as responder")

	normalized := normalizePattern(pattern)
	if handler, ok := responderHandlers[normalized]; ok {
		return handler(nc, ctx)
	}
	return oops.
		Code("UNSUPPORTED_PATTERN").
		In("noise").
		Errorf("unsupported handshake pattern: %s", pattern)
}

// ============================================================================
// ONE-WAY PATTERNS (1 message)
// ============================================================================

// performNInitiator handles N pattern as initiator: → e, es
func (nc *NoiseConn) performNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNInitiator"}).Debug("starting N pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "N")
}

// performKInitiator handles K pattern as initiator: → e, es, ss
func (nc *NoiseConn) performKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKInitiator"}).Debug("starting K pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "K")
}

// performXInitiator handles X pattern as initiator: → e, es, s, ss
func (nc *NoiseConn) performXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXInitiator"}).Debug("starting X pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "X")
}

// performNResponder handles N pattern as responder: → e, es
func (nc *NoiseConn) performNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNResponder"}).Debug("starting N pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "N")
}

// performKResponder handles K pattern as responder: → e, es, ss
func (nc *NoiseConn) performKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKResponder"}).Debug("starting K pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "K")
}

// performXResponder handles X pattern as responder: → e, es, s, ss
func (nc *NoiseConn) performXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXResponder"}).Debug("starting X pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "X")
}

// ============================================================================
// TWO-MESSAGE INTERACTIVE PATTERNS
// ============================================================================

// performNNInitiator handles NN pattern as initiator
func (nc *NoiseConn) performNNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNNInitiator"}).Debug("starting NN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NN")
}

// performNNResponder handles NN pattern as responder
func (nc *NoiseConn) performNNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNNResponder"}).Debug("starting NN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NN")
}

// performNKInitiator handles NK pattern as initiator: → e, es, ← e, ee
func (nc *NoiseConn) performNKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNKInitiator"}).Debug("starting NK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NK")
}

// performNKResponder handles NK pattern as responder: → e, es, ← e, ee
func (nc *NoiseConn) performNKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNKResponder"}).Debug("starting NK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NK")
}

// performNXInitiator handles NX pattern as initiator: → e, ← e, ee, s, es
func (nc *NoiseConn) performNXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNXInitiator"}).Debug("starting NX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NX")
}

// performNXResponder handles NX pattern as responder: → e, ← e, ee, s, es
func (nc *NoiseConn) performNXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNXResponder"}).Debug("starting NX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NX")
}

// performKNInitiator handles KN pattern as initiator: → e, ← e, ee, se, es
func (nc *NoiseConn) performKNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKNInitiator"}).Debug("starting KN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first KN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second KN")
}

// performKNResponder handles KN pattern as responder: → e, ← e, ee, se, es
func (nc *NoiseConn) performKNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKNResponder"}).Debug("starting KN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first KN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second KN")
}

// performKKInitiator handles KK pattern as initiator: → e, es, ss, ← e, ee, se
func (nc *NoiseConn) performKKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKKInitiator"}).Debug("starting KK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first KK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second KK")
}

// performKKResponder handles KK pattern as responder: → e, es, ss, ← e, ee, se
func (nc *NoiseConn) performKKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKKResponder"}).Debug("starting KK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first KK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second KK")
}

// performINInitiator handles IN pattern as initiator: → e, s, ← e, ee, se, es
func (nc *NoiseConn) performINInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performINInitiator"}).Debug("starting IN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IN")
}

// performINResponder handles IN pattern as responder: → e, s, ← e, ee, se, es
func (nc *NoiseConn) performINResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performINResponder"}).Debug("starting IN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first IN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second IN")
}

// performIKInitiator handles IK pattern as initiator: → e, es, s, ss, ← e, ee, se
func (nc *NoiseConn) performIKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIKInitiator"}).Debug("starting IK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IK")
}

// performIKResponder handles IK pattern as responder: → e, es, s, ss, ← e, ee, se
func (nc *NoiseConn) performIKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIKResponder"}).Debug("starting IK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first IK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second IK")
}

// performIXInitiator handles IX pattern as initiator: → e, s, ← e, ee, se, s, es
func (nc *NoiseConn) performIXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIXInitiator"}).Debug("starting IX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IX")
}

// performIXResponder handles IX pattern as responder: → e, s, ← e, ee, se, s, es
func (nc *NoiseConn) performIXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIXResponder"}).Debug("starting IX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first IX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second IX")
}

// performKXInitiator handles KX pattern as initiator (2 messages):
//
//	pre-message: → s
//	→ e
//	← e, ee, se, s, es
func (nc *NoiseConn) performKXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKXInitiator"}).Debug("starting KX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first KX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second KX")
}

// performKXResponder handles KX pattern as responder (2 messages):
//
//	pre-message: → s
//	→ e
//	← e, ee, se, s, es
func (nc *NoiseConn) performKXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKXResponder"}).Debug("starting KX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first KX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second KX")
}

// ============================================================================
// THREE-MESSAGE PATTERNS
// ============================================================================

// performXXInitiator handles XX pattern as initiator
func (nc *NoiseConn) performXXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXXInitiator"}).Debug("starting XX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first XX"); err != nil {
		return err
	}
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second XX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseFinal, "third XX")
}

// performXXResponder handles XX pattern as responder
func (nc *NoiseConn) performXXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXXResponder"}).Debug("starting XX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first XX"); err != nil {
		return err
	}
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second XX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseFinal, "third XX")
}

// performXNInitiator handles XN pattern as initiator (3 messages):
//
//	→ e
//	← e, ee
//	→ s, se
func (nc *NoiseConn) performXNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXNInitiator"}).Debug("starting XN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first XN"); err != nil {
		return err
	}
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second XN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseFinal, "third XN")
}

// performXNResponder handles XN pattern as responder (3 messages):
//
//	→ e
//	← e, ee
//	→ s, se
func (nc *NoiseConn) performXNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXNResponder"}).Debug("starting XN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first XN"); err != nil {
		return err
	}
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second XN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseFinal, "third XN")
}

// performXKInitiator handles XK pattern as initiator (3 messages):
//
//	pre-message: ← s
//	→ e, es
//	← e, ee
//	→ s, se
func (nc *NoiseConn) performXKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXKInitiator"}).Debug("starting XK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first XK"); err != nil {
		return err
	}
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second XK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseFinal, "third XK")
}

// performXKResponder handles XK pattern as responder (3 messages):
//
//	pre-message: ← s
//	→ e, es
//	← e, ee
//	→ s, se
func (nc *NoiseConn) performXKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXKResponder"}).Debug("starting XK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first XK"); err != nil {
		return err
	}
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second XK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseFinal, "third XK")
}

// ============================================================================
// PATTERN PARSING
// ============================================================================

// parseHandshakePattern maps pattern name strings to go-i2p/noise HandshakePattern types.
// Accepts short names (e.g., "XX") and full Noise protocol names for both
// AESGCM and ChaChaPoly cipher suites (e.g., "Noise_XX_25519_ChaChaPoly_SHA256").
func parseHandshakePattern(patternName string) (noise.HandshakePattern, error) {
	switch patternName {
	case "Noise_NN_25519_AESGCM_SHA256", "Noise_NN_25519_ChaChaPoly_SHA256", "NN":
		return noise.HandshakeNN, nil
	case "Noise_NK_25519_AESGCM_SHA256", "Noise_NK_25519_ChaChaPoly_SHA256", "NK":
		return noise.HandshakeNK, nil
	case "Noise_NX_25519_AESGCM_SHA256", "Noise_NX_25519_ChaChaPoly_SHA256", "NX":
		return noise.HandshakeNX, nil
	case "Noise_XN_25519_AESGCM_SHA256", "Noise_XN_25519_ChaChaPoly_SHA256", "XN":
		return noise.HandshakeXN, nil
	case "Noise_XK_25519_AESGCM_SHA256", "Noise_XK_25519_ChaChaPoly_SHA256", "XK":
		return noise.HandshakeXK, nil
	case "Noise_XX_25519_AESGCM_SHA256", "Noise_XX_25519_ChaChaPoly_SHA256", "XX":
		return noise.HandshakeXX, nil
	case "Noise_KN_25519_AESGCM_SHA256", "Noise_KN_25519_ChaChaPoly_SHA256", "KN":
		return noise.HandshakeKN, nil
	case "Noise_KK_25519_AESGCM_SHA256", "Noise_KK_25519_ChaChaPoly_SHA256", "KK":
		return noise.HandshakeKK, nil
	case "Noise_KX_25519_AESGCM_SHA256", "Noise_KX_25519_ChaChaPoly_SHA256", "KX":
		return noise.HandshakeKX, nil
	case "Noise_IN_25519_AESGCM_SHA256", "Noise_IN_25519_ChaChaPoly_SHA256", "IN":
		return noise.HandshakeIN, nil
	case "Noise_IK_25519_AESGCM_SHA256", "Noise_IK_25519_ChaChaPoly_SHA256", "IK":
		return noise.HandshakeIK, nil
	case "Noise_IX_25519_AESGCM_SHA256", "Noise_IX_25519_ChaChaPoly_SHA256", "IX":
		return noise.HandshakeIX, nil
	case "Noise_N_25519_AESGCM_SHA256", "Noise_N_25519_ChaChaPoly_SHA256", "N":
		return noise.HandshakeN, nil
	case "Noise_K_25519_AESGCM_SHA256", "Noise_K_25519_ChaChaPoly_SHA256", "K":
		return noise.HandshakeK, nil
	case "Noise_X_25519_AESGCM_SHA256", "Noise_X_25519_ChaChaPoly_SHA256", "X":
		return noise.HandshakeX, nil
	default:
		return noise.HandshakePattern{}, oops.
			Code("UNSUPPORTED_PATTERN").
			In("noise").
			With("pattern", patternName).
			Errorf("unsupported handshake pattern: %s", patternName)
	}
}
