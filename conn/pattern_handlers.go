package conn

import (
	"context"
	"sync"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// PatternHandlerFunc is the signature for a Noise handshake pattern handler.
// Consumers can implement custom patterns and register them via RegisterPattern.
//
// The handler receives a PatternContext interface that provides access to
// configuration, logging, and handshake message operations without exposing
// internal connection state. This allows third-party pattern implementations.
type PatternHandlerFunc func(pctx PatternContext, ctx context.Context) error

// patternMu guards concurrent access to initiatorHandlers and responderHandlers.
var patternMu sync.RWMutex

// initiatorHandlers maps pattern names to their initiator handshake implementations.
// Each handler is wrapped in an adapter that converts the *Conn method to PatternContext.
var initiatorHandlers = map[string]PatternHandlerFunc{
	"N":  wrapConnHandler((*Conn).performNInitiator),
	"K":  wrapConnHandler((*Conn).performKInitiator),
	"X":  wrapConnHandler((*Conn).performXInitiator),
	"NN": wrapConnHandler((*Conn).performNNInitiator),
	"NK": wrapConnHandler((*Conn).performNKInitiator),
	"NX": wrapConnHandler((*Conn).performNXInitiator),
	"XN": wrapConnHandler((*Conn).performXNInitiator),
	"XK": wrapConnHandler((*Conn).performXKInitiator),
	"XX": wrapConnHandler((*Conn).performXXInitiator),
	"KN": wrapConnHandler((*Conn).performKNInitiator),
	"KK": wrapConnHandler((*Conn).performKKInitiator),
	"KX": wrapConnHandler((*Conn).performKXInitiator),
	"IN": wrapConnHandler((*Conn).performINInitiator),
	"IK": wrapConnHandler((*Conn).performIKInitiator),
	"IX": wrapConnHandler((*Conn).performIXInitiator),
}

// responderHandlers maps pattern names to their responder handshake implementations.
// Each handler is wrapped in an adapter that converts the *Conn method to PatternContext.
var responderHandlers = map[string]PatternHandlerFunc{
	"N":  wrapConnHandler((*Conn).performNResponder),
	"K":  wrapConnHandler((*Conn).performKResponder),
	"X":  wrapConnHandler((*Conn).performXResponder),
	"NN": wrapConnHandler((*Conn).performNNResponder),
	"NK": wrapConnHandler((*Conn).performNKResponder),
	"NX": wrapConnHandler((*Conn).performNXResponder),
	"XN": wrapConnHandler((*Conn).performXNResponder),
	"XK": wrapConnHandler((*Conn).performXKResponder),
	"XX": wrapConnHandler((*Conn).performXXResponder),
	"KN": wrapConnHandler((*Conn).performKNResponder),
	"KK": wrapConnHandler((*Conn).performKKResponder),
	"KX": wrapConnHandler((*Conn).performKXResponder),
	"IN": wrapConnHandler((*Conn).performINResponder),
	"IK": wrapConnHandler((*Conn).performIKResponder),
	"IX": wrapConnHandler((*Conn).performIXResponder),
}

// wrapConnHandler adapts a *Conn method into a PatternHandlerFunc.
// This allows internal handlers to remain as methods while conforming
// to the public interface signature.
func wrapConnHandler(method func(*Conn, context.Context) error) PatternHandlerFunc {
	return func(pctx PatternContext, ctx context.Context) error {
		// The PatternContext is guaranteed to be a *Conn in our implementation,
		// so this type assertion is safe. External implementations would provide
		// their own PatternContext that doesn't depend on *Conn.
		nc, ok := pctx.(*Conn)
		if !ok {
			return oops.
				Code("INVALID_PATTERN_CONTEXT").
				In("noise").
				Errorf("pattern context must be *Conn for built-in handlers")
		}
		return method(nc, ctx)
	}
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
func (nc *Conn) performInitiatorHandshake(ctx context.Context) error {
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
	patternMu.RLock()
	handler, ok := initiatorHandlers[normalized]
	patternMu.RUnlock()
	if ok {
		return handler(nc, ctx)
	}
	return oops.
		Code("UNSUPPORTED_PATTERN").
		In("noise").
		Errorf("unsupported handshake pattern: %s", pattern)
}

// performResponderHandshake handles the responder side of the handshake.
func (nc *Conn) performResponderHandshake(ctx context.Context) error {
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
	patternMu.RLock()
	handler, ok := responderHandlers[normalized]
	patternMu.RUnlock()
	if ok {
		return handler(nc, ctx)
	}
	return oops.
		Code("UNSUPPORTED_PATTERN").
		In("noise").
		Errorf("unsupported handshake pattern: %s", pattern)
}

// RegisterPattern registers custom initiator and responder handlers for the
// given Noise pattern name. Both handlers must be non-nil. RegisterPattern is
// safe to call concurrently with connection handshakes and is intended to be
// called once at program start (e.g., from an init() function).
func RegisterPattern(name string, initiator, responder PatternHandlerFunc) {
	if name == "" || initiator == nil || responder == nil {
		return
	}
	patternMu.Lock()
	initiatorHandlers[name] = initiator
	responderHandlers[name] = responder
	patternMu.Unlock()
}

// ============================================================================
// ONE-WAY PATTERNS (1 message)
// ============================================================================

// performNInitiator handles N pattern as initiator: → e, es
func (nc *Conn) performNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNInitiator"}).Debug("starting N pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "N")
}

// performKInitiator handles K pattern as initiator: → e, es, ss
func (nc *Conn) performKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKInitiator"}).Debug("starting K pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "K")
}

// performXInitiator handles X pattern as initiator: → e, es, s, ss
func (nc *Conn) performXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXInitiator"}).Debug("starting X pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "X")
}

// performNResponder handles N pattern as responder: → e, es
func (nc *Conn) performNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNResponder"}).Debug("starting N pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "N")
}

// performKResponder handles K pattern as responder: → e, es, ss
func (nc *Conn) performKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKResponder"}).Debug("starting K pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "K")
}

// performXResponder handles X pattern as responder: → e, es, s, ss
func (nc *Conn) performXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXResponder"}).Debug("starting X pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "X")
}

// ============================================================================
// TWO-MESSAGE INTERACTIVE PATTERNS
// ============================================================================

// performNNInitiator handles NN pattern as initiator
func (nc *Conn) performNNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNNInitiator"}).Debug("starting NN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NN")
}

// performNNResponder handles NN pattern as responder
func (nc *Conn) performNNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNNResponder"}).Debug("starting NN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NN")
}

// performNKInitiator handles NK pattern as initiator: → e, es, ← e, ee
func (nc *Conn) performNKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNKInitiator"}).Debug("starting NK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NK")
}

// performNKResponder handles NK pattern as responder: → e, es, ← e, ee
func (nc *Conn) performNKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNKResponder"}).Debug("starting NK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NK")
}

// performNXInitiator handles NX pattern as initiator: → e, ← e, ee, s, es
func (nc *Conn) performNXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNXInitiator"}).Debug("starting NX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NX")
}

// performNXResponder handles NX pattern as responder: → e, ← e, ee, s, es
func (nc *Conn) performNXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNXResponder"}).Debug("starting NX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NX")
}

// performKNInitiator handles KN pattern as initiator: → e, ← e, ee, se, es
func (nc *Conn) performKNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKNInitiator"}).Debug("starting KN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first KN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second KN")
}

// performKNResponder handles KN pattern as responder: → e, ← e, ee, se, es
func (nc *Conn) performKNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKNResponder"}).Debug("starting KN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first KN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second KN")
}

// performKKInitiator handles KK pattern as initiator: → e, es, ss, ← e, ee, se
func (nc *Conn) performKKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKKInitiator"}).Debug("starting KK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first KK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second KK")
}

// performKKResponder handles KK pattern as responder: → e, es, ss, ← e, ee, se
func (nc *Conn) performKKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKKResponder"}).Debug("starting KK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first KK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second KK")
}

// performINInitiator handles IN pattern as initiator: → e, s, ← e, ee, se, es
func (nc *Conn) performINInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performINInitiator"}).Debug("starting IN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IN")
}

// performINResponder handles IN pattern as responder: → e, s, ← e, ee, se, es
func (nc *Conn) performINResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performINResponder"}).Debug("starting IN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first IN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second IN")
}

// performIKInitiator handles IK pattern as initiator: → e, es, s, ss, ← e, ee, se
func (nc *Conn) performIKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIKInitiator"}).Debug("starting IK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IK")
}

// performIKResponder handles IK pattern as responder: → e, es, s, ss, ← e, ee, se
func (nc *Conn) performIKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIKResponder"}).Debug("starting IK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first IK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second IK")
}

// performIXInitiator handles IX pattern as initiator: → e, s, ← e, ee, se, s, es
func (nc *Conn) performIXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIXInitiator"}).Debug("starting IX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IX")
}

// performIXResponder handles IX pattern as responder: → e, s, ← e, ee, se, s, es
func (nc *Conn) performIXResponder(ctx context.Context) error {
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
func (nc *Conn) performKXInitiator(ctx context.Context) error {
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
func (nc *Conn) performKXResponder(ctx context.Context) error {
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
func (nc *Conn) performXXInitiator(ctx context.Context) error {
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
func (nc *Conn) performXXResponder(ctx context.Context) error {
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
func (nc *Conn) performXNInitiator(ctx context.Context) error {
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
func (nc *Conn) performXNResponder(ctx context.Context) error {
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
func (nc *Conn) performXKInitiator(ctx context.Context) error {
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
func (nc *Conn) performXKResponder(ctx context.Context) error {
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

// ValidateHandshakePattern reports whether pattern is a known Noise handshake
// pattern name. It accepts both short names ("XX") and full protocol names
// ("Noise_XX_25519_AESGCM_SHA256"). Returns a non-nil error if the pattern
// is unknown. This exported form allows sibling packages (e.g., noise/listener)
// to validate patterns without importing the unexported parseHandshakePattern.
func ValidateHandshakePattern(pattern string) error {
	_, err := parseHandshakePattern(pattern)
	return err
}
