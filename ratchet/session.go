package ratchet

import (
	"sync"
	"time"

	"github.com/go-i2p/crypto/ratchet"
	"github.com/samber/oops"
)

// Session represents an active encrypted session with a remote destination.
// It maintains separate sending and receiving ratchet chains as required by
// the ECIES-X25519-AEAD-Ratchet Double Ratchet protocol.
//
// Thread safety: Session has its own mutex that protects ratchet state during
// crypto operations. The session manager lock and session lock have a defined
// ordering to prevent deadlocks.
type Session struct {
	mu               sync.Mutex
	RemotePublicKey  [32]byte
	DHRatchet        *ratchet.DHRatchet
	SymmetricRatchet *ratchet.SymmetricRatchet // sending chain
	TagRatchet       *ratchet.TagRatchet       // sending tags
	// RecvSymmetricRatchet is the receiving chain ratchet.
	RecvSymmetricRatchet *ratchet.SymmetricRatchet
	// RecvTagRatchet is the receiving tag ratchet.
	RecvTagRatchet *ratchet.TagRatchet
	LastUsed       time.Time
	MessageCounter uint32
	// recvCounter tracks the number of received messages.
	recvCounter uint32
	// pendingTags tracks tags we expect to receive (tag window).
	pendingTags [][8]byte
	// dhRatchetCounter tracks messages since last DH ratchet rotation.
	dhRatchetCounter uint32
	// consecutiveDHFailures tracks how many DH ratchet steps have failed in a row.
	consecutiveDHFailures uint32
	// newEphemeralPub holds the new ephemeral public key for the peer.
	newEphemeralPub *[32]byte
	// handshakeState retains intermediate Noise IK state for NSR.
	// Non-nil when NSR has not yet been sent (responder) or received (initiator).
	handshakeState *noiseHandshakeState
	// isInitiator tracks whether we initiated the session (sent NS).
	isInitiator bool
	// nsrTag is the NSR tag registered in the SessionManager's nsrTagIndex.
	// Non-nil only on initiator sessions until the NSR has been received.
	// Used to clean up the index entry on session eviction or expiry.
	nsrTag *[8]byte

	// sendKeyID is the current send-direction DH ratchet key ID.
	// Incremented each time we generate a new forward key.
	// Spec ref: ratchet.md §"Key and Tag Set IDs".
	sendKeyID uint16
	// recvKeyID is the current receive-direction DH ratchet key ID.
	// Updated when we receive a NextKey block from the peer.
	recvKeyID uint16
	// pendingNextKeys holds NextKey blocks to include in the next outgoing message.
	// These are generated when the DH ratchet rotates and consumed when sent.
	pendingNextKeys []PayloadBlock
	// awaitingReverseKey tracks whether we sent a forward NextKey with
	// request-reverse set and are waiting for the peer's reverse key.
	awaitingReverseKey bool
}

// createSession initializes a new Session with ratchet state from derived keys.
// The isInitiator flag determines key direction: the initiator's send ratchets
// use "initiator" direction keys and its receive ratchets use "responder" direction
// keys (and vice versa for the responder).
func createSession(remotePubKey [32]byte, keys *sessionKeys, ourPrivateKey [32]byte, isInitiator bool) (*Session, error) {
	sendRootKey, recvRootKey, err := deriveDirectionalKeys(keys.rootKey, isInitiator)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive directional root keys")
	}
	sendTagKey, recvTagKey, err := deriveDirectionalKeys(keys.tagKey, isInitiator)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive directional tag keys")
	}

	dhRatchet := ratchet.NewDHRatchet(keys.rootKey, ourPrivateKey, remotePubKey)
	symRatchet := ratchet.NewSymmetricRatchet(sendRootKey)
	tagRatchet := ratchet.NewTagRatchet(sendTagKey)
	recvSymRatchet := ratchet.NewSymmetricRatchet(recvRootKey)
	recvTagRatchet := ratchet.NewTagRatchet(recvTagKey)

	return &Session{
		RemotePublicKey:      remotePubKey,
		DHRatchet:            dhRatchet,
		SymmetricRatchet:     symRatchet,
		TagRatchet:           tagRatchet,
		RecvSymmetricRatchet: recvSymRatchet,
		RecvTagRatchet:       recvTagRatchet,
		LastUsed:             time.Now(),
		MessageCounter:       1,
		// recvCounter starts at 1 because the New Session message (message 0) is a
		// one-off ECIES handshake that is not counted in the ratchet counter.
		// After an NSR the counter resets to 1 for the same reason: the NSR itself
		// (message 0 in the new tag set) is a handshake, not an AEAD ratchet message.
		// Spec ref: ratchet.md §"Existing Session message" — "N=1 for the first
		// Existing Session message after a New Session or New Session Reply".
		recvCounter:     1,
		pendingTags:     make([][8]byte, 0, 10),
		pendingNextKeys: nil,
	}, nil
}
