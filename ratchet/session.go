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
		recvCounter:          1, // starts at 1 because message 0 is the New Session (ECIES, not ratchet)
		pendingTags:          make([][8]byte, 0, 10),
	}, nil
}
