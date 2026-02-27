package ratchet

// This file implements the Noise IKelg2+hs2 handshake for I2P
// ECIES-X25519-AEAD-Ratchet New Session messages. The implementation follows
// the Noise Protocol Framework (revision 34) with two I2P-specific
// modifications:
//
//   - elg2: Ephemeral public keys are Elligator2-encoded to be
//     indistinguishable from random bytes on the wire.
//   - hs2: The responder's static public key pre-message uses Hash(s)
//     instead of the raw key, allowing initiators to start a handshake
//     knowing only the responder's identity hash.
//
// Wire format for New Session (IK message 1):
//
//	[Elligator2(ephemeral_pub)(32)] + [EncryptAndHash(static_pub)(48)] + [EncryptAndHash(payload)(N+16)]

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/elligator2"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

const (
	// noiseProtocolName is the Noise protocol identifier for I2P ECIES-X25519-AEAD-Ratchet.
	noiseProtocolName = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"

	// noiseIKOverhead is the fixed overhead added by the Noise IK handshake:
	// 32 (Elligator2 ephemeral key) + 16 (static key AEAD tag) + 16 (payload AEAD tag).
	noiseIKOverhead = 32 + 16 + 16

	// noiseIKMinMessageSize is the minimum New Session message size:
	// 32 (ephemeral) + 48 (encrypted static) + 16 (minimum payload AEAD = empty plaintext + tag).
	noiseIKMinMessageSize = 32 + 48 + 16

	// noiseEncryptedStaticSize is the size of the encrypted static key section:
	// 32 bytes key + 16 bytes AEAD tag.
	noiseEncryptedStaticSize = 48
)

// noiseIKState implements the Noise symmetric state for the IKelg2+hs2 variant.
// It tracks the handshake hash (h), chaining key (ck), cipher key (k), and
// nonce counter (n) as defined in the Noise Protocol Framework §5.
type noiseIKState struct {
	h      [32]byte // handshake hash
	ck     [32]byte // chaining key
	k      [32]byte // cipher key (valid when hasKey is true)
	n      uint64   // nonce counter (reset to 0 after each MixKey)
	hasKey bool     // whether k holds a valid key
}

// initNoiseIK initializes the Noise symmetric state for the IKelg2+hs2 handshake.
// The protocol name is hashed (since it exceeds 32 bytes), then the null prologue
// is mixed in (as required by the Noise spec §5.6 and the I2P ECIES-X25519-AEAD-Ratchet
// spec KDF section), and finally the responder's static key hash is mixed in per hs2.
//
// Initialization transcript:
//
//	h = SHA-256(protocol_name)           InitializeSymmetric
//	ck = h
//	h = SHA-256(h || "")                 MixHash(null prologue)  — required by spec
//	h = SHA-256(h || SHA-256(rs))        MixHash(Hash(rs))       — hs2 pre-message
func initNoiseIK(responderStaticPub [32]byte) *noiseIKState {
	// InitializeSymmetric: protocol name is 50 chars > HASHLEN (32), so h = SHA-256(name)
	h := sha256.Sum256([]byte(noiseProtocolName))
	ns := &noiseIKState{h: h, ck: h}

	// MixHash(null prologue): h = SHA-256(h || "")
	// The I2P ECIES-X25519-AEAD-Ratchet spec requires an explicit MixHash of the
	// empty prologue before any pre-message processing. Omitting this step diverges
	// from the spec transcript and breaks interoperability with conformant routers
	// (Java I2P, i2pd) which apply this step correctly.
	ns.mixHash([]byte{})

	// Pre-message (← s) with hs2: MixHash(Hash(rs)) instead of MixHash(rs)
	rsHash := sha256.Sum256(responderStaticPub[:])
	ns.mixHash(rsHash[:])

	return ns
}

// mixHash updates the handshake hash: h = SHA-256(h || data).
func (ns *noiseIKState) mixHash(data []byte) {
	hasher := sha256.New()
	hasher.Write(ns.h[:])
	hasher.Write(data)
	copy(ns.h[:], hasher.Sum(nil))
}

// mixKey derives a new chaining key and cipher key from input key material.
// ck, k = HKDF(ck, ikm, 2); resets nonce counter to 0.
func (ns *noiseIKState) mixKey(ikm []byte) {
	ns.ck, ns.k = noiseHKDF2(ns.ck[:], ikm)
	ns.n = 0
	ns.hasKey = true
}

// mixKeyCKOnly updates only the chaining key via a single-output HKDF.
// Per I2P ratchet.md §1g, the "ee" handshake token in the NSR uses:
//
//	ck = HKDF(chainKey, DH(e, re), "", 32)
//
// Unlike mixKey, this does NOT update the cipher key (k) or reset the nonce.
// The spec mandates single-output HKDF for "ee" to prevent accidental use
// of an intermediate cipher key between the "ee" and "se" steps.
func (ns *noiseIKState) mixKeyCKOnly(ikm []byte) {
	ns.ck = noiseHKDF1(ns.ck[:], ikm)
}

// encryptAndHash encrypts plaintext using the current cipher key with h as AD.
// Returns ciphertext || tag (N + 16 bytes). Updates h with the ciphertext.
func (ns *noiseIKState) encryptAndHash(plaintext []byte) ([]byte, error) {
	if !ns.hasKey {
		// No key set: pass-through (per Noise spec §5.2)
		ns.mixHash(plaintext)
		return plaintext, nil
	}

	aead, err := chacha20poly1305.NewAEAD(ns.k)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD for handshake encryption")
	}

	nonce := noiseNonce(ns.n)
	ct, tag, err := aead.Encrypt(plaintext, ns.h[:], nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "handshake encryption failed")
	}
	ns.n++

	result := append(ct, tag[:]...)
	ns.mixHash(result)
	return result, nil
}

// decryptAndHash decrypts ciphertext (with appended 16-byte tag) using the
// current cipher key with h as AD. Updates h with the original ciphertext.
func (ns *noiseIKState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if !ns.hasKey {
		// No key set: pass-through (per Noise spec §5.2)
		ns.mixHash(ciphertext)
		return ciphertext, nil
	}

	if len(ciphertext) < 16 {
		return nil, oops.Errorf("handshake ciphertext too short for auth tag: %d bytes", len(ciphertext))
	}

	aead, err := chacha20poly1305.NewAEAD(ns.k)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD for handshake decryption")
	}

	ct := ciphertext[:len(ciphertext)-16]
	var tag [16]byte
	copy(tag[:], ciphertext[len(ciphertext)-16:])

	nonce := noiseNonce(ns.n)
	plaintext, err := aead.Decrypt(ct, tag[:], ns.h[:], nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "handshake decryption failed (authentication error)")
	}
	ns.n++

	ns.mixHash(ciphertext)
	return plaintext, nil
}

// noiseNonce constructs a 12-byte Noise nonce: [0,0,0,0 || LE64(counter)].
func noiseNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// noiseHKDF1 computes HKDF with 1 output as defined by the Noise spec §4.3.
// Returns a single 32-byte output (the new chaining key).
// Per I2P ratchet.md §1g, the "ee" handshake token uses a single-output HKDF:
//
//	ck = HKDF(chainKey, sharedSecret, "", 32)
//
// This updates only the chaining key, not the cipher key.
func noiseHKDF1(chainingKey, inputKeyMaterial []byte) [32]byte {
	tempKey := hmacSHA256(chainingKey, inputKeyMaterial)
	output1 := hmacSHA256(tempKey[:], []byte{0x01})
	return output1
}

// noiseHKDF2 computes HKDF with 2 outputs as defined by the Noise spec §4.3.
// Returns (output1, output2) each 32 bytes.
func noiseHKDF2(chainingKey, inputKeyMaterial []byte) ([32]byte, [32]byte) {
	tempKey := hmacSHA256(chainingKey, inputKeyMaterial)
	output1 := hmacSHA256(tempKey[:], []byte{0x01})

	input2 := make([]byte, 33)
	copy(input2[:32], output1[:])
	input2[32] = 0x02
	output2 := hmacSHA256(tempKey[:], input2)

	return output1, output2
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// writeNoiseIKMessage1 constructs a New Session message using the Noise IK pattern
// with Elligator2-encoded ephemeral keys (elg2) and hashed static pre-message (hs2).
//
// The initiator calls this to encrypt a payload for a known responder. Returns
// the wire-format message, session keys derived from the handshake chaining key,
// and the handshake state retained for processing the New Session Reply (message 2).
func writeNoiseIKMessage1(
	ourStaticPriv, ourStaticPub, responderStaticPub [32]byte,
	payload []byte,
) ([]byte, *sessionKeys, *noiseHandshakeState, error) {
	ns := initNoiseIK(responderStaticPub)

	// Token e: Generate Elligator2-representable ephemeral key pair
	ephPub, ephPrivBytes, err := elligator2.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to generate Elligator2 ephemeral key pair")
	}

	// Elligator2-encode the ephemeral public key for the wire
	ephEncoded, err := elligator2.Encode(ephPub)
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to Elligator2-encode ephemeral public key")
	}

	// MixHash the encoded (wire) representation, not the raw key
	ns.mixHash(ephEncoded)

	// Token es: DH(ephemeral_private, responder_static)
	ephPriv := x25519.PrivateKey(ephPrivBytes)
	sharedES, err := ephPriv.SharedKey(x25519.PublicKey(responderStaticPub[:]))
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to compute DH(e, rs)")
	}
	ns.mixKey(sharedES)

	// Token s: Encrypt our static public key under the current key
	encryptedStatic, err := ns.encryptAndHash(ourStaticPub[:])
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to encrypt static public key")
	}

	// Token ss: DH(our_static_private, responder_static)
	ourPriv := x25519.PrivateKey(ourStaticPriv[:])
	sharedSS, err := ourPriv.SharedKey(x25519.PublicKey(responderStaticPub[:]))
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to compute DH(s, rs)")
	}
	ns.mixKey(sharedSS)

	// Encrypt the garlic payload
	encryptedPayload, err := ns.encryptAndHash(payload)
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to encrypt payload")
	}

	// Construct wire message: [elligator2(e)(32)] + [encrypted_s(48)] + [encrypted_payload(N+16)]
	msg := make([]byte, 0, 32+len(encryptedStatic)+len(encryptedPayload))
	msg = append(msg, ephEncoded...)
	msg = append(msg, encryptedStatic...)
	msg = append(msg, encryptedPayload...)

	// Retain handshake state for New Session Reply (message 2)
	hs := &noiseHandshakeState{
		h:            ns.h,
		ck:           ns.ck,
		localEphPriv: ephPrivBytes,
	}

	// Derive session keys from the final chaining key
	keys, err := deriveSessionKeysFromSecret(ns.ck[:])
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to derive session keys from handshake")
	}

	return msg, keys, hs, nil
}

// writeNoiseIKMessage1Unbound constructs an unbound New Session message using
// the Noise N pattern (§1c of the I2P ECIES-X25519-AEAD-Ratchet spec). The
// initiator's static key is NOT included; instead a 32-byte zero flags section
// is encrypted in its place. The receiver detects the unbound variant by
// decrypting the flags section and testing whether all 32 bytes are zero.
//
// Use cases: raw-datagram and one-time-send traffic where sender anonymity
// requires not advertising the static key. Unbound sessions are non-repliable.
//
// Wire format: [Elligator2(e)(32)] + [EncryptAndHash(zeros32)(48)] + [EncryptAndHash(payload)(N+16)]
//
// KDF differences from the bound (IK) variant:
//   - No Token s: flags section (zeros) is encrypted with n=0 (same k as es token)
//   - No Token ss: no second DH, no new MixKey — the nonce counter is NOT reset
//   - Payload is encrypted with n=1 (one above the flags section)
//
// Spec ref: ratchet.md §1c, §1f "KDF for Payload Section (without Alice static key)"
func writeNoiseIKMessage1Unbound(
	responderStaticPub [32]byte,
	payload []byte,
) ([]byte, *sessionKeys, error) {
	// Same IK initializer as the bound variant: identical protocol name, null
	// prologue MixHash, and Hash(rs) pre-message. Spec §1f: "we use the same
	// initializer for both the IK pattern (bound sessions) and for N pattern
	// (unbound sessions)."
	ns := initNoiseIK(responderStaticPub)

	// Token e: Generate Elligator2-representable ephemeral key pair.
	ephPub, ephPrivBytes, err := elligator2.GenerateKeyPair()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to generate Elligator2 ephemeral key pair")
	}

	ephEncoded, err := elligator2.Encode(ephPub)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to Elligator2-encode ephemeral public key")
	}

	// MixHash the wire (Elligator2-encoded) representation.
	ns.mixHash(ephEncoded)

	// Token es: DH(ephemeral_private, responder_static). Sets k, resets n=0.
	ephPriv := x25519.PrivateKey(ephPrivBytes)
	sharedES, err := ephPriv.SharedKey(x25519.PublicKey(responderStaticPub[:]))
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to compute DH(e, rs)")
	}
	ns.mixKey(sharedES) // n=0 after this

	// Flags section (unbound marker): EncryptAndHash(zeros32) using n=0.
	// Plaintext is 32 zero bytes — the receiver tests the decrypted plaintext
	// for all-zeros to identify the unbound variant. Spec §1c.
	// After encryption ns.n advances to 1.
	encryptedFlags, err := ns.encryptAndHash(make([]byte, 32))
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to encrypt unbound flags section")
	}

	// Encrypt payload with n=1 (no ss token, no MixKey reset).
	// Spec §1f "KDF for Payload Section (without Alice static key)": n=1.
	encryptedPayload, err := ns.encryptAndHash(payload)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to encrypt payload")
	}

	// Wire: [Elligator2(e)(32)] + [encryptedFlags(48)] + [encryptedPayload(N+16)]
	msg := make([]byte, 0, 32+len(encryptedFlags)+len(encryptedPayload))
	msg = append(msg, ephEncoded...)
	msg = append(msg, encryptedFlags...)
	msg = append(msg, encryptedPayload...)

	// Derive session keys from the final chaining key.
	keys, err := deriveSessionKeysFromSecret(ns.ck[:])
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive session keys from unbound handshake")
	}

	return msg, keys, nil
}

// isAllZeros reports whether all bytes in b are 0x00.
func isAllZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// readNoiseIKMessage1 processes a received New Session message using the Noise
// IK pattern. The responder calls this to decrypt the initiator's payload.
// It handles both the bound (IK, with initiator static key) and unbound (N,
// flags section all-zeros) variants; isUnbound signals which was detected.
//
// For bound messages: returns initiator's static public key and handshake state.
// For unbound messages: initiatorStaticPub is [32]byte{} (zero), hs is nil.
//
// Returns the decrypted payload, initiator's static public key, session keys,
// handshake state for the New Session Reply (nil for unbound), isUnbound, and error.
func readNoiseIKMessage1(
	ourStaticPriv, ourStaticPub [32]byte,
	message []byte,
) ([]byte, [32]byte, *sessionKeys, *noiseHandshakeState, bool, error) {
	if len(message) < noiseIKMinMessageSize {
		return nil, [32]byte{}, nil, nil, false, oops.Errorf(
			"new session message too short: %d bytes (minimum %d)", len(message), noiseIKMinMessageSize)
	}

	ns := initNoiseIK(ourStaticPub)

	// Token e: Read Elligator2-encoded ephemeral key.
	ephEncoded := message[0:32]
	ns.mixHash(ephEncoded)

	// Decode Elligator2 representation to get the actual X25519 public key.
	ephPubBytes, err := elligator2.Decode(ephEncoded)
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to decode Elligator2 ephemeral key")
	}
	var initiatorEphPub [32]byte
	copy(initiatorEphPub[:], ephPubBytes)

	// Token es: DH(our_static_private, ephemeral). Sets k, resets n=0.
	ourPriv := x25519.PrivateKey(ourStaticPriv[:])
	sharedES, err := ourPriv.SharedKey(x25519.PublicKey(ephPubBytes))
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to compute DH(s, re)")
	}
	ns.mixKey(sharedES) // n=0 after this

	// Token s / Flags section: decrypt the 48-byte section that is either the
	// initiator's static key (bound) or 32 zero bytes (unbound).
	// Uses n=0; after decryption ns.n=1.
	encryptedStatic := message[32 : 32+noiseEncryptedStaticSize]
	initiatorStaticBytes, err := ns.decryptAndHash(encryptedStatic)
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to decrypt initiator static key / flags section")
	}

	// Detect unbound variant: spec §1c — "Bob determines whether it's a static
	// key or a flags section by testing if the 32 bytes are all zeros."
	if isAllZeros(initiatorStaticBytes) {
		// Unbound (N-pattern): no ss token, no new MixKey.
		// Payload is encrypted with n=1 (current nonce after flags section).
		encryptedPayload := message[32+noiseEncryptedStaticSize:]
		payload, payErr := ns.decryptAndHash(encryptedPayload)
		if payErr != nil {
			return nil, [32]byte{}, nil, nil, true, oops.Wrapf(payErr, "failed to decrypt unbound payload")
		}

		// No handshake state — unbound sessions are non-repliable (no NSR).
		keys, kErr := deriveSessionKeysFromSecret(ns.ck[:])
		if kErr != nil {
			return nil, [32]byte{}, nil, nil, true, oops.Wrapf(kErr, "failed to derive session keys from unbound handshake")
		}
		return payload, [32]byte{}, keys, nil, true, nil
	}

	// Bound path: initiatorStaticBytes is the initiator's static public key.
	var initiatorStaticPub [32]byte
	copy(initiatorStaticPub[:], initiatorStaticBytes)

	// Token ss: DH(our_static_private, initiator_static). Resets n=0.
	sharedSS, err := ourPriv.SharedKey(x25519.PublicKey(initiatorStaticPub[:]))
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to compute DH(s, rs)")
	}
	ns.mixKey(sharedSS) // n=0 after this

	// Decrypt the garlic payload (n=0 after ss MixKey).
	encryptedPayload := message[32+noiseEncryptedStaticSize:]
	payload, err := ns.decryptAndHash(encryptedPayload)
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to decrypt payload")
	}

	// Retain handshake state for New Session Reply (message 2).
	hs := &noiseHandshakeState{
		h:               ns.h,
		ck:              ns.ck,
		remoteEphPub:    initiatorEphPub,
		remoteStaticPub: initiatorStaticPub,
	}

	// Derive session keys from the final chaining key.
	keys, err := deriveSessionKeysFromSecret(ns.ck[:])
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to derive session keys from handshake")
	}

	return payload, initiatorStaticPub, keys, hs, false, nil
}
