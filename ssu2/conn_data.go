package ssu2

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/go-i2p/common/data"
	i2phkdf "github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// startDataLoops starts background goroutines for data transport.
// Called after handshake completes to avoid wasting resources on failed connections.
func (h *SSU2Conn) startDataLoops() {
	log.Debug("startDataLoops: starting send, keepalive, and retransmit loops")
	h.wg.Add(3)
	go h.sendLoop()
	go h.keepaliveLoop()
	go h.retransmitLoop()
}

// installCipherStates transfers transport cipher states from the handshake handler.
func (h *SSU2Conn) installCipherStates() error {
	log.Debug("installCipherStates: transferring cipher states from handshake")
	send, recv, err := h.handshakeHandler.GetCipherStates()
	if err != nil {
		return err
	}
	h.cipherMutex.Lock()
	h.sendCipher = send
	h.recvCipher = recv
	h.cipherMutex.Unlock()

	h.wireDataCallbacks()

	if err := h.validatePeerRouterInfo(); err != nil {
		return err
	}

	return nil
}

// wireDataCallbacks wires internal handler callbacks for data-phase processing.
func (h *SSU2Conn) wireDataCallbacks() {
	log.WithField("next_nonce_enabled", h.config.EnableNextNonce).Debug("wireDataCallbacks: wiring data-phase callbacks")
	cbs := h.dataHandler.getCallbacks()

	// G-2: Warn if signature verification callbacks are not configured.
	h.warnMissingSignatureVerifiers(&cbs)

	// Wire NextNonce callback only if enabled (G-1).
	if h.config.EnableNextNonce {
		cbs.OnNextNonce = h.handlePeerNextNonce
	}
	cbs.OnCongestion = h.handleCongestionBlock
	cbs.OnPathChallenge = h.handlePathChallengeData
	cbs.OnPathResponse = h.handlePathResponseData

	if cbs.OnAddress == nil {
		cbs.OnAddress = h.handleAddressBlock
	}

	h.wrapTerminationCallback(&cbs)
	h.dataHandler.SetCallbacks(cbs)
}

// warnMissingSignatureVerifiers logs warnings for unset signature verifiers (G-2).
func (h *SSU2Conn) warnMissingSignatureVerifiers(cbs *DataHandlerCallbacks) {
	if cbs.VerifyPeerTestSignature == nil {
		log.Warn("PeerTest signature verifier not configured; peer test messages will be rejected (G-2)")
	}
	if cbs.VerifyRelayRequestSignature == nil {
		log.Warn("RelayRequest signature verifier not configured; relay requests will be rejected (G-2)")
	}
	if cbs.VerifyRelayResponseSignature == nil {
		log.Warn("RelayResponse signature verifier not configured; signed relay responses will be rejected (G-2)")
	}
	if cbs.VerifyRelayIntroSignature == nil {
		log.Warn("RelayIntro signature verifier not configured; relay intros will be rejected (G-2)")
	}
}

// wrapTerminationCallback wraps the Termination callback to log packet-loss diagnostics (G-7).
func (h *SSU2Conn) wrapTerminationCallback(cbs *DataHandlerCallbacks) {
	existingOnTermination := cbs.OnTermination
	cbs.OnTermination = func(peerReceived uint64, reason uint8, additionalData []byte) {
		sent := h.validDataPacketsSent.Load()
		if sent > 0 {
			lost := int64(sent) - int64(peerReceived)
			log.WithFields(map[string]interface{}{
				"sent":         sent,
				"peerReceived": peerReceived,
				"lost":         lost,
				"reason":       reason,
			}).Info("Termination packet loss summary (G-7)")
		}
		if existingOnTermination != nil {
			existingOnTermination(peerReceived, reason, additionalData)
		}
	}
}

// validatePeerRouterInfo validates the peer's RouterInfo against the Noise-authenticated
// static key per SSU2 spec §Session Confirmed (C-2).
func (h *SSU2Conn) validatePeerRouterInfo() error {
	peerKey := h.handshakeHandler.GetRemoteStaticKey()
	if len(peerKey) != 32 {
		return nil
	}
	hash := sha256.Sum256(peerKey)
	h.ssu2Addr.UpdateRouterHash(data.NewHash(hash))

	if h.config.RouterInfoValidator == nil {
		return nil
	}
	ri := h.handshakeHandler.GetPeerRouterInfo()
	if len(ri) == 0 {
		return nil
	}
	if err := h.config.RouterInfoValidator(ri, peerKey); err != nil {
		return oops.Wrapf(err, "RouterInfo validation failed against authenticated static key")
	}
	return nil
}

// deriveSipHashModifier derives per-direction SipHash-2-4 keys and IVs for
// data-phase length obfuscation from the header protection keys using HKDF.
// Per SSU2 spec:
//
//	sipk_ab = HKDF(k_header_2_ab, ZEROLEN, "SipHashKey", 16) → two 8-byte keys
//	sipiv_ab = HKDF(k_header_2_ab, ZEROLEN, "SipHashIV", 8)  → one 8-byte IV
//	sipk_ba = HKDF(k_header_2_ba, ZEROLEN, "SipHashKey", 16)
//	sipiv_ba = HKDF(k_header_2_ba, ZEROLEN, "SipHashIV", 8)
func deriveSipHashModifier(sendKHeader2, recvKHeader2 []byte) (*SipHashLengthModifier, error) {
	log.WithFields(logger.Fields{"send_key_len": len(sendKHeader2), "recv_key_len": len(recvKHeader2)}).Debug("deriveSipHashModifier: deriving SipHash keys for length obfuscation")
	deriver := i2phkdf.NewHKDF()
	infoKey := []byte("SipHashKey")
	infoIV := []byte("SipHashIV")

	sendKeys, err := deriver.Derive(nil, sendKHeader2, infoKey, 16)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive send SipHash keys")
	}
	sendIVData, err := deriver.Derive(nil, sendKHeader2, infoIV, 8)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive send SipHash IV")
	}
	recvKeys, err := deriver.Derive(nil, recvKHeader2, infoKey, 16)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive recv SipHash keys")
	}
	recvIVData, err := deriver.Derive(nil, recvKHeader2, infoIV, 8)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive recv SipHash IV")
	}

	outKeys := [2]uint64{
		binary.LittleEndian.Uint64(sendKeys[0:8]),
		binary.LittleEndian.Uint64(sendKeys[8:16]),
	}
	outIV := binary.LittleEndian.Uint64(sendIVData[0:8])

	inKeys := [2]uint64{
		binary.LittleEndian.Uint64(recvKeys[0:8]),
		binary.LittleEndian.Uint64(recvKeys[8:16]),
	}
	inIV := binary.LittleEndian.Uint64(recvIVData[0:8])

	return NewSipHashLengthModifierDirectional("ssu2-data-siphash", outKeys, inKeys, outIV, inIV), nil
}

// deriveRekeyKey derives a new cipher key from the current cipher state
// using HKDF per SSU2 spec §NextNonce: newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32).
func deriveRekeyKey(cs *noise.CipherState) ([32]byte, error) {
	key := cs.UnsafeKey()
	deriver := i2phkdf.NewHKDF()
	derived, err := deriver.Derive(nil, key[:], []byte("WrapCipherKey"), 32)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "HKDF rekey derivation failed")
	}
	var newKey [32]byte
	copy(newKey[:], derived)
	return newKey, nil
}
