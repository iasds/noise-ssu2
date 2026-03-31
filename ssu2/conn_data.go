package ssu2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/go-i2p/common/data"
	i2phkdf "github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// startDataLoops starts background goroutines for data transport.
// Called after handshake completes to avoid wasting resources on failed connections.
func (h *SSU2Conn) startDataLoops() {
	h.wg.Add(3)
	go h.sendLoop()
	go h.keepaliveLoop()
	go h.retransmitLoop()
}

// installCipherStates transfers transport cipher states from the handshake handler.
// installCipherStates transfers transport cipher states from the handshake handler.
func (h *SSU2Conn) installCipherStates() error {
	send, recv, err := h.handshakeHandler.GetCipherStates()
	if err != nil {
		return err
	}
	h.cipherMutex.Lock()
	h.sendCipher = send
	h.recvCipher = recv
	h.cipherMutex.Unlock()

	cbs := h.dataHandler.getCallbacks()

	// G-2: Warn if signature verification callbacks are not configured.
	// Relay, peer-test, and hole-punch traffic will be silently rejected
	// when the corresponding verifier is nil.
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

	// Wire NextNonce callback only if enabled (G-1). When disabled,
	// inbound NextNonce blocks are silently ignored.
	if h.config.EnableNextNonce {
		cbs.OnNextNonce = h.handlePeerNextNonce
	}
	// Wire Congestion callback so RequestACK flag triggers immediate ACK (G-6).
	cbs.OnCongestion = h.handleCongestionBlock
	// Wire PathChallenge/PathResponse callbacks for path validation (G-7).
	cbs.OnPathChallenge = h.handlePathChallengeData
	cbs.OnPathResponse = h.handlePathResponseData

	// Wire default Address block handler for passive NAT detection (G-6).
	if cbs.OnAddress == nil {
		cbs.OnAddress = h.handleAddressBlock
	}

	// Wire Termination callback to compare peer-reported received count
	// against our sent count for packet-loss diagnostics (G-7).
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

	h.dataHandler.SetCallbacks(cbs)

	// Update router hash from peer's static key if available
	if peerKey := h.handshakeHandler.GetRemoteStaticKey(); len(peerKey) == 32 {
		hash := sha256.Sum256(peerKey)
		h.ssu2Addr.UpdateRouterHash(data.NewHash(hash))

		// Validate the RouterInfo against the Noise-authenticated static key
		// per SSU2 spec §Session Confirmed (C-2).
		if h.config.RouterInfoValidator != nil {
			if ri := h.handshakeHandler.GetPeerRouterInfo(); len(ri) > 0 {
				if err := h.config.RouterInfoValidator(ri, peerKey); err != nil {
					return oops.Wrapf(err, "RouterInfo validation failed against authenticated static key")
				}
			}
		}
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
//
// deriveSipHashModifier derives per-direction SipHash-2-4 keys and IVs for
// data-phase length obfuscation from the header protection keys using HKDF.
// Per SSU2 spec:
//
//	sipk_ab = HKDF(k_header_2_ab, ZEROLEN, "SipHashKey", 16) → two 8-byte keys
//	sipiv_ab = HKDF(k_header_2_ab, ZEROLEN, "SipHashIV", 8)  → one 8-byte IV
//	sipk_ba = HKDF(k_header_2_ba, ZEROLEN, "SipHashKey", 16)
//	sipiv_ba = HKDF(k_header_2_ba, ZEROLEN, "SipHashIV", 8)
func deriveSipHashModifier(sendKHeader2, recvKHeader2 []byte) (*SipHashLengthModifier, error) {
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

// validateReadyForIO checks that the connection is in the Established state
// and ready for read/write operations.
// validateReadyForIO checks that the connection is in the Established state
// and ready for read/write operations.
func (h *SSU2Conn) validateReadyForIO() error {
	h.stateMutex.RLock()
	state := h.state
	h.stateMutex.RUnlock()

	if state != StateEstablished {
		return oops.Errorf("connection not established: %s", state)
	}
	return nil
}

// Read implements net.Conn.Read.
// Reads data from the connection, reassembling I2NP messages from Data packets.
// Blocks until data is available, the read deadline expires, or the connection closes.
// Read implements net.Conn.Read.
// Reads data from the connection, reassembling I2NP messages from Data packets.
// Blocks until data is available, the read deadline expires, or the connection closes.
func (h *SSU2Conn) Read(b []byte) (int, error) {
	if err := h.validateReadyForIO(); err != nil {
		return 0, err
	}

	// Block until a message arrives, the connection closes, or the deadline expires
	var msg []byte
	select {
	case msg = <-h.dataHandler.MessageChan():
		// Message received
	case <-h.closeChan:
		return 0, oops.Errorf("connection closed")
	case <-h.getReadDeadline():
		return 0, oops.Errorf("read deadline exceeded")
	}

	// Copy message to buffer
	n := copy(b, msg)
	if n < len(msg) {
		return n, oops.Errorf("buffer too small: need %d bytes, got %d", len(msg), len(b))
	}

	return n, nil
}

// Write implements net.Conn.Write.
// Writes data to the connection. If the data exceeds the per-packet payload
// capacity (determined by MTU), it is automatically split into FirstFragment
// and FollowOnFragment blocks per SSU2 spec §FirstFragment/§FollowOnFragment.
//
// For unfragmented messages, b is sent as-is in a BlockTypeI2NPMessage block.
// Per the SSU2 spec, block type 3 (I2NP) data must already contain the 9-byte
// I2NP short header: [I2NPType:1][MessageID:4][ShortExpiry:4] followed by the
// message body. The caller is responsible for prepending this header.
//
// For fragmented messages, the implementation generates its own MessageID and
// ShortExpiry for the FirstFragment/FollowOnFragment blocks, treating b[0] as
// the I2NP type byte and the rest as body data.
// Write implements net.Conn.Write.
// Writes data to the connection. If the data exceeds the per-packet payload
// capacity (determined by MTU), it is automatically split into FirstFragment
// and FollowOnFragment blocks per SSU2 spec §FirstFragment/§FollowOnFragment.
//
// For unfragmented messages, b is sent as-is in a BlockTypeI2NPMessage block.
// Per the SSU2 spec, block type 3 (I2NP) data must already contain the 9-byte
// I2NP short header: [I2NPType:1][MessageID:4][ShortExpiry:4] followed by the
// message body. The caller is responsible for prepending this header.
//
// For fragmented messages, the implementation generates its own MessageID and
// ShortExpiry for the FirstFragment/FollowOnFragment blocks, treating b[0] as
// the I2NP type byte and the rest as body data.
func (h *SSU2Conn) Write(b []byte) (int, error) {
	if err := h.validateReadyForIO(); err != nil {
		return 0, err
	}

	// Maximum block data that fits in a single Data packet.
	// Available = MTU - IP(40) - UDP(8) - SSU2_header(16) - AEAD_MAC(16) - block_TLV(3)
	maxBlockData := h.config.MTU - 80 - minBlockHeaderSize

	if len(b)+minBlockHeaderSize <= maxBlockData+minBlockHeaderSize {
		// Fits in a single I2NP message block
		block := &SSU2Block{
			Type: BlockTypeI2NPMessage,
			Data: copyBytes(b),
		}
		if err := h.writeBlock(block); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	// Fragment the message using FirstFragment + FollowOnFragment blocks.
	blocks, err := h.buildI2NPFragmentBlocks(b, maxBlockData)
	if err != nil {
		return 0, oops.Wrapf(err, "failed to build I2NP fragment blocks")
	}

	if err := h.WriteBlocks(blocks); err != nil {
		return 0, err
	}
	return len(b), nil
}

// buildI2NPFragmentBlocks splits a large I2NP message into FirstFragment and
// FollowOnFragment blocks per SSU2 spec.
//
// FirstFragment (type 4): I2NPType(1) + MessageID(4) + ShortExpiry(4) + data
// FollowOnFragment (type 5): FragInfo(1) + MessageID(4) + data
// buildI2NPFragmentBlocks splits a large I2NP message into FirstFragment and
// FollowOnFragment blocks per SSU2 spec.
//
// FirstFragment (type 4): I2NPType(1) + MessageID(4) + ShortExpiry(4) + data
// FollowOnFragment (type 5): FragInfo(1) + MessageID(4) + data
func (h *SSU2Conn) buildI2NPFragmentBlocks(data []byte, maxBlockData int) ([]*SSU2Block, error) {
	const (
		firstFragHeaderSize    = 9 // type(1) + msgID(4) + shortExpiry(4)
		followOnFragHeaderSize = 5 // fragInfo(1) + msgID(4)
	)

	// Generate a random message ID for fragment correlation.
	var msgIDBuf [4]byte
	if _, err := rand.Read(msgIDBuf[:]); err != nil {
		return nil, oops.Wrapf(err, "failed to generate fragment message ID")
	}
	messageID := binary.BigEndian.Uint32(msgIDBuf[:])

	// I2NP type: use first byte if present, else 0.
	var i2npType uint8
	if len(data) > 0 {
		i2npType = data[0]
	}
	// Short expiration: current time + 120 seconds, in seconds since epoch.
	shortExpiry := uint32(time.Now().Unix()) + 120

	maxFirstData := maxBlockData - firstFragHeaderSize
	if maxFirstData <= 0 {
		return nil, oops.Errorf("MTU too small for fragmentation")
	}

	end := maxFirstData
	if end > len(data) {
		end = len(data)
	}

	// Build FirstFragment block.
	firstData := make([]byte, firstFragHeaderSize+end)
	firstData[0] = i2npType
	binary.BigEndian.PutUint32(firstData[1:5], messageID)
	binary.BigEndian.PutUint32(firstData[5:9], shortExpiry)
	copy(firstData[9:], data[:end])

	blocks := []*SSU2Block{{Type: BlockTypeFirstFragment, Data: firstData}}
	offset := end
	fragNum := uint8(1)

	maxFollowData := maxBlockData - followOnFragHeaderSize
	for offset < len(data) {
		fEnd := offset + maxFollowData
		if fEnd > len(data) {
			fEnd = len(data)
		}
		isLast := fEnd == len(data)
		fragInfo := fragNum << 1
		if isLast {
			fragInfo |= 0x01
		}

		followData := make([]byte, followOnFragHeaderSize+(fEnd-offset))
		followData[0] = fragInfo
		binary.BigEndian.PutUint32(followData[1:5], messageID)
		copy(followData[5:], data[offset:fEnd])

		blocks = append(blocks, &SSU2Block{Type: BlockTypeFollowOnFragment, Data: followData})
		offset = fEnd
		fragNum++
	}

	return blocks, nil
}

// WriteBlocks sends the provided SSU2 blocks as individual Data packets (one
// packet per block). Unlike Write, this bypasses the BlockTypeI2NPMessage
// wrapper and sends pre-built blocks directly. Use this to send fragment
// blocks (BlockTypeFirstFragment / BlockTypeFollowOnFragment) for large I2NP
// messages.
// WriteBlocks sends the provided SSU2 blocks as individual Data packets (one
// packet per block). Unlike Write, this bypasses the BlockTypeI2NPMessage
// wrapper and sends pre-built blocks directly. Use this to send fragment
// blocks (BlockTypeFirstFragment / BlockTypeFollowOnFragment) for large I2NP
// messages.
func (h *SSU2Conn) WriteBlocks(blocks []*SSU2Block) error {
	if err := h.validateReadyForIO(); err != nil {
		return err
	}
	for _, block := range blocks {
		if err := h.writeBlock(block); err != nil {
			return err
		}
	}
	return nil
}

// writeBlock sends a single SSU2Block as a Data packet.
// writeBlock sends a single SSU2Block as a Data packet.
func (h *SSU2Conn) writeBlock(block *SSU2Block) error {
	pktNum := h.nextSendSequence()
	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID)
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	// byte 12 = MessageType will be written by Serialize()
	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Payload:      nil,
		Header:       hdr,
		MAC:          make([]byte, MACSize), // placeholder; real MAC is in encrypted payload
	}

	// Serialize block into payload
	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return oops.Wrapf(err, "failed to serialize block")
	}
	packet.Payload = payload

	// Enqueue for sending
	select {
	case h.sendQueue <- packet:
		return nil
	case <-h.closeChan:
		return oops.Errorf("connection closed")
	case <-h.getWriteDeadline():
		return oops.Errorf("write deadline exceeded")
	}
}

// Close implements net.Conn.Close.
// Sends a Termination block with reason NormalClose and closes the connection.
// sendLoop handles outbound packet transmission.
func (h *SSU2Conn) sendLoop() {
	defer h.wg.Done()

	for {
		select {
		case packet := <-h.sendQueue:
			if err := h.sendPacketDirect(packet); err != nil {
				// Log error but continue
				continue
			}
		case <-h.closeChan:
			return
		}
	}
}

// retransmitLoop periodically scans pendingPackets for RTO expiry and
// re-enqueues expired packets. Packets exceeding maxPacketRetries are dropped.
// retransmitLoop periodically scans pendingPackets for RTO expiry and
// re-enqueues expired packets. Packets exceeding maxPacketRetries are dropped.
func (h *SSU2Conn) retransmitLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(retransmitInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.retransmitExpired()
		case <-h.closeChan:
			return
		}
	}
}

// retransmitExpired checks all pending packets and retransmits those that
// have exceeded their NextRetry deadline.
// retransmitExpired checks all pending packets and retransmits those that
// have exceeded their NextRetry deadline.
func (h *SSU2Conn) retransmitExpired() {
	now := time.Now()
	rto := h.rttEstimator.GetRTO()

	h.pendingMutex.Lock()
	defer h.pendingMutex.Unlock()

	for pn, pp := range h.pendingPackets {
		if now.Before(pp.NextRetry) {
			continue
		}

		if pp.Retries >= maxPacketRetries {
			delete(h.pendingPackets, pn)
			continue
		}

		pp.Retries++
		// Exponential backoff: double the RTO for each retry
		backoff := rto * time.Duration(1<<pp.Retries)
		pp.NextRetry = now.Add(backoff)

		// Per spec: retransmissions must use a fresh packet number.
		newPktNum := h.nextSendSequence()
		hdr := make([]byte, ShortHeaderSize)
		binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID)
		binary.BigEndian.PutUint32(hdr[8:12], newPktNum)
		newPacket := &SSU2Packet{
			MessageType:  MessageTypeData,
			PacketNumber: newPktNum,
			Header:       hdr,
			MAC:          make([]byte, MACSize),
			Payload:      make([]byte, len(pp.PlaintextPayload)),
		}
		copy(newPacket.Payload, pp.PlaintextPayload)

		// Remove old entry; sendPacketDirect will track the new one.
		delete(h.pendingPackets, pn)

		// Best-effort re-enqueue; drop if sendQueue is full
		select {
		case h.sendQueue <- newPacket:
		default:
		}
	}
}

// recvLoop handles inbound packet reception.
// recvLoop handles inbound packet reception.
func (h *SSU2Conn) recvLoop() {
	defer h.wg.Done()

	// Buffer must hold any valid SSU2 packet; use MaxPacketSizeIPv4 so we
	// never truncate legitimate packets regardless of the configured MTU.
	buf := make([]byte, MaxPacketSizeIPv4)
	for {
		select {
		case <-h.closeChan:
			return
		default:
			_ = h.underlying.SetReadDeadline(time.Now().Add(1 * time.Second))

			n, addr, err := h.underlying.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				h.readErrors.Add(1)
				continue
			}

			fmt.Fprintf(os.Stderr, "RECVLOOP: got %d bytes from %v\n", n, addr)
			if packet := h.parseInboundPacket(buf[:n], addr); packet != nil {
				fmt.Fprintf(os.Stderr, "RECVLOOP: parsed packet type=%d pktnum=%d payload_len=%d\n",
					packet.MessageType, packet.PacketNumber, len(packet.Payload))
				h.processInboundPacket(packet)
			} else {
				fmt.Fprintf(os.Stderr, "RECVLOOP: parseInboundPacket returned nil\n")
			}
		}
	}
}

// parseInboundPacket validates the source address, deserializes, and decrypts an
// inbound UDP datagram. Returns nil if the packet should be dropped.
// Supports connection migration: if a packet from a new address passes AEAD
// verification, the remote address is updated (per spec §Connection Migration).
// parseInboundPacket validates the source address, deserializes, and decrypts an
// inbound UDP datagram. Returns nil if the packet should be dropped.
// Supports connection migration: if a packet from a new address passes AEAD
// verification, the remote address is updated (per spec §Connection Migration).
func (h *SSU2Conn) parseInboundPacket(data []byte, addr net.Addr) *SSU2Packet {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil
	}

	addrChanged := !udpAddr.IP.Equal(h.remoteAddr.IP) || udpAddr.Port != h.remoteAddr.Port

	// Decrypt header protection before parsing
	if h.headerProtector != nil {
		hType := h.expectedInboundHeaderType()
		if err := h.headerProtector.DecryptInboundHeader(data, hType); err != nil {
			h.parseErrors.Add(1)
			return nil
		}
	}

	// SipHash length deobfuscation: recover the data length from header
	// bytes 14-15 per spec §Data Phase Length Obfuscation (G-2).
	if mod := h.sipHashModifier.Load(); mod != nil && len(data) >= ShortHeaderSize {
		mask := mod.NextInboundMask()
		obfuscated := binary.BigEndian.Uint16(data[14:16])
		binary.BigEndian.PutUint16(data[14:16], obfuscated^mask)
	}

	packet := &SSU2Packet{}
	if err := packet.Deserialize(data); err != nil {
		h.parseErrors.Add(1)
		return nil
	}

	h.cipherMutex.Lock()
	cipher := h.recvCipher
	if cipher != nil && packet.MessageType == MessageTypeData && len(packet.Payload) > 0 {
		// Per SSU2 spec: nonce is the packet number, AD is the 16-byte header.
		// Bytes 14-15 must be zeroed before AEAD decryption because the sender
		// encrypts with bytes 14-15 = 0 (they are set to the obfuscated length
		// only AFTER encryption). Without this, the AD mismatch causes every
		// data packet to fail AEAD verification.
		binary.BigEndian.PutUint16(packet.Header[14:16], 0)
		cipher.SetNonce(uint64(packet.PacketNumber))
		decrypted, err := cipher.Decrypt(nil, packet.Header[:ShortHeaderSize], packet.Payload)
		if err != nil {
			h.cipherMutex.Unlock()
			h.decryptErrors.Add(1)
			return nil
		}
		packet.Payload = decrypted
	}
	h.cipherMutex.Unlock()

	// If the address changed but AEAD passed, initiate path validation (G-7).
	// Per spec §Connection Migration: packets from a new address require
	// path validation before accepting the address change.
	if addrChanged && h.pathValidator != nil {
		_, _ = h.pathValidator.InitiatePathValidation(udpAddr)
	}

	h.updateActivity()
	return packet
}

// keepaliveLoop manages connection keepalive.
// keepaliveLoop manages connection keepalive.
func (h *SSU2Conn) keepaliveLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.lastActivityLock.RLock()
			timeSinceActivity := time.Since(h.lastActivity)
			h.lastActivityLock.RUnlock()

			// Check if we need to send keepalive
			if timeSinceActivity >= h.config.KeepaliveInterval {
				// Send ACK-only packet as keepalive per spec §Keepalive (M-3)
				ack, err := h.ackHandler.GenerateACK()
				if err == nil && ack != nil {
					pktNum := h.nextSendSequence()
					hdr := make([]byte, ShortHeaderSize)
					binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID)
					binary.BigEndian.PutUint32(hdr[8:12], pktNum)
					packet := &SSU2Packet{
						MessageType:  MessageTypeData,
						PacketNumber: pktNum,
						Header:       hdr,
						MAC:          make([]byte, MACSize),
					}
					payload, _ := SerializeBlocks([]*SSU2Block{ack})
					packet.Payload = payload
					_ = h.sendPacketDirect(packet)
				}
			}

			// Check for timeout (M-2: configurable idle timeout)
			idleTimeout := h.config.IdleTimeout
			if idleTimeout <= 0 {
				idleTimeout = 5 * time.Minute
			}
			if timeSinceActivity >= idleTimeout {
				h.closeMutex.Lock()
				h.closeErr = oops.Errorf("idle timeout")
				h.closeMutex.Unlock()
				_ = h.Close()
				return
			}
		case <-h.closeChan:
			return
		}
	}
}

// sendPacketDirect sends a packet directly to the peer.
// For data packets in the established state, the payload is encrypted with AEAD.
// sendPacketDirect sends a packet directly to the peer.
// For data packets in the established state, the payload is encrypted with AEAD.
func (h *SSU2Conn) sendPacketDirect(packet *SSU2Packet) error {
	// Save plaintext payload before encryption for potential retransmit.
	var plaintextPayload []byte

	// Encrypt payload for data packets when cipher states are available.
	// Lock is exclusive because SetNonce+Encrypt must be atomic.
	h.cipherMutex.Lock()
	cipher := h.sendCipher
	if cipher != nil && packet.MessageType == MessageTypeData && len(packet.Payload) > 0 {
		plaintextPayload = make([]byte, len(packet.Payload))
		copy(plaintextPayload, packet.Payload)
		// Per SSU2 spec: nonce is the packet number, AD is the 16-byte header.
		// The message type byte (header[12]) must be set before AEAD encryption
		// so that the AD matches what the receiver will see after deserialization.
		// Serialize() also writes this byte, but that runs after encryption.
		packet.Header[12] = packet.MessageType
		cipher.SetNonce(uint64(packet.PacketNumber))
		encrypted, err := cipher.Encrypt(nil, packet.Header[:ShortHeaderSize], packet.Payload)
		if err != nil {
			h.cipherMutex.Unlock()
			return oops.Wrapf(err, "failed to encrypt payload")
		}
		packet.Payload = encrypted
	}
	h.cipherMutex.Unlock()

	// SipHash length obfuscation: write obfuscated payload length to header
	// bytes 14-15 per spec §Data Phase Length Obfuscation (G-2).
	if mod := h.sipHashModifier.Load(); mod != nil && packet.MessageType == MessageTypeData {
		dataLen := uint16(len(packet.Payload))
		mask := mod.NextOutboundMask()
		binary.BigEndian.PutUint16(packet.Header[14:16], dataLen^mask)
	}

	// Serialize packet
	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize packet")
	}

	// Apply header protection if enabled
	if h.headerProtector != nil {
		hType := messageTypeToHeaderType(packet.MessageType)
		if hpErr := h.headerProtector.EncryptOutboundHeader(data, hType); hpErr != nil {
			return oops.Wrapf(hpErr, "failed to encrypt header")
		}
	}

	// Send to peer
	_, err = h.underlying.WriteTo(data, h.remoteAddr)
	if err != nil {
		return oops.Wrapf(err, "failed to write to UDP")
	}

	// Count successfully sent data packets (G-7)
	if packet.MessageType == MessageTypeData {
		h.validDataPacketsSent.Add(1)
	}

	// Update activity
	h.updateActivity()

	// Track pending packet if it needs ACK
	if packet.MessageType == MessageTypeData && packet.PacketNumber > 0 {
		h.pendingMutex.Lock()
		h.pendingPackets[packet.PacketNumber] = &PendingPacket{
			Packet:           packet,
			PlaintextPayload: plaintextPayload,
			SentTime:         time.Now(),
			Retries:          0,
			NextRetry:        time.Now().Add(h.rttEstimator.GetRTO()),
		}
		h.pendingMutex.Unlock()
	}

	return nil
}

// processInboundPacket processes a received packet.
// processInboundPacket processes a received packet.
func (h *SSU2Conn) processInboundPacket(packet *SSU2Packet) {
	switch packet.MessageType {
	case MessageTypeData:
		// Enforce receive window: reject duplicate, old, and out-of-window packets
		if h.recvWindow != nil {
			if _, err := h.recvWindow.Insert(packet); err != nil {
				return // silently drop
			}
		}

		// Record for ACK only after window acceptance
		if packet.PacketNumber > 0 {
			h.ackHandler.RecordReceived(packet.PacketNumber)
		}

		h.validDataPacketsReceived.Add(1)
		// Check immediate-ack flag: header byte 13, bit 0 (M-5: this is also
		// checked via CongestionFlagRequestACK in the Congestion block handler,
		// providing redundant but harmless ACK triggering)
		if len(packet.Header) > 13 && packet.Header[13]&0x01 != 0 {
			h.sendImmediateACK()
		}
		h.processDataPacket(packet)
	case MessageTypeSessionRequest, MessageTypeSessionCreated, MessageTypeSessionConfirmed:
		// Handshake packets bypass receive window
		if packet.PacketNumber > 0 {
			h.ackHandler.RecordReceived(packet.PacketNumber)
		}
		select {
		case h.recvQueue <- packet:
		default:
		}
	}
}

// processDataPacket handles a data-phase packet: parses blocks and retires ACKed packets.
// processDataPacket handles a data-phase packet: parses blocks and retires ACKed packets.
func (h *SSU2Conn) processDataPacket(packet *SSU2Packet) {
	log.WithFields(map[string]interface{}{
		"pkt_num":     packet.PacketNumber,
		"payload_len": len(packet.Payload),
	}).Debug("processDataPacket: processing")
	blocks, err := h.dataHandler.ProcessDataPacket(packet)
	if err != nil {
		log.WithField("error", err.Error()).Debug("processDataPacket: ProcessDataPacket error")
		return
	}
	log.WithField("num_blocks", len(blocks)).Debug("processDataPacket: processed blocks")

	// Process ACK blocks
	for _, block := range blocks {
		if block.Type == BlockTypeACK {
			ackedNums, _ := h.ackHandler.ProcessACK(block)
			// Remove acknowledged packets from pending queue
			h.pendingMutex.Lock()
			for _, num := range ackedNums {
				delete(h.pendingPackets, num)
			}
			h.pendingMutex.Unlock()
		}
	}
}

// sendImmediateACK generates and sends an ACK packet without delay, honoring
// the immediate-ack flag (header byte 13 bit 0) from the peer.
// sendImmediateACK generates and sends an ACK packet without delay, honoring
// the immediate-ack flag (header byte 13 bit 0) from the peer.
func (h *SSU2Conn) sendImmediateACK() {
	ack, err := h.ackHandler.GenerateACK()
	if err != nil || ack == nil {
		return
	}
	pktNum := h.nextSendSequence()
	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID)
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		MAC:          make([]byte, MACSize),
	}
	payload, _ := SerializeBlocks([]*SSU2Block{ack})
	packet.Payload = payload
	_ = h.sendPacketDirect(packet)
}

// handleCongestionBlock processes a received Congestion block (G-6).
// If the RequestACK flag (bit 0) is set, triggers an immediate ACK per spec.
// If the ECN flag (bit 1) is set, signals the congestion controller.
// handleCongestionBlock processes a received Congestion block (G-6).
// If the RequestACK flag (bit 0) is set, triggers an immediate ACK per spec.
// If the ECN flag (bit 1) is set, signals the congestion controller.
func (h *SSU2Conn) handleCongestionBlock(flags uint8) error {
	if flags&CongestionFlagRequestACK != 0 {
		h.sendImmediateACK()
	}
	if flags&CongestionFlagECN != 0 && h.congestionController != nil {
		h.congestionController.OnECN()
	}
	return nil
}

// handlePathChallengeData wraps PathValidator.HandlePathChallenge for the DataHandler callback (G-7).
// handlePathChallengeData wraps PathValidator.HandlePathChallenge for the DataHandler callback (G-7).
func (h *SSU2Conn) handlePathChallengeData(data []byte) error {
	block := &SSU2Block{Type: BlockTypePathChallenge, Data: data}
	return h.pathValidator.HandlePathChallenge(block, h.remoteAddr)
}

// handlePathResponseData wraps PathValidator.HandlePathResponse for the DataHandler callback (G-7).
// handlePathResponseData wraps PathValidator.HandlePathResponse for the DataHandler callback (G-7).
func (h *SSU2Conn) handlePathResponseData(data []byte) error {
	block := &SSU2Block{Type: BlockTypePathResponse, Data: data}
	return h.pathValidator.HandlePathResponse(block, h.remoteAddr)
}

// handleAddressBlock processes an Address block (Type 13) for passive NAT
// detection (G-6). The block contains the sender's view of our IP and port.
// Format: IP (4 or 16 bytes) + Port (2 bytes big-endian).
// handleAddressBlock processes an Address block (Type 13) for passive NAT
// detection (G-6). The block contains the sender's view of our IP and port.
// Format: IP (4 or 16 bytes) + Port (2 bytes big-endian).
func (h *SSU2Conn) handleAddressBlock(data []byte) error {
	if len(data) != 6 && len(data) != 18 {
		return oops.Errorf("Address block invalid length: %d (expected 6 or 18)", len(data))
	}
	portOffset := len(data) - 2
	ip := net.IP(data[:portOffset])
	port := binary.BigEndian.Uint16(data[portOffset:])

	localAddr := h.LocalAddr()
	if udp, ok := localAddr.(*net.UDPAddr); ok {
		if !udp.IP.Equal(ip) || udp.Port != int(port) {
			log.WithFields(map[string]interface{}{
				"reportedIP":   ip.String(),
				"reportedPort": port,
				"localIP":      udp.IP.String(),
				"localPort":    udp.Port,
			}).Info("Address block reports different address (possible NAT)")
		}
	}
	return nil
}

// extractRetryToken parses a Retry message and returns the 8-byte token.
// nextSendSequence returns the next packet sequence number.
// When the sequence crosses rekeyThreshold, it fires a one-shot
// NextNonce rekey so the cipher is refreshed before the 32-bit
// counter wraps. Per SSU2 spec, the packet number must not wrap
// around to zero (G-1); if the counter reaches 0xFFFFFFFF the
// connection is closed.
//
// NOTE: The SSU2 spec marks NextNonce (block type 11) as "TODO only if we
// rotate keys" with size "TBD". This rekey mechanism is based on an
// unfinalized spec area and may need revision when the spec is updated.
func (h *SSU2Conn) nextSendSequence() uint32 {
	h.sendSeqMutex.Lock()
	defer h.sendSeqMutex.Unlock()

	// Hard reject: do not wrap past 0xFFFFFFFF (G-1).
	if h.sendSequence == 0xFFFFFFFF {
		log.Error("packet number exhausted (0xFFFFFFFF): closing connection per SSU2 spec")
		go h.Close()
		return 0xFFFFFFFF
	}

	seq := h.sendSequence
	h.sendSequence++

	// Trigger rekey exactly once when we cross the threshold,
	// but only if NextNonce is enabled via config (G-1).
	if h.config.EnableNextNonce && seq >= rekeyThreshold && !h.rekeyInFlight.Load() {
		if h.rekeyInFlight.CompareAndSwap(false, true) {
			go h.initiateRekey()
		}
	}
	return seq
}

// initiateRekey sends a NextNonce block to the peer, then rekeys the local
// send cipher and resets the send sequence counter.
//
// The NextNonce block MUST be encrypted with the OLD key so the receiver can
// decrypt it and learn about the rekey. Only after the NextNonce packet is
// fully encrypted and transmitted do we switch to the new key.
//
// This function bypasses the normal sendQueue path and sends inline under
// cipherMutex to guarantee atomic key transition: no packet can be encrypted
// between NextNonce send and the key switch.
// initiateRekey sends a NextNonce block to the peer, then rekeys the local
// send cipher and resets the send sequence counter.
//
// The NextNonce block MUST be encrypted with the OLD key so the receiver can
// decrypt it and learn about the rekey. Only after the NextNonce packet is
// fully encrypted and transmitted do we switch to the new key.
//
// This function bypasses the normal sendQueue path and sends inline under
// cipherMutex to guarantee atomic key transition: no packet can be encrypted
// between NextNonce send and the key switch.
func (h *SSU2Conn) initiateRekey() {
	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	if h.sendCipher == nil {
		return
	}

	log.Warn("initiating NextNonce rekey (unfinalized spec area — interoperability not guaranteed)")

	// Derive new send cipher key per SSU2 spec §NextNonce:
	// newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32).
	newKey, err := deriveRekeyKey(h.sendCipher)
	if err != nil {
		log.WithField("error", err).Error("failed to derive rekey for send cipher")
		return
	}

	// Send NextNonce block encrypted with the OLD key before rekeying.
	if err := h.sendNextNonceInline(); err != nil {
		log.WithField("error", err).Error("failed to send NextNonce block")
		return
	}

	// NOW rekey the cipher to the new key.
	h.sendCipher.UnsafeSetKey(newKey)
	h.sendCipher.SetNonce(0)

	// Reset send sequence so new packets start at 0.
	h.sendSeqMutex.Lock()
	h.sendSequence = 0
	h.sendSeqMutex.Unlock()
}

// sendNextNonceInline builds, encrypts, and sends a NextNonce block directly,
// bypassing the sendQueue. Must be called while holding cipherMutex so the
// packet is encrypted with the current (old) key atomically.
// sendNextNonceInline builds, encrypts, and sends a NextNonce block directly,
// bypassing the sendQueue. Must be called while holding cipherMutex so the
// packet is encrypted with the current (old) key atomically.
func (h *SSU2Conn) sendNextNonceInline() error {
	// Allocate packet number from the current sequence counter.
	h.sendSeqMutex.Lock()
	pktNum := h.sendSequence
	h.sendSequence++
	h.sendSeqMutex.Unlock()

	// Build NextNonce block with new starting nonce (0).
	var nonceBuf [8]byte
	block := &SSU2Block{Type: BlockTypeNextNonce, Data: nonceBuf[:]}

	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return oops.Wrapf(err, "serialize NextNonce block")
	}

	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID)
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	hdr[12] = MessageTypeData

	// Encrypt with the current (OLD) key.
	h.sendCipher.SetNonce(uint64(pktNum))
	encrypted, err := h.sendCipher.Encrypt(nil, hdr[:ShortHeaderSize], payload)
	if err != nil {
		return oops.Wrapf(err, "encrypt NextNonce block")
	}

	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		Payload:      encrypted,
		MAC:          make([]byte, MACSize),
	}

	// SipHash length obfuscation.
	if mod := h.sipHashModifier.Load(); mod != nil {
		dataLen := uint16(len(encrypted))
		mask := mod.NextOutboundMask()
		binary.BigEndian.PutUint16(packet.Header[14:16], dataLen^mask)
	}

	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "serialize NextNonce packet")
	}

	if h.headerProtector != nil {
		hType := messageTypeToHeaderType(packet.MessageType)
		_ = h.headerProtector.EncryptOutboundHeader(data, hType)
	}

	_, err = h.underlying.WriteTo(data, h.remoteAddr)
	if err != nil {
		return oops.Wrapf(err, "send NextNonce packet")
	}

	h.updateActivity()
	return nil
}

// handlePeerNextNonce is the OnNextNonce callback wired in installCipherStates.
// When the peer sends us a NextNonce, we rekey the *receive* cipher to match.
// handlePeerNextNonce is the OnNextNonce callback wired in installCipherStates.
// When the peer sends us a NextNonce, we rekey the *receive* cipher to match.
func (h *SSU2Conn) handlePeerNextNonce(newNonce uint64) error {
	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	if h.recvCipher == nil {
		return oops.Errorf("receive cipher not initialized")
	}

	// Derive new recv cipher key per SSU2 spec §NextNonce:
	// newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32) (G-5).
	newKey, err := deriveRekeyKey(h.recvCipher)
	if err != nil {
		return oops.Wrapf(err, "failed to derive rekey for recv cipher")
	}
	h.recvCipher.UnsafeSetKey(newKey)
	h.recvCipher.SetNonce(newNonce)

	log.WithField("newNonce", newNonce).Info("Applied peer NextNonce rekey on receive cipher")
	return nil
}

// updateActivity updates the last activity timestamp.
// updateActivity updates the last activity timestamp.
func (h *SSU2Conn) updateActivity() {
	h.lastActivityLock.Lock()
	defer h.lastActivityLock.Unlock()
	h.lastActivity = time.Now()
}

// getReadDeadline returns a channel that closes at read deadline.
// getReadDeadline returns a channel that closes at read deadline.
func (h *SSU2Conn) getReadDeadline() <-chan time.Time {
	h.deadlineMutex.RLock()
	defer h.deadlineMutex.RUnlock()
	if h.readDeadline.IsZero() {
		return nil
	}
	return time.After(time.Until(h.readDeadline))
}

// getWriteDeadline returns a channel that closes at write deadline.
// getWriteDeadline returns a channel that closes at write deadline.
func (h *SSU2Conn) getWriteDeadline() <-chan time.Time {
	h.deadlineMutex.RLock()
	defer h.deadlineMutex.RUnlock()
	if h.writeDeadline.IsZero() {
		return nil
	}
	return time.After(time.Until(h.writeDeadline))
}

// sortFragmentsByIndex sorts SessionConfirmed fragments by their fragment
// index (bits 7-4 of header byte 13). This ensures ProcessSessionConfirmedFragments
// receives fragments in the correct order regardless of arrival order.
