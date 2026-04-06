package ntcp2

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// NTCP2 handshake wire-format constants.
const (
	// msg1Size is the fixed size of NTCP2 message 1 AEAD frame (before cleartext padding).
	// 32 bytes (AES-obfuscated ephemeral key) + 16 bytes (encrypted options) + 16 bytes (Poly1305 tag).
	msg1Size = 64

	// msg2Size is the fixed size of NTCP2 message 2 AEAD frame (before cleartext padding).
	msg2Size = 64

	// msg3Part1Size is the fixed size of NTCP2 message 3 part 1.
	// 32 bytes (encrypted static key) + 16 bytes (Poly1305 tag).
	msg3Part1Size = 48

	// ntcp2NetID is the I2P network ID (value 2 for the main network).
	ntcp2NetID = 0x02

	// ntcp2Ver is the NTCP2 protocol version field value.
	ntcp2Ver = 0x02

	// ntcp2OptionsSize is the fixed size of the options block in bytes.
	ntcp2OptionsSize = 16

	// routerInfoBlockType is the NTCP2 block type for RouterInfo (type 2).
	routerInfoBlockType = 0x02
)

// Handshake performs the NTCP2 XK three-way handshake with correct wire framing.
//
// The standard Noise framing adds a 2-byte length prefix to every handshake
// message. The NTCP2 spec explicitly forbids length prefixes on messages 1, 2,
// and 3.  This method writes and reads raw Noise bytes directly over the TCP
// socket to produce the correct on-wire format:
//
//   - Message 1 (64 bytes): [AES-obfuscated e (32B)] [EncryptAndHash(options) (16B)] [tag (16B)]
//   - Message 2 (64 bytes): [AES-obfuscated e (32B)] [EncryptAndHash(options) (16B)] [tag (16B)]
//   - Message 3 (48 + m3p2Len bytes): [EncryptAndHash(s) (48B)] [EncryptAndHash(RI block) (m3p2Len B)]
//
// Cleartext padding: Alice sends none (padLen=0). Bob's padding is read,
// MixHash'd, and discarded per the NTCP2 spec §4.4.
//
// Handshake must not be called concurrently on the same connection.
func (c *NTCP2Conn) Handshake(ctx context.Context) error {
	cfg := c.ntcp2Config.Load()
	if cfg == nil {
		return oops.
			Code("MISSING_NTCP2_CONFIG").
			In("ntcp2").
			Errorf("NTCP2Config not set; call SetNTCP2Config before Handshake")
	}

	nc := c.UnderlyingConn()
	nc.StartHandshake()

	// Apply a handshake deadline to the underlying TCP connection so that
	// blocking Read/Write calls in performInitiatorHandshake / performResponderHandshake
	// are bounded. Without this, a misbehaving peer can cause the handshake to block
	// indefinitely (the ctx was previously accepted but never used).
	raw := nc.Underlying()
	hsCtx := ctx
	if cfg.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		hsCtx, cancel = context.WithTimeout(ctx, cfg.HandshakeTimeout)
		defer cancel()
	}
	if deadline, ok := hsCtx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			nc.FailHandshake()
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("ntcp2").
				Wrapf(err, "failed to set handshake deadline on underlying connection")
		}
		// Clear the deadline once the handshake finishes (or fails) so
		// subsequent data-phase I/O is not accidentally time-limited.
		defer func() {
			_ = raw.SetDeadline(time.Time{})
		}()
	}

	var err error
	if cfg.Initiator {
		if len(cfg.LocalRouterInfo) == 0 {
			nc.FailHandshake()
			return oops.
				Code("MISSING_LOCAL_ROUTER_INFO").
				In("ntcp2").
				Errorf("LocalRouterInfo must be set in NTCP2Config for outbound connections")
		}
		err = performInitiatorHandshake(cfg, nc)
	} else {
		err = performResponderHandshake(cfg, nc)
	}
	if err != nil {
		nc.FailHandshake()
		return err
	}

	// Run the PostHandshakeHook to derive SipHash keys from the ASK master and h.
	if err := nc.RunPostHandshakeHook(); err != nil {
		nc.FailHandshake()
		return oops.
			Code("POST_HANDSHAKE_HOOK_FAILED").
			In("ntcp2").
			Wrapf(err, "post-handshake hook failed after NTCP2 handshake")
	}

	nc.CompleteHandshake()

	// Copy the derived SipHash modifier from the config into the connection's
	// data-phase length obfuscator (mirrors the standard handshake path).
	c.PropagateSipHash()
	return nil
}

// performInitiatorHandshake executes the three-message NTCP2 XK exchange.
func performInitiatorHandshake(cfg *NTCP2Config, nc *noise.NoiseConn) error {
	riBytes := cfg.LocalRouterInfo
	// m3p2Len includes the block header (3B), flag byte (1B), RouterInfo bytes, and the AEAD tag (16B).
	// Per the NTCP2 spec, the RouterInfo block (type 2) data starts with a 1-byte flag field.
	m3p2Len := uint16(BlockHeaderSize + 1 + len(riBytes) + Poly1305Overhead)

	raw := nc.Underlying()

	// === Message 1 (Alice -> Bob) ============================================
	opts1 := buildMessage1Options(m3p2Len)
	msg1, err := nc.WriteHandshakeMsgToBytes(handshake.PhaseInitial, opts1)
	if err != nil {
		return oops.Code("MSG1_WRITE_FAILED").In("ntcp2").
			Wrapf(err, "failed to build NTCP2 message 1")
	}
	if len(msg1) != msg1Size {
		return oops.Code("MSG1_SIZE_MISMATCH").In("ntcp2").
			Errorf("expected message 1 to be %d bytes, got %d", msg1Size, len(msg1))
	}
	if _, err := raw.Write(msg1); err != nil {
		return oops.Code("MSG1_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 1")
	}
	// padLen = 0: no cleartext padding appended after message 1.

	// === Message 2 (Bob -> Alice) ============================================
	buf2 := make([]byte, msg2Size)
	if _, err := io.ReadFull(raw, buf2); err != nil {
		return oops.Code("MSG2_READ_FAILED").In("ntcp2").
			Wrapf(err, "failed to read NTCP2 message 2")
	}
	bobOpts, err := nc.ReadHandshakeMsgFromBytes(handshake.PhaseExchange, buf2)
	if err != nil {
		return oops.Code("MSG2_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 2")
	}
	// Read and MixHash Bob's cleartext padding (bytes 2-3 of his options = padLen).
	if len(bobOpts) >= ntcp2OptionsSize {
		bobPadLen := int(binary.BigEndian.Uint16(bobOpts[2:4]))
		if bobPadLen > 0 {
			pad := make([]byte, bobPadLen)
			if _, err := io.ReadFull(raw, pad); err != nil {
				return oops.Code("MSG2_PAD_READ_FAILED").In("ntcp2").
					Wrapf(err, "failed to read %d cleartext padding bytes after message 2", bobPadLen)
			}
			nc.MixHashData(pad)
		}
	}

	// === Message 3 (Alice -> Bob) ============================================
	msg3Payload := buildMsg3Part2Payload(riBytes)
	msg3, err := nc.WriteHandshakeMsgToBytes(handshake.PhaseFinal, msg3Payload)
	if err != nil {
		return oops.Code("MSG3_WRITE_FAILED").In("ntcp2").
			Wrapf(err, "failed to build NTCP2 message 3")
	}
	expectedLen := msg3Part1Size + int(m3p2Len)
	if len(msg3) != expectedLen {
		return oops.Code("MSG3_SIZE_MISMATCH").In("ntcp2").
			Errorf("expected message 3 to be %d bytes, got %d", expectedLen, len(msg3))
	}
	if _, err := raw.Write(msg3); err != nil {
		return oops.Code("MSG3_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 3")
	}
	return nil
}

// performResponderHandshake executes the three-message NTCP2 XK exchange
// from the responder's (Bob's) perspective.
func performResponderHandshake(cfg *NTCP2Config, nc *noise.NoiseConn) error {
	raw := nc.Underlying()

	// === Message 1 (Alice -> Bob) ============================================
	buf1 := make([]byte, msg1Size)
	if _, err := io.ReadFull(raw, buf1); err != nil {
		return oops.Code("MSG1_READ_FAILED").In("ntcp2").
			Wrapf(err, "failed to read NTCP2 message 1")
	}
	aliceOpts, err := nc.ReadHandshakeMsgFromBytes(handshake.PhaseInitial, buf1)
	if err != nil {
		return oops.Code("MSG1_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 1")
	}
	// Parse Alice's options to extract padLen (bytes 2-3) and m3p2Len (bytes 4-5).
	if len(aliceOpts) < ntcp2OptionsSize {
		return oops.Code("MSG1_OPTIONS_TOO_SHORT").In("ntcp2").
			Errorf("message 1 options too short: got %d, need %d", len(aliceOpts), ntcp2OptionsSize)
	}
	alicePadLen := int(binary.BigEndian.Uint16(aliceOpts[2:4]))
	m3p2Len := binary.BigEndian.Uint16(aliceOpts[4:6])

	// Read and MixHash Alice's cleartext padding after message 1.
	// Per NTCP2 spec §4.1: "padding MUST be mixed into the handshake hash"
	// even when padLen is 0 (no bytes to read, no MixHash needed).
	if alicePadLen > 0 {
		pad := make([]byte, alicePadLen)
		if _, err := io.ReadFull(raw, pad); err != nil {
			return oops.Code("MSG1_PAD_READ_FAILED").In("ntcp2").
				Wrapf(err, "failed to read %d cleartext padding bytes after message 1", alicePadLen)
		}
		nc.MixHashData(pad)
	}

	// === Message 2 (Bob -> Alice) ============================================
	opts2 := buildMessage2Options()
	msg2, err := nc.WriteHandshakeMsgToBytes(handshake.PhaseExchange, opts2)
	if err != nil {
		return oops.Code("MSG2_WRITE_FAILED").In("ntcp2").
			Wrapf(err, "failed to build NTCP2 message 2")
	}
	if len(msg2) != msg2Size {
		return oops.Code("MSG2_SIZE_MISMATCH").In("ntcp2").
			Errorf("expected message 2 to be %d bytes, got %d", msg2Size, len(msg2))
	}
	if _, err := raw.Write(msg2); err != nil {
		return oops.Code("MSG2_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 2")
	}
	// padLen = 0: no cleartext padding appended after message 2 for now.

	// === Message 3 (Alice -> Bob) ============================================
	msg3Len := msg3Part1Size + int(m3p2Len)
	buf3 := make([]byte, msg3Len)
	if _, err := io.ReadFull(raw, buf3); err != nil {
		return oops.Code("MSG3_READ_FAILED").In("ntcp2").
			Wrapf(err, "failed to read NTCP2 message 3 (%d bytes)", msg3Len)
	}
	_, err = nc.ReadHandshakeMsgFromBytes(handshake.PhaseFinal, buf3)
	if err != nil {
		return oops.Code("MSG3_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 3")
	}

	return nil
}

// buildMessage2Options constructs the 16-byte options block sent as the
// AEAD payload in NTCP2 message 2 (Bob -> Alice).
//
// Wire layout (all fields big-endian):
//
//	byte 0     : id     = 0x02  (network ID)
//	byte 1     : ver    = 0x02  (NTCP2 protocol version)
//	bytes 2-3  : padLen = 0     (no cleartext padding for MVP)
//	bytes 4-7  : tsB            (Bob's Unix timestamp, big-endian uint32)
//	bytes 8-15 : Reserved = 0
func buildMessage2Options() []byte {
	opts := make([]byte, ntcp2OptionsSize)
	// opts[0:2] = Reserved = 0 (Message 2 has no id/ver)
	// opts[2:4] = padLen   = 0 (zero by make)
	// opts[4:8] = Reserved = 0
	binary.BigEndian.PutUint32(opts[8:12], uint32(time.Now().Unix()))
	// opts[12:16] = Reserved = 0
	return opts
}

// buildMessage1Options constructs the 16-byte options block sent as the
// AEAD payload in NTCP2 message 1 (Alice -> Bob).
//
// Wire layout (all fields big-endian):
//
//	byte 0     : id     = 0x02  (network ID)
//	byte 1     : ver    = 0x02  (NTCP2 protocol version)
//	bytes 2-3  : padLen = 0     (no cleartext padding for MVP)
//	bytes 4-5  : m3p2Len        (message-3 part-2 size, including AEAD tag)
//	bytes 6-7  : Rsvd   = 0
//	bytes 8-11 : tsA            (Alice's Unix timestamp, big-endian uint32)
//	bytes 12-15: Reserved = 0
func buildMessage1Options(m3p2Len uint16) []byte {
	opts := make([]byte, ntcp2OptionsSize)
	opts[0] = ntcp2NetID
	opts[1] = ntcp2Ver
	// opts[2:4] = padLen  = 0 (zero by make)
	binary.BigEndian.PutUint16(opts[4:6], m3p2Len)
	// opts[6:8] = Rsvd = 0
	binary.BigEndian.PutUint32(opts[8:12], uint32(time.Now().Unix()))
	// opts[12:16] = Reserved = 0
	return opts
}

// buildMsg3Part2Payload wraps raw RouterInfo bytes in the NTCP2 block frame
// (type 2) that becomes the plaintext payload of Noise message 3.
//
// Per the NTCP2 spec, the RouterInfo block data starts with a 1-byte flag field:
//   - bit 0: if set, request peer to flood the RouterInfo
//
// Wire layout:
//
//	byte 0    : block type = 0x02 (RouterInfo)
//	bytes 1-2 : block size = 1 + len(routerInfoBytes) (big-endian uint16)
//	byte 3    : flag = 0x00 (no flood request)
//	bytes 4+  : routerInfoBytes
func buildMsg3Part2Payload(routerInfoBytes []byte) []byte {
	payload := make([]byte, BlockHeaderSize+1+len(routerInfoBytes))
	payload[0] = routerInfoBlockType
	binary.BigEndian.PutUint16(payload[1:3], uint16(1+len(routerInfoBytes)))
	payload[3] = 0x00 // flag byte: no flood request
	copy(payload[4:], routerInfoBytes)
	return payload
}
