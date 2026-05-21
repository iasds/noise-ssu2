package ntcp2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/crypto/curve25519"

	i2pbase64 "github.com/go-i2p/common/base64"
)

// msg1WireDumpRemaining is decremented each time we hex-dump a msg1 wire
// payload. When NTCP2_DUMP_MSG1=N is set in the environment, the first N
// initiator handshakes will emit a one-shot hex dump of the AES key,
// AES IV, full 64-byte msg1, and the 16-byte cleartext options that were
// AEAD-encrypted into bytes 32-63. This is intended for one-shot
// interop debugging against i2pd / Java I2P; it is a no-op when the
// env var is unset or its budget is exhausted.
var (
	msg1WireDumpRemaining atomic.Int32
	msg3WireDumpRemaining atomic.Int32
)

func init() {
	if v := os.Getenv("NTCP2_DUMP_MSG1"); v != "" {
		var n int32
		for _, c := range v {
			if c < '0' || c > '9' {
				return
			}
			n = n*10 + int32(c-'0')
			if n > 1000 {
				n = 1000
				break
			}
		}
		msg1WireDumpRemaining.Store(n)
	}
	if v := os.Getenv("NTCP2_DUMP_MSG3"); v != "" {
		var n int32
		for _, c := range v {
			if c < '0' || c > '9' {
				return
			}
			n = n*10 + int32(c-'0')
			if n > 1000 {
				n = 1000
				break
			}
		}
		msg3WireDumpRemaining.Store(n)
	}
}

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
func (c *Conn) Handshake(ctx context.Context) error {
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
	var msg3Payload []byte
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
		msg3Payload, err = performResponderHandshake(cfg, nc)
	}
	if err != nil {
		nc.FailHandshake()
		return err
	}

	// On the responder side, store Alice's decrypted message-3 part-2 payload
	// (the I2NP block frame containing her RouterInfo) so the router transport
	// layer can parse it via PeerMessage3Payload() / PeerRouterInfoBytes().
	// Without this, the OBEP/responder has no way to learn Alice's NTCP2
	// address for direct delivery of replies (e.g. ShortTunnelBuildReply).
	if msg3Payload != nil {
		buf := make([]byte, len(msg3Payload))
		copy(buf, msg3Payload)
		c.peerMsg3Payload.Store(&buf)
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
func performInitiatorHandshake(cfg *Config, nc *noise.NoiseConn) error {
	riBytes := cfg.LocalRouterInfo
	// m3p2Len includes the block header (3B), flag byte (1B), RouterInfo bytes, and the AEAD tag (16B).
	// Per the NTCP2 spec, the RouterInfo block (type 2) data starts with a 1-byte flag field.
	m3p2Len := uint16(BlockHeaderSize + 1 + len(riBytes) + Poly1305Overhead)

	raw := nc.Underlying()

	// Defense-in-depth: verify the public key derived from our Noise static
	// private key actually appears in the LocalRouterInfo we are about to
	// send inside msg3. i2pd silently terminates the TCP connection (no
	// termination frame) if the static public key it received in msg1 does
	// not appear as the `s=` option of any NTCP2 address in the RouterInfo
	// we send in msg3 (libi2pd/NTCP2.cpp:690, RouterInfo.cpp:838). The
	// observable symptom is "frame #0 EOF" in the data phase. We log a
	// warning here so the misconfiguration is visible in production logs;
	// the authoritative fix lives in the caller (go-i2p/go-i2p) — see
	// PROMPT.md in this repo. Logging (not erroring) keeps existing tests
	// that use synthetic RouterInfo bytes working.
	if err := verifyLocalRouterInfoMatchesStaticKey(cfg.StaticKey, riBytes); err != nil {
		log.WithFields(logger.Fields{
			"pkg":   "ntcp2",
			"func":  "performInitiatorHandshake",
			"event": "static_key_ri_mismatch",
			"err":   err.Error(),
		}).Warn("LocalRouterInfo does not advertise the static key we will send in the Noise handshake; i2pd peers will silently close the TCP connection after msg3 (frame #0 EOF). See PROMPT.md.")
	}

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
	dumpMsg1IfEnabled(cfg, raw, opts1, msg1)
	if _, err := raw.Write(msg1); err != nil {
		return oops.Code("MSG1_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 1")
	}
	// padLen = 0: no cleartext padding appended after message 1.

	// === Message 2 (Bob -> Alice) ============================================
	// Split the read into a 1-byte probe + the remaining 63 bytes so we can
	// distinguish "peer rejected msg1 (closed before writing any byte)" from
	// "peer started msg2 then aborted (partial write)". This is critical
	// interop diagnostic info: the first case points at TCP-reachability or
	// msg1-AEAD problems, the second at msg2 framing on the responder side.
	buf2 := make([]byte, msg2Size)
	n1, err := io.ReadFull(raw, buf2[:1])
	if err != nil {
		classifyMsg2ReadFailure(cfg, raw, 0, err)
		return oops.Code("MSG2_NO_BYTES").In("ntcp2").
			With("bytes_read", 0).
			Wrapf(err, "peer closed connection without sending any msg2 bytes (msg1 likely rejected)")
	}
	if n2, err := io.ReadFull(raw, buf2[1:]); err != nil {
		classifyMsg2ReadFailure(cfg, raw, n1+n2, err)
		return oops.Code("MSG2_PARTIAL").In("ntcp2").
			With("bytes_read", n1+n2).
			With("bytes_expected", msg2Size).
			Wrapf(err, "peer started msg2 but closed after %d bytes", n1+n2)
	}
	bobOpts, err := nc.ReadHandshakeMsgFromBytes(handshake.PhaseExchange, buf2)
	if err != nil {
		return oops.Code("MSG2_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 2")
	}
	// Read and MixHash Bob's cleartext padding (bytes 2-3 of his options = padLen).
	// i2pd ALWAYS sends a random number of padding bytes (0..222) after msg2 and
	// MixHashes them into h before decrypting m3p1. We MUST mirror that or
	// m3p1 AEAD verification on i2pd's side fails, causing silent terminate.
	var bobPadLen int
	var bobOptsHex string
	if len(bobOpts) >= ntcp2OptionsSize {
		bobPadLen = int(binary.BigEndian.Uint16(bobOpts[2:4]))
		bobOptsHex = hex.EncodeToString(bobOpts[:ntcp2OptionsSize])
		if bobPadLen > 0 {
			pad := make([]byte, bobPadLen)
			if _, err := io.ReadFull(raw, pad); err != nil {
				return oops.Code("MSG2_PAD_READ_FAILED").In("ntcp2").
					Wrapf(err, "failed to read %d cleartext padding bytes after message 2", bobPadLen)
			}
			nc.MixHashData(pad)
		}
	}
	// Warn-level breadcrumb so we can correlate msg2 padding handling with the
	// downstream "frame #0 EOF" warning. If bob_padlen is consistently 0 in
	// production logs against i2pd peers, the padding is not being parsed
	// correctly (i2pd's CreateSessionCreatedMessage uses rand()%(287-64) so
	// a 0 value should be rare).
	log.WithFields(logger.Fields{
		"pkg":          "ntcp2",
		"func":         "performInitiatorHandshake",
		"event":        "msg2_processed",
		"bob_padlen":   bobPadLen,
		"bob_opts_len": len(bobOpts),
		"bob_opts_hex": bobOptsHex,
		"remote":       raw.RemoteAddr().String(),
	}).Warn("NTCP2 msg2 processed; bob padlen extracted")

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
	dumpMsg3IfEnabled(cfg, raw, msg3, riBytes, m3p2Len)
	if _, err := raw.Write(msg3); err != nil {
		return oops.Code("MSG3_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 3")
	}
	// Emit a Warn-level breadcrumb at msg3 send so we can correlate with the
	// data-phase reader's "frame #0 EOF" warning. If the two warnings are
	// adjacent in the log, the peer rejected msg3 immediately (silent
	// Terminate after AEAD/block check). If they are seconds apart, the peer
	// accepted msg3 and closed later for an unrelated reason. See
	// libi2pd/NTCP2.cpp:634 (HandleSessionConfirmedReceived).
	log.WithFields(logger.Fields{
		"pkg":      "ntcp2",
		"func":     "performInitiatorHandshake",
		"event":    "msg3_sent",
		"msg3_len": len(msg3),
		"m3p1_len": msg3Part1Size,
		"m3p2_len": int(m3p2Len),
		"ri_len":   len(riBytes),
		"remote":   fmt.Sprintf("%v", raw.RemoteAddr()),
		"sent_ns":  time.Now().UnixNano(),
	}).Warn("NTCP2 msg3 written to wire; awaiting first data-phase frame")
	return nil
}

// performResponderHandshake executes the three-message NTCP2 XK exchange
// from the responder's (Bob's) perspective. On success it returns the
// decrypted message-3 part-2 plaintext, which is the I2NP block frame
// containing Alice's RouterInfo (and any optional padding/options blocks
// per the NTCP2 spec). The caller is responsible for parsing and storing
// it for the router transport layer.
func performResponderHandshake(cfg *Config, nc *noise.NoiseConn) ([]byte, error) {
	raw := nc.Underlying()

	// === Message 1 (Alice -> Bob) ============================================
	buf1 := make([]byte, msg1Size)
	if _, err := io.ReadFull(raw, buf1); err != nil {
		return nil, oops.Code("MSG1_READ_FAILED").In("ntcp2").
			Wrapf(err, "failed to read NTCP2 message 1")
	}
	aliceOpts, err := nc.ReadHandshakeMsgFromBytes(handshake.PhaseInitial, buf1)
	if err != nil {
		dumpInboundMsg1IfEnabled(cfg, raw, buf1, nil, err)
		return nil, oops.Code("MSG1_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 1")
	}
	dumpInboundMsg1IfEnabled(cfg, raw, buf1, aliceOpts, nil)
	// Parse Alice's options to extract padLen (bytes 2-3) and m3p2Len (bytes 4-5).
	if len(aliceOpts) < ntcp2OptionsSize {
		return nil, oops.Code("MSG1_OPTIONS_TOO_SHORT").In("ntcp2").
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
			return nil, oops.Code("MSG1_PAD_READ_FAILED").In("ntcp2").
				Wrapf(err, "failed to read %d cleartext padding bytes after message 1", alicePadLen)
		}
		nc.MixHashData(pad)
	}

	// === Message 2 (Bob -> Alice) ============================================
	opts2 := buildMessage2Options()
	msg2, err := nc.WriteHandshakeMsgToBytes(handshake.PhaseExchange, opts2)
	if err != nil {
		return nil, oops.Code("MSG2_WRITE_FAILED").In("ntcp2").
			Wrapf(err, "failed to build NTCP2 message 2")
	}
	if len(msg2) != msg2Size {
		return nil, oops.Code("MSG2_SIZE_MISMATCH").In("ntcp2").
			Errorf("expected message 2 to be %d bytes, got %d", msg2Size, len(msg2))
	}
	if _, err := raw.Write(msg2); err != nil {
		return nil, oops.Code("MSG2_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 2")
	}
	// padLen = 0: no cleartext padding appended after message 2 for now.

	// === Message 3 (Alice -> Bob) ============================================
	msg3Len := msg3Part1Size + int(m3p2Len)
	buf3 := make([]byte, msg3Len)
	if _, err := io.ReadFull(raw, buf3); err != nil {
		return nil, oops.Code("MSG3_READ_FAILED").In("ntcp2").
			Wrapf(err, "failed to read NTCP2 message 3 (%d bytes)", msg3Len)
	}
	payload, err := nc.ReadHandshakeMsgFromBytes(handshake.PhaseFinal, buf3)
	if err != nil {
		return nil, oops.Code("MSG3_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 3")
	}

	// Return the decrypted message-3 part-2 plaintext to the caller. This is
	// the I2NP block frame containing Alice's RouterInfo (block type 2) and
	// any optional padding/options blocks. The router transport layer needs
	// this to learn Alice's NTCP2 address for direct reply delivery (e.g.
	// ShortTunnelBuildReply for 1-hop outbound tunnels).
	return payload, nil
}

// buildMessage2Options constructs the 16-byte options block sent as the
// AEAD payload in NTCP2 message 2 (Bob -> Alice).
//
// Wire layout (all fields big-endian) — spec: https://spec.i2p.net/ntcp2#options:
//
//	bytes 0-1  : Reserved = 0   (NOT id/ver — those fields are message 1 only)
//	bytes 2-3  : padLen = 0     (no cleartext padding for MVP)
//	bytes 4-7  : Reserved = 0
//	bytes 8-11 : tsB            (Bob's Unix timestamp, big-endian uint32)
//	bytes 12-15: Reserved = 0
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

// rawConn is the minimum surface needed by dumpMsg1IfEnabled to identify
// the remote peer. We accept any value that exposes RemoteAddr() and
// LocalAddr() to avoid importing net here just for the type assertion.
type rawConn interface {
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
}

// dumpMsg1IfEnabled emits a one-shot hex dump of every cryptographic input
// to NTCP2 message 1 plus the final 64-byte wire payload. It is intended for
// interop debugging against i2pd / Java I2P when peers reject our message 1.
//
// Activation: set NTCP2_DUMP_MSG1=N (positive integer) in the environment.
// The next N initiator handshakes will dump; subsequent handshakes are silent.
//
// Output goes through the structured logger at Info level. The dump exposes
// the peer's published router hash and IV (both already public via netDb)
// and the encrypted msg1 bytes (visible on the wire). It does NOT expose any
// private key material.
func dumpMsg1IfEnabled(cfg *Config, raw interface{}, opts1, msg1 []byte) {
	if msg1WireDumpRemaining.Load() <= 0 {
		return
	}
	if msg1WireDumpRemaining.Add(-1) < 0 {
		return
	}
	fields := logger.Fields{
		"pkg":           "ntcp2",
		"func":          "dumpMsg1IfEnabled",
		"aes_key":       hex.EncodeToString(cfg.BobRouterHash[:]),
		"aes_iv":        hex.EncodeToString(cfg.ObfuscationIV),
		"remote_s":      hex.EncodeToString(cfg.RemoteStaticKey),
		"opts_clear":    hex.EncodeToString(opts1),
		"msg1_wire":     hex.EncodeToString(msg1),
		"msg1_x_obf":    hex.EncodeToString(msg1[:32]),
		"msg1_aead_ct":  hex.EncodeToString(msg1[32:]),
		"local_ri_len":  len(cfg.LocalRouterInfo),
		"protocol_name": NTCP2ProtocolName,
	}
	if rc, ok := raw.(rawConn); ok && rc != nil {
		if a := rc.RemoteAddr(); a != nil {
			fields["peer"] = a.String()
		}
		if a := rc.LocalAddr(); a != nil {
			fields["local"] = a.String()
		}
	}
	log.WithFields(fields).Info("NTCP2 msg1 wire dump (one-shot interop debug)")
}

// dumpInboundMsg1IfEnabled emits a one-shot hex dump of an inbound NTCP2
// message 1 from the responder's perspective. Useful for diagnosing rejected
// peer connections (where decryptedOpts is nil and decryptErr is set) or
// confirming what i2pd actually sends. Shares the NTCP2_DUMP_MSG1 budget
// with the initiator-side dumper.
func dumpInboundMsg1IfEnabled(cfg *Config, raw interface{}, buf1, decryptedOpts []byte, decryptErr error) {
	if msg1WireDumpRemaining.Load() <= 0 {
		return
	}
	if msg1WireDumpRemaining.Add(-1) < 0 {
		return
	}
	fields := logger.Fields{
		"pkg":       "ntcp2",
		"func":      "dumpInboundMsg1IfEnabled",
		"aes_key":   hex.EncodeToString(cfg.BobRouterHash[:]),
		"aes_iv":    hex.EncodeToString(cfg.ObfuscationIV),
		"msg1_wire": hex.EncodeToString(buf1),
	}
	if len(decryptedOpts) > 0 {
		fields["opts_clear"] = hex.EncodeToString(decryptedOpts)
		fields["status"] = "decrypted_ok"
	}
	if decryptErr != nil {
		fields["status"] = "decrypt_failed"
		fields["err"] = decryptErr.Error()
	}
	if rc, ok := raw.(rawConn); ok && rc != nil {
		if a := rc.RemoteAddr(); a != nil {
			fields["peer"] = a.String()
		}
		if a := rc.LocalAddr(); a != nil {
			fields["local"] = a.String()
		}
	}
	log.WithFields(fields).Info("NTCP2 inbound msg1 wire dump (one-shot interop debug)")
}

// classifyMsg2ReadFailure logs a structured classification of a failed
// msg2 read so we can distinguish between three interop failure modes:
//
//  1. bytes_read == 0 + io.EOF:         peer accepted TCP but rejected msg1
//     silently (most likely AEAD failure
//     on their side, or msg1 framing bug).
//  2. bytes_read == 0 + ECONNRESET:     peer sent RST without writing
//     (firewall, banlist, version policy).
//  3. bytes_read in 1..63 + EOF/RST:    peer started msg2 then aborted
//     (msg2 construction bug on their side
//     or our side closing prematurely).
//
// Always logged (not gated by NTCP2_DUMP_MSG1) because it is cheap and the
// most actionable signal for live interop debugging.
func classifyMsg2ReadFailure(cfg *Config, raw interface{}, bytesRead int, err error) {
	var category string
	switch {
	case bytesRead == 0 && errors.Is(err, io.EOF):
		category = "peer_closed_silently_after_msg1"
	case bytesRead == 0:
		category = "peer_reset_after_msg1"
	case bytesRead < msg2Size:
		category = "peer_truncated_msg2"
	default:
		category = "unknown"
	}
	fields := logger.Fields{
		"pkg":        "ntcp2",
		"func":       "classifyMsg2ReadFailure",
		"event":      "msg2_read_failure",
		"category":   category,
		"bytes_read": bytesRead,
		"bytes_want": msg2Size,
		"err":        err.Error(),
	}
	if cfg != nil && cfg.RemoteRouterHash != nil {
		fields["peer_hash_b64"] = base64.StdEncoding.EncodeToString(cfg.RemoteRouterHash[:])
	}
	if rc, ok := raw.(rawConn); ok && rc != nil {
		if a := rc.RemoteAddr(); a != nil {
			fields["peer"] = a.String()
		}
		if a := rc.LocalAddr(); a != nil {
			fields["local"] = a.String()
		}
	}
	log.WithFields(fields).Warn("NTCP2 msg2 read failed (interop diagnostic)")
}

// verifyLocalRouterInfoMatchesStaticKey is a defense-in-depth check that
// verifies the public key derived from staticPriv (32-byte Curve25519 scalar)
// is actually advertised in riBytes (a serialized RouterInfo).
//
// The check is intentionally cheap: it derives the public key, encodes it
// using i2p-base64 (the encoding used in RouterAddress option mappings),
// and substring-scans riBytes for that 43-character text.
//
// This avoids depending on the full RouterInfo parser (which would create a
// dep cycle: go-noise is below go-i2p in the layer stack). The trade-off is
// that this can produce a false negative if i2p-base64 substring happens to
// appear elsewhere in the RI by coincidence (probability ≈ 2^-258, ignorable).
//
// staticPriv == nil or len != 32 returns nil (no-op): the caller is responsible
// for static-key length validation elsewhere; this helper exists only to
// catch the specific mismatch failure mode and not to second-guess validation.
//
// riBytes == nil or len == 0 also returns nil: caller checks for that
// (msg3 will fail later with a clearer error).
func verifyLocalRouterInfoMatchesStaticKey(staticPriv, riBytes []byte) error {
	if len(staticPriv) != StaticKeySize {
		return nil
	}
	if len(riBytes) == 0 {
		return nil
	}
	pub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return oops.Wrapf(err, "failed to derive Curve25519 public key from static private key")
	}
	pubB64 := i2pbase64.EncodeToString(pub)
	if bytes.Contains(riBytes, []byte(pubB64)) {
		return nil
	}
	return oops.
		With("derived_public_key_b64", pubB64).
		With("ri_bytes_len", len(riBytes)).
		Errorf("derived public key from live NTCP2 static private key does not " +
			"appear in serialized LocalRouterInfo (no NTCP2 address publishes " +
			"this key as its `s=` option)")
}

// dumpMsg3IfEnabled emits a one-shot hex dump of the NTCP2 message 3 wire
// payload (m3p1 + m3p2) plus the inner RouterInfo bytes that were just
// AEAD-encrypted into m3p2. Activation: NTCP2_DUMP_MSG3=N. The dump exposes
// only data already on the wire (after AEAD encryption) and the local
// RouterInfo bytes (which we publish to the netDb anyway). It does NOT
// expose any private key material or the data-phase keys.
func dumpMsg3IfEnabled(cfg *Config, raw interface{}, msg3, riBytes []byte, m3p2Len uint16) {
	if msg3WireDumpRemaining.Load() <= 0 {
		return
	}
	if msg3WireDumpRemaining.Add(-1) < 0 {
		return
	}
	var remote, local string
	if rc, ok := raw.(rawConn); ok {
		if a := rc.RemoteAddr(); a != nil {
			remote = a.String()
		}
		if a := rc.LocalAddr(); a != nil {
			local = a.String()
		}
	}
	m3p1End := msg3Part1Size
	if m3p1End > len(msg3) {
		m3p1End = len(msg3)
	}
	log.WithFields(logger.Fields{
		"pkg":      "ntcp2",
		"func":     "dumpMsg3IfEnabled",
		"event":    "ntcp2_msg3_wire_dump",
		"remote":   remote,
		"local":    local,
		"msg3_len": len(msg3),
		"m3p1_len": msg3Part1Size,
		"m3p2_len": int(m3p2Len),
		"ri_len":   len(riBytes),
		"m3p1_hex": hex.EncodeToString(msg3[:m3p1End]),
		"m3p2_hex": hex.EncodeToString(msg3[m3p1End:]),
		"ri_hex":   hex.EncodeToString(riBytes),
		"sent_ns":  time.Now().UnixNano(),
	}).Info("NTCP2 msg3 hex dump (wire bytes about to be written)")
	_ = cfg
}
