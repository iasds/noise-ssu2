package internal

import (
	"encoding/binary"
	"testing"

	"github.com/go-i2p/go-noise/handshake"
)

// --- SipHashNextMask tests ---

func TestSipHashNextMask_DeterministicChain(t *testing.T) {
	// Same keys/IV must produce the same mask sequence.
	keys := [2]uint64{0x0706050403020100, 0x0F0E0D0C0B0A0908}
	iv1 := uint64(0)
	iv2 := uint64(0)

	for i := 0; i < 20; i++ {
		m1 := SipHashNextMask(keys, &iv1)
		m2 := SipHashNextMask(keys, &iv2)
		if m1 != m2 {
			t.Fatalf("iteration %d: deterministic mismatch %d != %d", i, m1, m2)
		}
	}
}

func TestSipHashNextMask_IVAdvances(t *testing.T) {
	keys := [2]uint64{0x0706050403020100, 0x0F0E0D0C0B0A0908}
	iv := uint64(0)

	SipHashNextMask(keys, &iv)
	if iv == 0 {
		t.Fatal("IV was not updated after SipHashNextMask call")
	}
}

func TestSipHashNextMask_MaskIsLow16Bits(t *testing.T) {
	keys := [2]uint64{0xDEADBEEF, 0xCAFEBABE}
	iv := uint64(42)

	// Compute the expected full hash manually.
	var input [8]byte
	binary.LittleEndian.PutUint64(input[:], iv)

	mask := SipHashNextMask(keys, &iv)
	// mask must equal low 16 bits of the new IV (which is the hash output).
	expected := uint16(iv & 0xFFFF)
	if mask != expected {
		t.Errorf("mask = 0x%04X, want low 16 of IV = 0x%04X", mask, expected)
	}
}

func TestSipHashNextMask_DifferentKeysProduceDifferentMasks(t *testing.T) {
	keys1 := [2]uint64{0x1111111111111111, 0x2222222222222222}
	keys2 := [2]uint64{0x3333333333333333, 0x4444444444444444}
	iv1 := uint64(0)
	iv2 := uint64(0)

	m1 := SipHashNextMask(keys1, &iv1)
	m2 := SipHashNextMask(keys2, &iv2)
	if m1 == m2 {
		t.Error("different keys produced the same mask — extremely unlikely")
	}
}

func TestSipHashNextMask_ChainedSequenceNotConstant(t *testing.T) {
	keys := [2]uint64{0x0706050403020100, 0x0F0E0D0C0B0A0908}
	iv := uint64(0)

	seen := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		mask := SipHashNextMask(keys, &iv)
		seen[mask] = true
	}
	// With 100 iterations over a 16-bit space, we expect many distinct values.
	if len(seen) < 50 {
		t.Errorf("only %d distinct masks in 100 iterations — expected more variation", len(seen))
	}
}

// --- SipHashLengthModifier tests ---

func TestSipHashLengthModifier_RoundTrip(t *testing.T) {
	keys := [2]uint64{0xAAAAAAAAAAAAAAAA, 0xBBBBBBBBBBBBBBBB}
	iv := uint64(0)

	sender := NewSipHashLengthModifier("test", keys, iv)
	receiver := NewSipHashLengthModifier("test", keys, iv)

	for i := 0; i < 50; i++ {
		original := uint16(1000 + i*13)
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, original)

		obfuscated, err := sender.ModifyOutbound(handshake.PhaseData, data)
		if err != nil {
			t.Fatalf("iteration %d: ModifyOutbound error: %v", i, err)
		}

		recovered, err := receiver.ModifyInbound(handshake.PhaseData, obfuscated)
		if err != nil {
			t.Fatalf("iteration %d: ModifyInbound error: %v", i, err)
		}

		got := binary.BigEndian.Uint16(recovered)
		if got != original {
			t.Fatalf("iteration %d: round-trip failed, got %d want %d", i, got, original)
		}
	}
}

func TestSipHashLengthModifier_DirectionalRoundTrip(t *testing.T) {
	outKeys := [2]uint64{0x1111111111111111, 0x2222222222222222}
	inKeys := [2]uint64{0x3333333333333333, 0x4444444444444444}
	outIV := uint64(100)
	inIV := uint64(200)

	// Sender's outbound == receiver's inbound, and vice versa.
	sender := NewSipHashLengthModifierDirectional("s", outKeys, inKeys, outIV, inIV)
	receiver := NewSipHashLengthModifierDirectional("r", inKeys, outKeys, inIV, outIV)

	for i := 0; i < 30; i++ {
		original := uint16(500 + i)
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, original)

		obfuscated, err := sender.ModifyOutbound(handshake.PhaseData, data)
		if err != nil {
			t.Fatalf("iteration %d: ModifyOutbound error: %v", i, err)
		}

		recovered, err := receiver.ModifyInbound(handshake.PhaseData, obfuscated)
		if err != nil {
			t.Fatalf("iteration %d: ModifyInbound error: %v", i, err)
		}

		got := binary.BigEndian.Uint16(recovered)
		if got != original {
			t.Fatalf("iteration %d: directional round-trip failed, got %d want %d", i, got, original)
		}
	}
}

func TestSipHashLengthModifier_PassthroughBeforeFinal(t *testing.T) {
	keys := [2]uint64{0xDEAD, 0xBEEF}
	mod := NewSipHashLengthModifier("test", keys, 0)

	original := []byte{0x01, 0x02}

	// Phases before PhaseData should pass data through unmodified.
	phases := []handshake.HandshakePhase{
		handshake.PhaseInitial,
		handshake.PhaseExchange,
		handshake.PhaseFinal,
	}
	for _, phase := range phases {
		out, err := mod.ModifyOutbound(phase, original)
		if err != nil {
			t.Fatalf("phase %d ModifyOutbound error: %v", phase, err)
		}
		if out[0] != original[0] || out[1] != original[1] {
			t.Errorf("phase %d: expected passthrough, got %v", phase, out)
		}
	}
}

func TestSipHashLengthModifier_WrongLengthPassthrough(t *testing.T) {
	keys := [2]uint64{0xDEAD, 0xBEEF}
	mod := NewSipHashLengthModifier("test", keys, 0)

	// Data that is not exactly 2 bytes should pass through unmodified.
	data := []byte{0x01, 0x02, 0x03}
	out, err := mod.ModifyOutbound(handshake.PhaseData, data)
	if err != nil {
		t.Fatalf("ModifyOutbound error: %v", err)
	}
	if len(out) != len(data) {
		t.Errorf("expected passthrough for 3-byte input, got len %d", len(out))
	}
}

func TestSipHashLengthModifier_Name(t *testing.T) {
	mod := NewSipHashLengthModifier("my-modifier", [2]uint64{}, 0)
	if mod.Name() != "my-modifier" {
		t.Errorf("Name() = %q, want %q", mod.Name(), "my-modifier")
	}
}

func TestSipHashLengthModifier_ZeroKeys(t *testing.T) {
	keys := [2]uint64{0x1234, 0x5678}
	mod := NewSipHashLengthModifier("test", keys, 42)

	mod.ZeroKeys()

	if k := mod.PeekOutboundKeys(); k[0] != 0 || k[1] != 0 {
		t.Error("outbound keys not zeroed")
	}
	if k := mod.PeekInboundKeys(); k[0] != 0 || k[1] != 0 {
		t.Error("inbound keys not zeroed")
	}
	if mod.PeekOutboundIV() != 0 || mod.PeekInboundIV() != 0 {
		t.Error("IVs not zeroed")
	}
}

func TestSipHashLengthModifier_Close(t *testing.T) {
	mod := NewSipHashLengthModifier("test", [2]uint64{0xAA, 0xBB}, 99)
	if err := mod.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if k := mod.PeekOutboundKeys(); k[0] != 0 {
		t.Error("Close did not zero key material")
	}
	if mod.PeekInboundIV() != 0 {
		t.Error("Close did not zero IV")
	}
}

func TestSipHashLengthModifier_NextMaskMethods(t *testing.T) {
	keys := [2]uint64{0xAAAA, 0xBBBB}
	mod := NewSipHashLengthModifier("test", keys, 0)

	// Public NextOutboundMask/NextInboundMask should advance independently.
	out1 := mod.NextOutboundMask()
	out2 := mod.NextOutboundMask()
	in1 := mod.NextInboundMask()

	// First inbound mask should equal first outbound mask (same keys/IV).
	if in1 != out1 {
		t.Errorf("first inbound mask %d != first outbound mask %d (same initial state)", in1, out1)
	}
	// Second outbound mask should differ from first (chain advances).
	if out1 == out2 {
		t.Log("consecutive masks are equal — possible but unlikely")
	}
}
