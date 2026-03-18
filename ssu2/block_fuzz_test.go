package ssu2

import (
	"encoding/binary"
	"testing"
)

// FuzzSSU2Block_Deserialize fuzzes the SSU2Block deserialization.
// It ensures the deserialize function handles malformed input gracefully
// without panicking or causing memory corruption.
//
// Run with: go test -fuzz=FuzzSSU2Block_Deserialize ./ssu2/
func FuzzSSU2Block_Deserialize(f *testing.F) {
	// Add seed corpus with valid and boundary cases
	// Empty block
	f.Add([]byte{})

	// Too short for header
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x00})

	// Valid header but no data (type 1, length 0)
	f.Add([]byte{0x01, 0x00, 0x00})

	// Valid DateTimeBlock (type 4, length 4)
	f.Add([]byte{0x04, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04})

	// Valid OptionsBlock (type 5, length 8)
	f.Add([]byte{0x05, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	// Length overflow - says 255 bytes but only has 3
	f.Add([]byte{0x01, 0xFF, 0x00, 0x01, 0x02, 0x03})

	// Maximum length header
	f.Add([]byte{0x01, 0xFF, 0xFF})

	// Valid RouterInfo block (type 6)
	ri := make([]byte, 51)
	ri[0] = 0x06 // Type
	ri[1] = 0x30 // Length low byte (48)
	ri[2] = 0x00 // Length high byte
	f.Add(ri)

	// Valid I2NP block (type 1)
	i2np := make([]byte, 20)
	i2np[0] = 0x01
	i2np[1] = 0x11
	i2np[2] = 0x00
	f.Add(i2np)

	// Padding block (type 254)
	padding := make([]byte, 10)
	padding[0] = 0xFE
	padding[1] = 0x07
	padding[2] = 0x00
	f.Add(padding)

	// Termination block (type 3)
	term := make([]byte, 15)
	term[0] = 0x03
	term[1] = 0x0C
	term[2] = 0x00
	f.Add(term)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		_, err := block.Deserialize(data)

		// We only care about panics and crashes, errors are expected
		// for malformed input
		if err == nil && len(data) >= 3 {
			// If decode succeeded, verify it's internally consistent
			if len(block.Data) > 0 {
				// Try to serialize and check it doesn't panic
				_, _ = block.Serialize()
			}
		}
	})
}

// FuzzDeserializeBlocks fuzzes the multi-block deserialization.
func FuzzDeserializeBlocks(f *testing.F) {
	// Valid single block
	f.Add([]byte{0x01, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04})

	// Two blocks back-to-back
	twoBlocks := []byte{
		0x04, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, // DateTime
		0xFE, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
	}
	f.Add(twoBlocks)

	// Block chain with different types
	chain := make([]byte, 30)
	chain[0] = 0x04 // DateTime
	chain[1] = 0x04
	chain[2] = 0x00
	chain[7] = 0x02 // ACK
	chain[8] = 0x08
	chain[9] = 0x00
	f.Add(chain)

	// Truncated second block
	f.Add([]byte{0x01, 0x01, 0x00, 0xFF, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		// DeserializeBlocks should not panic
		blocks, err := DeserializeBlocks(data)

		// If successful, verify each block is valid
		if err == nil && len(blocks) > 0 {
			for _, block := range blocks {
				if block != nil {
					// Serialize should not panic
					_, _ = block.Serialize()
				}
			}
		}
	})
}

// FuzzDecodeRelayRequest fuzzes RelayRequest block decoding.
func FuzzDecodeRelayRequest(f *testing.F) {
	// Valid relay request: nonce(4) + tag(4) + hash(32) = 40 minimum
	valid := make([]byte, 43)
	valid[0] = BlockTypeRelayRequest
	binary.BigEndian.PutUint16(valid[1:3], 40)
	binary.BigEndian.PutUint32(valid[3:7], 12345)  // Nonce
	binary.BigEndian.PutUint32(valid[7:11], 67890) // RelayTag
	f.Add(valid)

	// With token appended
	withToken := make([]byte, 58)
	copy(withToken, valid)
	binary.BigEndian.PutUint16(withToken[1:3], 55) // Larger length
	f.Add(withToken)

	// Wrong type
	wrongType := make([]byte, 43)
	wrongType[0] = 0xFF
	binary.BigEndian.PutUint16(wrongType[1:3], 40)
	f.Add(wrongType)

	// Too short
	f.Add([]byte{BlockTypeRelayRequest, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05})

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return // Can't decode base block
		}

		// Try to decode as RelayRequest - should not panic
		_, _ = DecodeRelayRequest(block)
	})
}

// FuzzDecodeRelayResponse fuzzes RelayResponse block decoding.
func FuzzDecodeRelayResponse(f *testing.F) {
	// Valid relay response: nonce(4) + status(1) + addr_type(1) + addr
	valid := make([]byte, 15)
	valid[0] = BlockTypeRelayResponse
	binary.BigEndian.PutUint16(valid[1:3], 12) // Length
	binary.BigEndian.PutUint32(valid[3:7], 12345)
	valid[7] = 0                                   // Success status
	valid[8] = 0x04                                // IPv4
	copy(valid[9:13], []byte{192, 168, 1, 1})      // IP
	binary.BigEndian.PutUint16(valid[13:15], 5555) // Port
	f.Add(valid)

	// IPv6 response
	validV6 := make([]byte, 27)
	validV6[0] = BlockTypeRelayResponse
	binary.BigEndian.PutUint16(validV6[1:3], 24) // Length
	binary.BigEndian.PutUint32(validV6[3:7], 12345)
	validV6[7] = 0    // Success
	validV6[8] = 0x06 // IPv6
	f.Add(validV6)

	// Failure response (no address)
	failure := make([]byte, 8)
	failure[0] = BlockTypeRelayResponse
	binary.BigEndian.PutUint16(failure[1:3], 5)
	failure[7] = 1 // Failure status
	f.Add(failure)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodeRelayResponse(block)
	})
}

// FuzzDecodeRelayIntro fuzzes RelayIntro block decoding.
func FuzzDecodeRelayIntro(f *testing.F) {
	// Valid relay intro: hash(32) + tag(4) + timestamp(4) + addr
	valid := make([]byte, 52)
	valid[0] = BlockTypeRelayIntro
	binary.BigEndian.PutUint16(valid[1:3], 49) // Length
	copy(valid[3:35], make([]byte, 32))        // Router hash
	binary.BigEndian.PutUint32(valid[35:39], 12345)
	binary.BigEndian.PutUint32(valid[39:43], 1234567890)
	valid[43] = 0x04                               // IPv4
	copy(valid[44:48], []byte{10, 0, 0, 1})        // IP
	binary.BigEndian.PutUint16(valid[48:50], 8080) // Port
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodeRelayIntro(block)
	})
}

// FuzzDecodePeerTestBlock fuzzes PeerTest block decoding.
func FuzzDecodePeerTestBlock(f *testing.F) {
	// Minimal peer test block
	valid := make([]byte, 20)
	valid[0] = BlockTypePeerTest
	binary.BigEndian.PutUint16(valid[1:3], 17)
	valid[3] = 1 // Message code
	f.Add(valid)

	// With signature
	withSig := make([]byte, 84)
	withSig[0] = BlockTypePeerTest
	binary.BigEndian.PutUint16(withSig[1:3], 81)
	withSig[3] = 1 // Message code
	f.Add(withSig)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodePeerTestBlock(block)
	})
}

// FuzzDecodeRelayTag fuzzes RelayTag block decoding.
func FuzzDecodeRelayTag(f *testing.F) {
	// Valid relay tag: tag(4) + expiration(4)
	valid := make([]byte, 11)
	valid[0] = BlockTypeRelayTag
	binary.BigEndian.PutUint16(valid[1:3], 8)
	binary.BigEndian.PutUint32(valid[3:7], 0x12345678)
	binary.BigEndian.PutUint32(valid[7:11], 3600)
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodeRelayTag(block)
	})
}

// FuzzDecodeRelayTagRequest fuzzes RelayTagRequest block decoding.
func FuzzDecodeRelayTagRequest(f *testing.F) {
	// Valid relay tag request: nonce(4)
	valid := make([]byte, 7)
	valid[0] = BlockTypeRelayTagRequest
	binary.BigEndian.PutUint16(valid[1:3], 4)
	binary.BigEndian.PutUint32(valid[3:7], 0xDEADBEEF)
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodeRelayTagRequest(block)
	})
}

// FuzzDecodePathChallenge fuzzes PathChallenge block decoding.
func FuzzDecodePathChallenge(f *testing.F) {
	// Valid path challenge: nonce(8)
	valid := make([]byte, 11)
	valid[0] = BlockTypePathChallenge
	binary.BigEndian.PutUint16(valid[1:3], 8)
	binary.BigEndian.PutUint64(valid[3:11], 0x123456789ABCDEF0)
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodePathChallenge(block)
	})
}

// FuzzDecodePathResponse fuzzes PathResponse block decoding.
func FuzzDecodePathResponse(f *testing.F) {
	// Valid path response: nonce(8)
	valid := make([]byte, 11)
	valid[0] = BlockTypePathResponse
	binary.BigEndian.PutUint16(valid[1:3], 8)
	binary.BigEndian.PutUint64(valid[3:11], 0x123456789ABCDEF0)
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodePathResponse(block)
	})
}
