package reliability

import "github.com/go-i2p/go-noise/ssu2/wire"

// Type aliases from ssu2/wire so reliability code can reference these types
// without qualifying them with the wire package name.
type SSU2Block = wire.SSU2Block
type SSU2Packet = wire.SSU2Packet

// Packet size constants
const (
	MaxPacketSizeIPv4 = wire.MaxPacketSizeIPv4
	MaxPacketSizeIPv6 = wire.MaxPacketSizeIPv6
)

// Block type constants
const (
	BlockTypeACK        = wire.BlockTypeACK
	BlockTypeCongestion = wire.BlockTypeCongestion
	BlockTypePadding    = wire.BlockTypePadding
)

// Constructor aliases
var NewSSU2Block = wire.NewSSU2Block
