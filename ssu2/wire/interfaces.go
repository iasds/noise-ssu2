package wire

// BlockHandler defines the interface for processing SSU2 blocks.
// Implementations handle specific block types or categories.
// *BlockRouter satisfies this interface for dispatch, while custom
// implementations can handle individual block types.
type BlockHandler interface {
	// HandleBlock processes a block and returns true if handled successfully.
	// If the handler cannot process this block type, it should return false,
	// allowing the router to try the next registered handler.
	HandleBlock(block *SSU2Block) (handled bool, err error)

	// SupportedTypes returns the block types this handler processes.
	SupportedTypes() []uint8
}

// BlockHandlerFunc is a function adapter for BlockHandler.
// It wraps a plain function as a BlockHandler.
type BlockHandlerFunc func(block *SSU2Block) (bool, error)
