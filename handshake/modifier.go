package handshake

// HandshakeModifier transforms data during any phase of a Noise connection,
// providing obfuscation and padding capabilities. Modifiers can be chained to
// create complex transformations while maintaining Noise protocol security.
//
// Implementations must be safe for concurrent calls to ModifyOutbound and
// ModifyInbound from separate goroutines (e.g. read and write pumps on the same
// connection). Stateless implementations are safe by construction; stateful ones
// must protect mutable fields with a mutex.
type HandshakeModifier interface {
	// ModifyOutbound modifies data being sent during any phase of the connection.
	ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error)

	// ModifyInbound modifies data being received during any phase of the connection.
	ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error)

	// Name returns the modifier name for logging and debugging.
	Name() string

	// Close releases any resources held by the modifier and zeroes sensitive key
	// material. It must be called when the connection is torn down.
	// Implementations that hold no key material should return nil.
	// ModifierChain.Close() propagates Close() to all chained members.
	Close() error
}

// ModifierCloner is an optional interface that HandshakeModifier implementations
// can implement to support deep copying. If a modifier holds mutable state
// (e.g., configuration, statistics), it should implement Clone to return an
// independent copy. Config.Clone() will attempt to deep-copy modifiers that
// implement this interface; otherwise, the modifier reference is shared between
// the original and cloned config.
type ModifierCloner interface {
	HandshakeModifier
	Clone() HandshakeModifier
}
