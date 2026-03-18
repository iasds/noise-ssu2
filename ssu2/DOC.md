# ssu2
--
    import "github.com/go-i2p/go-noise/ssu2"

![ssu2.svg](ssu2.svg)



## Usage

#### type ChaChaObfuscationModifier

```go
type ChaChaObfuscationModifier struct {
}
```

ChaChaObfuscationModifier implements SSU2's ChaCha20-based ephemeral key
obfuscation. This modifier encrypts/decrypts the X and Y ephemeral keys in
messages 1 and 2 using ChaCha20 stream cipher with the router hash as key and
published IV. Key differences from NTCP2's AES: 8-byte IV, XOR-based stream
cipher vs block cipher.

#### func  NewChaChaObfuscationModifier

```go
func NewChaChaObfuscationModifier(name string, routerHash, iv []byte) (*ChaChaObfuscationModifier, error)
```
NewChaChaObfuscationModifier creates a new ChaCha20 obfuscation modifier for
SSU2. routerHash must be 32 bytes (RH_B), iv must be 8 bytes from network
database. Returns error if parameters are invalid.

#### func (*ChaChaObfuscationModifier) ModifyInbound

```go
func (com *ChaChaObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound removes ChaCha20 obfuscation from ephemeral keys in handshake
messages. ChaCha20 is symmetric (XOR-based), so encryption and decryption are
identical.

#### func (*ChaChaObfuscationModifier) ModifyOutbound

```go
func (com *ChaChaObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound applies ChaCha20 obfuscation to ephemeral keys in handshake
messages. Message 1: XOR X key with ChaCha20(routerHash, iv) Message 2: XOR Y
key with ChaCha20(routerHash, derived_iv) Message 3+: No obfuscation (like
NTCP2)

#### func (*ChaChaObfuscationModifier) Name

```go
func (com *ChaChaObfuscationModifier) Name() string
```
Name returns the modifier name for logging and debugging.



ssu2 

github.com/go-i2p/go-noise/ssu2

[go-i2p template file](/template.md)
