// Package session: type aliases for types from ssu2 sub-packages.
// This file re-exports all external ssu2 types used within this package so
// that the implementation files need only change their package declaration.
package session

import (
	ssu2config "github.com/go-i2p/go-noise/ssu2/config"
	ssu2hs "github.com/go-i2p/go-noise/ssu2/handshake"
	"github.com/go-i2p/go-noise/ssu2/path"
	"github.com/go-i2p/go-noise/ssu2/reliability"
	"github.com/go-i2p/go-noise/ssu2/wire"
)

// ─── From ssu2/config ─────────────────────────────────────────────────────────

type SSU2Config = ssu2config.SSU2Config
type SSU2Addr = ssu2config.SSU2Addr

var (
	NewSSU2Config        = ssu2config.NewSSU2Config
	NewSSU2Addr          = ssu2config.NewSSU2Addr
	NewMockSSU2Addr      = ssu2config.NewMockSSU2Addr
	GenerateConnectionID = ssu2config.GenerateConnectionID
)

// ─── From ssu2/wire ───────────────────────────────────────────────────────────

type SSU2Block = wire.SSU2Block
type SSU2Packet = wire.SSU2Packet
type TerminationReason = wire.TerminationReason
type AddressBlock = wire.AddressBlock
type NewTokenBlock = wire.NewTokenBlock
type BlockHandler = wire.BlockHandler
type BlockHandlerFunc = wire.BlockHandlerFunc
type BlockRouter = wire.BlockRouter
type BlockRouterStats = wire.BlockRouterStats
type BlockTypeCategory = wire.BlockTypeCategory
type HeaderType = wire.HeaderType
type HeaderProtector = wire.HeaderProtector
type HeaderProtectorManager = wire.HeaderProtectorManager
type SipHashLengthModifier = wire.SipHashLengthModifier
type ChaChaObfuscationModifier = wire.ChaChaObfuscationModifier
type SSU2PaddingModifier = wire.SSU2PaddingModifier
type TokenCache = wire.TokenCache
type Token = wire.Token

const (
	BlockTypeDateTime          = wire.BlockTypeDateTime
	BlockTypeOptions           = wire.BlockTypeOptions
	BlockTypeRouterInfo        = wire.BlockTypeRouterInfo
	BlockTypeI2NPMessage       = wire.BlockTypeI2NPMessage
	BlockTypeFirstFragment     = wire.BlockTypeFirstFragment
	BlockTypeFollowOnFragment  = wire.BlockTypeFollowOnFragment
	BlockTypeTermination       = wire.BlockTypeTermination
	BlockTypeRelayRequest      = wire.BlockTypeRelayRequest
	BlockTypeRelayResponse     = wire.BlockTypeRelayResponse
	BlockTypeRelayIntro        = wire.BlockTypeRelayIntro
	BlockTypePeerTest          = wire.BlockTypePeerTest
	BlockTypeNextNonce         = wire.BlockTypeNextNonce
	BlockTypeACK               = wire.BlockTypeACK
	BlockTypeAddress           = wire.BlockTypeAddress
	BlockTypeReserved14        = wire.BlockTypeReserved14
	BlockTypeRelayTagRequest   = wire.BlockTypeRelayTagRequest
	BlockTypeRelayTag          = wire.BlockTypeRelayTag
	BlockTypeNewToken          = wire.BlockTypeNewToken
	BlockTypePathChallenge     = wire.BlockTypePathChallenge
	BlockTypePathResponse      = wire.BlockTypePathResponse
	BlockTypeFirstPacketNumber = wire.BlockTypeFirstPacketNumber
	BlockTypeCongestion        = wire.BlockTypeCongestion
	BlockTypePadding           = wire.BlockTypePadding
)

const (
	TerminationNormalClose           = wire.TerminationNormalClose
	TerminationReceived              = wire.TerminationReceived
	TerminationIdleTimeout           = wire.TerminationIdleTimeout
	TerminationRouterShutdown        = wire.TerminationRouterShutdown
	TerminationDataPhaseAEADFailure  = wire.TerminationDataPhaseAEADFailure
	TerminationIncompatibleOptions   = wire.TerminationIncompatibleOptions
	TerminationIncompatibleSignature = wire.TerminationIncompatibleSignature
	TerminationClockSkew             = wire.TerminationClockSkew
	TerminationPaddingViolation      = wire.TerminationPaddingViolation
	TerminationAEADFramingError      = wire.TerminationAEADFramingError
	TerminationPayloadFormatError    = wire.TerminationPayloadFormatError
	TerminationSessionRequestError   = wire.TerminationSessionRequestError
	TerminationSessionCreatedError   = wire.TerminationSessionCreatedError
	TerminationSessionConfirmedError = wire.TerminationSessionConfirmedError
	TerminationTimeout               = wire.TerminationTimeout
	TerminationRISigVerifyFail       = wire.TerminationRISigVerifyFail
	TerminationSParamMissing         = wire.TerminationSParamMissing
	TerminationBanned                = wire.TerminationBanned
	TerminationBadToken              = wire.TerminationBadToken
	TerminationConnectionLimits      = wire.TerminationConnectionLimits
	TerminationIncompatibleVersion   = wire.TerminationIncompatibleVersion
	TerminationWrongNetID            = wire.TerminationWrongNetID
	TerminationReplacedByNewSession  = wire.TerminationReplacedByNewSession
)

const (
	HeaderTypeSessionRequest   = wire.HeaderTypeSessionRequest
	HeaderTypeSessionCreated   = wire.HeaderTypeSessionCreated
	HeaderTypeRetry            = wire.HeaderTypeRetry
	HeaderTypeTokenRequest     = wire.HeaderTypeTokenRequest
	HeaderTypeSessionConfirmed = wire.HeaderTypeSessionConfirmed
	HeaderTypeData             = wire.HeaderTypeData
	HeaderTypePeerTest         = wire.HeaderTypePeerTest
	HeaderTypeHolePunch        = wire.HeaderTypeHolePunch
)

const (
	MessageTypeSessionRequest   = wire.MessageTypeSessionRequest
	MessageTypeSessionCreated   = wire.MessageTypeSessionCreated
	MessageTypeSessionConfirmed = wire.MessageTypeSessionConfirmed
	MessageTypeData             = wire.MessageTypeData
	MessageTypePeerTest         = wire.MessageTypePeerTest
	MessageTypeRetry            = wire.MessageTypeRetry
	MessageTypeTokenRequest     = wire.MessageTypeTokenRequest
	MessageTypeHolePunch        = wire.MessageTypeHolePunch
)

const (
	ShortHeaderSize            = wire.ShortHeaderSize
	LongHeaderSize             = wire.LongHeaderSize
	EphemeralKeySize           = wire.EphemeralKeySize
	MACSize                    = wire.MACSize
	MinPacketSize              = wire.MinPacketSize
	MaxPacketSizeIPv4          = wire.MaxPacketSizeIPv4
	MaxPacketSizeIPv6          = wire.MaxPacketSizeIPv6
	SSU2ProtocolVersion        = wire.SSU2ProtocolVersion
	SSU2NetworkID              = wire.SSU2NetworkID
	SipHashIVSize              = wire.SipHashIVSize
	DataLengthFieldSize        = wire.DataLengthFieldSize
	TokenSize                  = wire.TokenSize
	MaxTokenCacheSize          = wire.MaxTokenCacheSize
	HeaderKeySize              = wire.HeaderKeySize
	MinPacketSizeForEncryption = wire.MinPacketSizeForEncryption
)

var (
	NewSSU2Block                        = wire.NewSSU2Block
	NewSSU2Packet                       = wire.NewSSU2Packet
	NewBlockRouter                      = wire.NewBlockRouter
	SerializeBlocks                     = wire.SerializeBlocks
	DeserializeBlocks                   = wire.DeserializeBlocks
	FindBlockByType                     = wire.FindBlockByType
	IsKnownBlockType                    = wire.IsKnownBlockType
	BlockTypeName                       = wire.BlockTypeName
	GetBlockTypeName                    = wire.GetBlockTypeName
	GetBlockCategory                    = wire.GetBlockCategory
	AllBlockTypes                       = wire.AllBlockTypes
	ExtractConnectionID                 = wire.ExtractConnectionID
	ParseNewTokenBlock                  = wire.ParseNewTokenBlock
	EncodeAddressBlock                  = wire.EncodeAddressBlock
	DecodeAddressBlock                  = wire.DecodeAddressBlock
	NewSipHashLengthModifierDirectional = wire.NewSipHashLengthModifierDirectional
	NewHeaderProtectorManager           = wire.NewHeaderProtectorManager
	NewTokenCache                       = wire.NewTokenCache
	NewTokenCacheWithMaxSize            = wire.NewTokenCacheWithMaxSize
	IntroKeyFromRouterAddress           = wire.IntroKeyFromRouterAddress
	StaticKeyFromRouterAddress          = wire.StaticKeyFromRouterAddress
)

// ─── From ssu2/handshake ──────────────────────────────────────────────────────

type HandshakeHandler = ssu2hs.HandshakeHandler
type OptionsParams = ssu2hs.OptionsParams
type KeyState = ssu2hs.KeyState
type ManagedKey = ssu2hs.ManagedKey
type KeyRotationCallback = ssu2hs.KeyRotationCallback
type KeyRotationManager = ssu2hs.KeyRotationManager
type KeyRotationStatus = ssu2hs.KeyRotationStatus

const (
	SSU2ProtocolName         = ssu2hs.SSU2ProtocolName
	PublishedKeyMinAge       = ssu2hs.PublishedKeyMinAge
	UnpublishedKeyMinAge     = ssu2hs.UnpublishedKeyMinAge
	KeyRotationCheckInterval = ssu2hs.KeyRotationCheckInterval
	KeyGracePeriod           = ssu2hs.KeyGracePeriod
	StaticKeySize            = ssu2hs.StaticKeySize
	IntroKeySize             = ssu2hs.IntroKeySize
	KeyStateActive           = ssu2hs.KeyStateActive
	KeyStatePendingRotation  = ssu2hs.KeyStatePendingRotation
	KeyStateRotating         = ssu2hs.KeyStateRotating
	KeyStateRetired          = ssu2hs.KeyStateRetired
)

var (
	NewHandshakeHandler         = ssu2hs.NewHandshakeHandler
	NewHandshakeHandlerWithKeys = ssu2hs.NewHandshakeHandlerWithKeys
	ParseOptionsBlock           = ssu2hs.ParseOptionsBlock
	NewKeyRotationManager       = ssu2hs.NewKeyRotationManager
	GenerateNewStaticKey        = ssu2hs.GenerateNewStaticKey
	GenerateNewIntroKey         = ssu2hs.GenerateNewIntroKey
)

// ─── From ssu2/reliability ────────────────────────────────────────────────────

type ACKHandler = reliability.ACKHandler
type CongestionController = reliability.CongestionController
type CongestionState = reliability.CongestionState
type CongestionStats = reliability.CongestionStats
type PendingACK = reliability.PendingACK
type RTTEstimator = reliability.RTTEstimator
type ReceiveWindow = reliability.ReceiveWindow
type SendReceiver = reliability.SendReceiver
type KeepaliveManager = reliability.KeepaliveManager

const (
	CongestionFlagRequestACK    = reliability.CongestionFlagRequestACK
	CongestionFlagECN           = reliability.CongestionFlagECN
	MinCongestionWindow         = reliability.MinCongestionWindow
	InitialCongestionWindow     = reliability.InitialCongestionWindow
	MaxCongestionWindow         = reliability.MaxCongestionWindow
	SlowStart                   = reliability.SlowStart
	CongestionAvoidance         = reliability.CongestionAvoidance
	Recovery                    = reliability.Recovery
	DefaultMaxWindowSize        = reliability.DefaultMaxWindowSize
	MaxPacketNumber             = reliability.MaxPacketNumber
	InitialSlowStartThreshold   = reliability.InitialSlowStartThreshold
	RTTKMultiplier              = reliability.RTTKMultiplier
	ClockGranularity            = reliability.ClockGranularity
	InitialRTO                  = reliability.InitialRTO
	MinRTO                      = reliability.MinRTO
	MaxRTO                      = reliability.MaxRTO
)

var (
	NewACKHandler                  = reliability.NewACKHandler
	NewCongestionController        = reliability.NewCongestionController
	NewCongestionControllerWithMTU = reliability.NewCongestionControllerWithMTU
	NewRTTEstimator                = reliability.NewRTTEstimator
	NewReceiveWindow               = reliability.NewReceiveWindow
	NewKeepaliveManager            = reliability.NewKeepaliveManager
	DecodeCongestionBlock          = reliability.DecodeCongestionBlock
	EncodeCongestionBlock          = reliability.EncodeCongestionBlock
	SortDescDedupPackets           = reliability.SortDescDedupPackets
)

// ─── From ssu2/path ───────────────────────────────────────────────────────────

type ListenerRef = path.ListenerRef
type PathValidationConn = path.PathValidationConn
type TokenCacheAccessor = path.TokenCacheAccessor
type CongestionControllerAccessor = path.CongestionControllerAccessor
type HolePunchAttempt = path.HolePunchAttempt
type HolePunchCoordinator = path.HolePunchCoordinator
type HolePunchState = path.HolePunchState
type IntroducerInfo = path.IntroducerInfo
type IntroducerRegistry = path.IntroducerRegistry
type NATType = path.NATType
type PathChallenge = path.PathChallenge
type PathChallengeState = path.PathChallengeState
type PathValidator = path.PathValidator
type PeerTest = path.PeerTest
type PeerTestBlock = path.PeerTestBlock
type PeerTestManager = path.PeerTestManager
type PeerTestMessageCode = path.PeerTestMessageCode
type PeerTestRole = path.PeerTestRole
type PeerTestState = path.PeerTestState
type PendingSession = path.PendingSession
type RegisteredIntroducer = path.RegisteredIntroducer
type RelayIntroBlock = path.RelayIntroBlock
type RelayManager = path.RelayManager
type RelayRequestBlock = path.RelayRequestBlock
type RelayResponseBlock = path.RelayResponseBlock
type RelayTag = path.RelayTag
type RelayTagBlock = path.RelayTagBlock
type RelayTagRequestBlock = path.RelayTagRequestBlock
type TestResult = path.TestResult

const (
	NATUnknown        = path.NATUnknown
	NATNone           = path.NATNone
	NATCone           = path.NATCone
	NATRestricted     = path.NATRestricted
	NATPortRestricted = path.NATPortRestricted
	NATSymmetric      = path.NATSymmetric

	HolePunchRequested = path.HolePunchRequested
	HolePunchSent      = path.HolePunchSent
	HolePunchWaiting   = path.HolePunchWaiting
	HolePunchSuccess   = path.HolePunchSuccess
	HolePunchFailed    = path.HolePunchFailed

	ChallengeSent      = path.ChallengeSent
	ChallengeReceived  = path.ChallengeReceived
	ChallengeValidated = path.ChallengeValidated
	ChallengeFailed    = path.ChallengeFailed

	PeerTestRequest      = path.PeerTestRequest
	PeerTestRelay        = path.PeerTestRelay
	PeerTestResponse     = path.PeerTestResponse
	PeerTestResult       = path.PeerTestResult
	PeerTestProbe        = path.PeerTestProbe
	PeerTestReply        = path.PeerTestReply
	PeerTestConfirmation = path.PeerTestConfirmation

	RoleInitiator = path.RoleInitiator
	RoleRelay     = path.RoleRelay
	RoleResponder = path.RoleResponder

	TestRequested = path.TestRequested
	TestRelayed   = path.TestRelayed
	TestProbed    = path.TestProbed
	TestComplete  = path.TestComplete
	TestFailed    = path.TestFailed
)

var (
	NewPathValidator              = path.NewPathValidator
	DecodeRelayIntro              = path.DecodeRelayIntro
	DecodeRelayRequest            = path.DecodeRelayRequest
	DecodeRelayResponse           = path.DecodeRelayResponse
	DecodePeerTestBlock           = path.DecodePeerTestBlock
	EncodeRelayRequest            = path.EncodeRelayRequest
	EncodeRelayResponse           = path.EncodeRelayResponse
	EncodeRelayIntro              = path.EncodeRelayIntro
	EncodeRelayTagRequest         = path.EncodeRelayTagRequest
	EncodeRelayTag                = path.EncodeRelayTag
	EncodePeerTestBlock           = path.EncodePeerTestBlock
	VerifyRelayRequestSignature   = path.VerifyRelayRequestSignature
	VerifyRelayResponseSignature  = path.VerifyRelayResponseSignature
	VerifyPeerTestSignature       = path.VerifyPeerTestSignature
)
