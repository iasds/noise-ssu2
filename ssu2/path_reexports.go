// Package ssu2: path/relay/peertest re-exports from ssu2/path.
// Implementations live in ssu2/path; this file provides
// backward-compatible access from the flat ssu2 package.
package ssu2

import "github.com/go-i2p/go-noise/ssu2/path"

// ─── Interface re-exports ──────────────────────────────────────────────────────

type ListenerRef = path.ListenerRef
type PathValidationConn = path.PathValidationConn
type TokenCacheAccessor = path.TokenCacheAccessor
type CongestionControllerAccessor = path.CongestionControllerAccessor

// ─── Type aliases ─────────────────────────────────────────────────────────────

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

// ─── NAT type constants ────────────────────────────────────────────────────────

const (
	NATUnknown        = path.NATUnknown
	NATNone           = path.NATNone
	NATCone           = path.NATCone
	NATRestricted     = path.NATRestricted
	NATPortRestricted = path.NATPortRestricted
	NATSymmetric      = path.NATSymmetric
)

// ─── HolePunch state constants ─────────────────────────────────────────────────

const (
	HolePunchRequested = path.HolePunchRequested
	HolePunchSent      = path.HolePunchSent
	HolePunchWaiting   = path.HolePunchWaiting
	HolePunchSuccess   = path.HolePunchSuccess
	HolePunchFailed    = path.HolePunchFailed
)

// ─── PathChallenge state constants ────────────────────────────────────────────

const (
	ChallengeSent      = path.ChallengeSent
	ChallengeReceived  = path.ChallengeReceived
	ChallengeValidated = path.ChallengeValidated
	ChallengeFailed    = path.ChallengeFailed
)

// ─── PeerTest message code constants ──────────────────────────────────────────

const (
	PeerTestRequest      = path.PeerTestRequest
	PeerTestRelay        = path.PeerTestRelay
	PeerTestResponse     = path.PeerTestResponse
	PeerTestResult       = path.PeerTestResult
	PeerTestProbe        = path.PeerTestProbe
	PeerTestReply        = path.PeerTestReply
	PeerTestConfirmation = path.PeerTestConfirmation
)

// ─── PeerTest role constants ───────────────────────────────────────────────────

const (
	RoleInitiator = path.RoleInitiator
	RoleRelay     = path.RoleRelay
	RoleResponder = path.RoleResponder
)

// ─── PeerTest state constants ──────────────────────────────────────────────────

const (
	TestRequested = path.TestRequested
	TestRelayed   = path.TestRelayed
	TestProbed    = path.TestProbed
	TestComplete  = path.TestComplete
	TestFailed    = path.TestFailed
)

// ─── Validation / MTU / relay constants ───────────────────────────────────────

const (
	PathValidationTimeout  = path.PathValidationTimeout
	MinMTU                 = path.MinMTU
	RelayRequestPrologue   = path.RelayRequestPrologue
	PeerTestPrologue       = path.PeerTestPrologue
	RelayAgreementPrologue = path.RelayAgreementPrologue
)

// ─── Function re-exports ───────────────────────────────────────────────────────

var (
	NewHolePunchCoordinator      = path.NewHolePunchCoordinator
	NewIntroducerRegistry        = path.NewIntroducerRegistry
	NewPathValidator             = path.NewPathValidator
	NewPeerTestManager           = path.NewPeerTestManager
	NewPeerTestManagerWithFields = path.NewPeerTestManagerWithFields
	NewRelayManager              = path.NewRelayManager

	EncodePathChallenge            = path.EncodePathChallenge
	EncodePathChallengeWithPadding = path.EncodePathChallengeWithPadding
	EncodePathResponse             = path.EncodePathResponse
	DecodePathChallenge            = path.DecodePathChallenge
	DecodePathResponse             = path.DecodePathResponse

	DecodePeerTestBlock   = path.DecodePeerTestBlock
	EncodePeerTestBlock   = path.EncodePeerTestBlock
	DecodeRelayIntro      = path.DecodeRelayIntro
	EncodeRelayIntro      = path.EncodeRelayIntro
	DecodeRelayRequest    = path.DecodeRelayRequest
	EncodeRelayRequest    = path.EncodeRelayRequest
	DecodeRelayResponse   = path.DecodeRelayResponse
	EncodeRelayResponse   = path.EncodeRelayResponse
	DecodeRelayTag        = path.DecodeRelayTag
	EncodeRelayTag        = path.EncodeRelayTag
	DecodeRelayTagRequest = path.DecodeRelayTagRequest
	EncodeRelayTagRequest = path.EncodeRelayTagRequest

	BuildPeerTestSignedData      = path.BuildPeerTestSignedData
	BuildRelayRequestSignedData  = path.BuildRelayRequestSignedData
	BuildRelayResponseSignedData = path.BuildRelayResponseSignedData
	SignPeerTest                 = path.SignPeerTest
	SignRelayRequest             = path.SignRelayRequest
	SignRelayResponse            = path.SignRelayResponse
	VerifyPeerTestSignature      = path.VerifyPeerTestSignature
	VerifyRelayRequestSignature  = path.VerifyRelayRequestSignature
	VerifyRelayResponseSignature = path.VerifyRelayResponseSignature

	CompareNATTypes         = path.CompareNATTypes
	DescribeNATCapabilities = path.DescribeNATCapabilities
	HasPublicIP             = path.HasPublicIP
	IsSymmetricNAT          = path.IsSymmetricNAT
	RequiresRelay           = path.RequiresRelay
	SelectBestNATType       = path.SelectBestNATType
	SelectWorstNATType      = path.SelectWorstNATType

	AnalyzeProbeResults    = path.AnalyzeProbeResults
	ExtractExternalAddress = path.ExtractExternalAddress
	ExtractExternalPort    = path.ExtractExternalPort
	IsDirectlyReachable    = path.IsDirectlyReachable
	IsReachableViaRelay    = path.IsReachableViaRelay
	ValidateTestResult     = path.ValidateTestResult

	IsAddressConsistent = path.IsAddressConsistent
	IsIPConsistent      = path.IsIPConsistent
	IsPortConsistent    = path.IsPortConsistent
	IsValidSourcePort   = path.IsValidSourcePort
	NonceConnectionIDs  = path.NonceConnectionIDs
)
