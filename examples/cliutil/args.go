// Package shared provides common utilities for go-noise examples
package shared

import (
	"flag"
	"fmt"
	"time"

	"github.com/samber/oops"
)

// CommonArgs holds common command-line arguments for Noise examples
type CommonArgs struct {
	// Network configuration
	ServerAddr string
	ClientAddr string
	Pattern    string

	// Cryptographic material
	StaticKey string
	RemoteKey string

	// Timeouts
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration

	// Operation modes
	Demo     bool
	Generate bool
	Verbose  bool
}

// RegisterNetworkFlags registers the common -server and -client flags shared
// by both standard and NTCP2 argument parsing.
func RegisterNetworkFlags(serverAddr, clientAddr *string, serverExample string) {
	flag.StringVar(serverAddr, "server", "", fmt.Sprintf("Run as server on specified address (e.g., %s)", serverExample))
	flag.StringVar(clientAddr, "client", "", "Run as client connecting to specified address")
}

// RegisterTimeoutFlags registers the common timeout flags shared by both
// standard and NTCP2 argument parsing.
func RegisterTimeoutFlags(handshakeTimeout, readTimeout, writeTimeout *time.Duration, defaultHandshake time.Duration, handshakeDesc string) {
	flag.DurationVar(handshakeTimeout, "handshake-timeout", defaultHandshake, handshakeDesc)
	flag.DurationVar(readTimeout, "read-timeout", 60*time.Second, "Read operation timeout")
	flag.DurationVar(writeTimeout, "write-timeout", 60*time.Second, "Write operation timeout")
}

// RegisterModeFlags registers the common operation mode flags shared by both
// standard and NTCP2 argument parsing.
func RegisterModeFlags(demo, generate, verbose *bool, demoDesc, generateDesc string) {
	flag.BoolVar(demo, "demo", false, demoDesc)
	flag.BoolVar(generate, "generate", false, generateDesc)
	flag.BoolVar(verbose, "verbose", false, "Enable verbose logging")
}

// ParseCommonArgs parses standard command-line arguments for Noise examples
func ParseCommonArgs(appName string) (*CommonArgs, error) {
	args := &CommonArgs{}

	// Network configuration
	RegisterNetworkFlags(&args.ServerAddr, &args.ClientAddr, "localhost:8080")
	flag.StringVar(&args.Pattern, "pattern", "NN", "Noise handshake pattern to use")

	// Cryptographic material
	flag.StringVar(&args.StaticKey, "static-key", "", "Static private key as 64-character hex string (generated if empty)")
	flag.StringVar(&args.RemoteKey, "remote-key", "", "Remote static public key as 64-character hex string (generated if empty)")

	// Timeouts
	RegisterTimeoutFlags(&args.HandshakeTimeout, &args.ReadTimeout, &args.WriteTimeout, 30*time.Second, "Handshake timeout duration")

	// Operation modes
	RegisterModeFlags(&args.Demo, &args.Generate, &args.Verbose,
		"Run demonstration mode showing configurations and patterns",
		"Generate and display cryptographic keys for testing")

	flag.Parse()

	// Validate pattern
	if err := ValidatePattern(args.Pattern); err != nil {
		return nil, oops.
			Code("INVALID_ARGS").
			In("examples").
			Wrapf(err, "invalid pattern specified")
	}

	return args, nil
}

// PrintUsageHeader prints the common header portion of usage output shared
// between PrintUsage and PrintNTCP2Usage. It displays the app name, description,
// usage syntax, available options, and the "Examples:" label.
func PrintUsageHeader(appName, description string) {
	fmt.Printf("%s - %s\n\n", appName, description)
	fmt.Println("Usage:")
	fmt.Printf("  %s [options]\n\n", appName)
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
}

// PrintUsageExample prints a single usage example consisting of a description
// comment and the corresponding command line, consolidating the repeated
// description-plus-command pattern used by PrintUsage and PrintNTCP2Usage.
func PrintUsageExample(appName, description, command string) {
	fmt.Printf("  # %s:\n", description)
	fmt.Printf("  %s %s\n\n", appName, command)
}

// PrintUsage displays usage information for a Noise example
func PrintUsage(appName, description string) {
	PrintUsageHeader(appName, description)
	PrintUsageExample(appName, "Generate keys for testing", "-generate")
	PrintUsageExample(appName, "Run demo mode", "-demo")
	PrintUsageExample(appName, "Run server with NN pattern (no keys required)", "-server localhost:8080 -pattern NN")
	PrintUsageExample(appName, "Run client with NN pattern", "-client localhost:8080 -pattern NN")
	PrintUsageExample(appName, "Run server with XX pattern (keys required)", "-server localhost:8080 -pattern XX -static-key <64-char-hex>")
	PrintUsageExample(appName, "Run client with XX pattern", "-client localhost:8080 -pattern XX -static-key <64-char-hex>")
	fmt.Println("Supported Patterns:")
	for _, pattern := range SupportedPatterns {
		needsLocal, needsRemote := GetPatternRequirements(pattern)
		requirements := "no keys required"
		if needsLocal && needsRemote {
			requirements = "requires local and remote static keys"
		} else if needsLocal {
			requirements = "requires local static key"
		} else if needsRemote {
			requirements = "requires remote static key"
		}
		fmt.Printf("  %-4s - %s\n", pattern, requirements)
	}
}

// ValidateArgs performs validation on parsed arguments
func (args *CommonArgs) ValidateArgs() error {
	if err := args.validateOperationMode(); err != nil {
		return err
	}

	if err := args.validateKeyRequirements(); err != nil {
		return err
	}

	return nil
}

// validateOperationMode ensures exactly one operation mode is specified
func (args *CommonArgs) validateOperationMode() error {
	modeCount := args.countActiveModes()

	if modeCount == 0 {
		return oops.
			Code("INVALID_ARGS").
			In("examples").
			Errorf("must specify one of: -server, -client, -demo, or -generate")
	}

	if modeCount > 1 {
		return oops.
			Code("INVALID_ARGS").
			In("examples").
			Errorf("cannot specify multiple modes simultaneously")
	}

	return nil
}

// countActiveModes returns the number of operation modes that are enabled
func (args *CommonArgs) countActiveModes() int {
	modeCount := 0
	if args.ServerAddr != "" {
		modeCount++
	}
	if args.ClientAddr != "" {
		modeCount++
	}
	if args.Demo {
		modeCount++
	}
	if args.Generate {
		modeCount++
	}
	return modeCount
}

// validateKeyRequirements ensures required keys are provided for the chosen pattern
func (args *CommonArgs) validateKeyRequirements() error {
	needsLocal, needsRemote := GetPatternRequirements(args.Pattern)

	if err := args.validateLocalKeyRequirement(needsLocal); err != nil {
		return err
	}

	if err := args.validateRemoteKeyRequirement(needsRemote); err != nil {
		return err
	}

	return nil
}

// validateLocalKeyRequirement checks if local static key is provided when required
func (args *CommonArgs) validateLocalKeyRequirement(needsLocal bool) error {
	if needsLocal && args.StaticKey == "" && !args.Demo && !args.Generate {
		return oops.
			Code("MISSING_KEY").
			In("examples").
			With("pattern", args.Pattern).
			Errorf("pattern %s requires a local static key (-static-key)", args.Pattern)
	}
	return nil
}

// validateRemoteKeyRequirement checks if remote static key is provided when required
func (args *CommonArgs) validateRemoteKeyRequirement(needsRemote bool) error {
	if needsRemote && args.RemoteKey == "" && !args.Demo && !args.Generate {
		return oops.
			Code("MISSING_KEY").
			In("examples").
			With("pattern", args.Pattern).
			Errorf("pattern %s requires a remote static key (-remote-key)", args.Pattern)
	}
	return nil
}

// HandleDefaultAddress sets the default server address when no address is provided.
// This consolidates the common default-address pattern used across example programs.
func HandleDefaultAddress(args *CommonArgs, defaultAddr string) {
	if args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = defaultAddr
	}
}

// HandleSpecialModes handles demo and generate modes, returning true if handled.
// demoFunc is a callback that runs the example-specific demo logic. This
// consolidates the common special-mode dispatch pattern used across example programs.
func HandleSpecialModes(args *CommonArgs, demoFunc func(*CommonArgs)) bool {
	if args.Demo {
		demoFunc(args)
		return true
	}
	if args.Generate {
		RunGenerate()
		return true
	}
	return false
}
