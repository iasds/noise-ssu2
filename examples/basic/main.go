// Example: Basic usage of the go-noise library with configurable patterns and complete handshakes
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("basic-noise")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("basic-noise", "Basic Noise Protocol example with all pattern support")
		return
	}

	// Handle special modes
	if shared.HandleSpecialModes(args, func(_ *shared.CommonArgs) { shared.RunDemo() }) {
		return
	}

	// Parse and validate keys for the selected pattern
	staticKey, remoteKey, err := shared.ParseKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run client or server based on arguments
	if args.ServerAddr != "" {
		runBasicServer(args, staticKey)
	} else if args.ClientAddr != "" {
		runBasicClient(args, staticKey, remoteKey)
	}
}

// demonstrateBasicConfigurations shows examples of creating and validating Noise configurations.
func demonstrateBasicConfigurations() {
	// 1. Create configuration for XX pattern (most common)
	configXX := noise.NewConnConfig("XX", true).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second)

	fmt.Printf("XX Pattern Config: %s\n", configXX.Pattern)

	// 2. Create configuration with full pattern name
	configFull := noise.NewConnConfig("Noise_IK_25519_AESGCM_SHA256", false).
		WithHandshakeTimeout(15 * time.Second)

	fmt.Printf("Full Pattern Config: %s\n", configFull.Pattern)

	// 3. Validate configurations
	validateConfiguration("XX", configXX)
	validateConfiguration("Full", configFull)
}

// validateConfiguration validates a Noise configuration and prints the result.
func validateConfiguration(name string, config *noise.ConnConfig) {
	if err := config.Validate(); err != nil {
		fmt.Printf("%s config validation failed: %v\n", name, err)
	} else {
		fmt.Printf("%s config is valid\n", name)
	}
}

// demonstrateSupportedPatterns shows all supported Noise patterns and their validation status.
func demonstrateSupportedPatterns() {
	supportedPatterns := []string{
		"NN", "NK", "NX",
		"XN", "XK", "XX",
		"KN", "KK", "KX",
		"IN", "IK", "IX",
		"N", "K", "X",
	}

	fmt.Println("\nSupported Noise patterns:")
	for _, pattern := range supportedPatterns {
		config := noise.NewConnConfig(pattern, true)
		if err := config.Validate(); err == nil {
			fmt.Printf("✓ %s\n", pattern)
		} else {
			fmt.Printf("✗ %s: %v\n", pattern, err)
		}
	}
}

// demonstrateNoiseAddressing shows examples of NoiseAddr usage and formatting.
func demonstrateNoiseAddressing() {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "localhost:8080")
	noiseAddr := noise.NewNoiseAddr(tcpAddr, "XX", "initiator")

	fmt.Printf("\nNoise Address Examples:\n")
	fmt.Printf("Network: %s\n", noiseAddr.Network())
	fmt.Printf("String: %s\n", noiseAddr.String())
	fmt.Printf("Pattern: %s\n", noiseAddr.Pattern())
	fmt.Printf("Role: %s\n", noiseAddr.Role())

	printConnectionExample()
}

// printConnectionExample prints a commented example of NoiseConn usage.
func printConnectionExample() {
	shared.PrintLines(
		"\n// Note: Actual connection creation would require a real net.Conn",
		"// and proper logger setup, which is commented out due to logger issues",
		"//",
		"// Example of creating a NoiseConn (requires working logger):",
		"// tcpConn, err := net.Dial(\"tcp\", \"localhost:8080\")",
		"// noiseConn, err := noise.NewNoiseConn(tcpConn, configXX)",
		"// err := noiseConn.Handshake(ctx)",
	)
}

// runBasicServer starts a basic Noise server with complete handshake
func runBasicServer(args *shared.CommonArgs, staticKey []byte) {
	shared.RunServer(args, staticKey, "basic", func(conn net.Conn) {
		shared.HandleConnection(conn, "Basic", nil)
	})
}

// runBasicClient connects to a basic Noise server with complete handshake
func runBasicClient(args *shared.CommonArgs, staticKey, remoteKey []byte) {
	shared.RunClient(args, staticKey, remoteKey, "basic", func(conn *noise.NoiseConn) {
		fmt.Printf("📤 Sending: Hello from basic client!\n")
		_, err := conn.Write([]byte("Hello from basic client!"))
		if err != nil {
			log.Fatalf("Write failed: %v", err)
		}
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Fatalf("Read failed: %v", err)
		}
		fmt.Printf("📨 Received: %s\n", string(buffer[:n]))
		fmt.Println("✓ Basic Noise communication completed successfully!")
	})
}
