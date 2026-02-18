// Example: Connection state management demonstration with complete handshakes
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("state-example")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	handleDefaultAddress(args, "localhost:8080")

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("state-example", "Connection state management demonstration supporting all Noise patterns")
		return
	}

	// Handle special modes
	if handleSpecialModes(args, runStateDemo) {
		return
	}

	// Parse keys for the selected pattern
	staticKey, _, err := shared.ParseKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	fmt.Printf("🔄 Connection State Management Example with pattern %s\n", args.Pattern)

	// Run based on mode
	if args.ServerAddr != "" {
		runStateServer(args, staticKey)
	} else if args.ClientAddr != "" {
		runStateClient(args, staticKey)
	}
}

// handleDefaultAddress sets the default address when none provided
func handleDefaultAddress(args *shared.CommonArgs, defaultAddr string) {
	if args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = defaultAddr
	}
}

// handleSpecialModes handles demo and generate modes, returning true if handled
func handleSpecialModes(args *shared.CommonArgs, demoFunc func(*shared.CommonArgs)) bool {
	if args.Demo {
		demoFunc(args)
		return true
	}
	if args.Generate {
		shared.RunGenerate()
		return true
	}
	return false
}

// runStateDemo demonstrates state management with server and client
func runStateDemo(args *shared.CommonArgs) {
	fmt.Printf("🎭 Running state demo with server and client\n")

	// Parse keys for demo
	staticKey, _, err := shared.ParseKeys(args)
	if err != nil {
		log.Fatalf("Failed to parse keys for demo: %v", err)
	}

	// Start server in background
	go runStateServer(args, staticKey)
	time.Sleep(200 * time.Millisecond) // Wait for server to start

	// Run client to connect to server
	clientArgs := *args
	clientArgs.ClientAddr = args.ServerAddr
	clientArgs.ServerAddr = "" // Clear server mode for client
	runStateClient(&clientArgs, staticKey)
}

// runStateServer runs a server for state management testing
func runStateServer(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting state server on %s with pattern %s\n", args.ServerAddr, args.Pattern)

	// Create server configuration
	config := noise.NewListenerConfig(args.Pattern).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	// Add static key if provided
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	// Start server
	listener, err := noise.ListenNoise("tcp", args.ServerAddr, config)
	if err != nil {
		log.Fatalf("Failed to start state server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("✓ State server listening on: %s\n", listener.Addr())

	// Accept connections and demonstrate state management
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handleStateConnection(conn)
	}
}

// runStateClient runs a client for state management testing
func runStateClient(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("📱 Starting state client connecting to %s\n", args.ClientAddr)

	// Create client configuration
	config := noise.NewConnConfig(args.Pattern, true). // initiator = true
								WithHandshakeTimeout(args.HandshakeTimeout).
								WithReadTimeout(args.ReadTimeout).
								WithWriteTimeout(args.WriteTimeout)

	// Add static key if provided
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	// Connect to server
	conn, err := noise.DialNoise("tcp", args.ClientAddr, config)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	fmt.Printf("✓ Connected to server: %s\n", conn.RemoteAddr())

	// Demonstrate state management
	demonstrateClientState(conn)
}

// handleStateConnection handles a connection and demonstrates state management
func handleStateConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New connection from: %s\n", clientAddr)

	// Check if this is a Noise connection to access state
	if noiseConn, ok := conn.(*noise.NoiseConn); ok {
		fmt.Printf("🔐 Starting handshake with %s...\n", clientAddr)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := noiseConn.Handshake(ctx)
		if err != nil {
			log.Printf("Handshake failed with %s: %v", clientAddr, err)
			return
		}
		fmt.Printf("✅ Handshake completed with %s\n", clientAddr)

		// Demonstrate state access
		demonstrateServerState(noiseConn)
	}

	// Handle communication
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("Client %s disconnected\n", clientAddr)
			return
		}

		message := string(buffer[:n])
		fmt.Printf("📨 Received from %s: %s\n", clientAddr, message)

		// Echo back with state info
		response := fmt.Sprintf("State echo: %s", message)
		conn.Write([]byte(response))
	}
}

// demonstrateServerState shows server-side state information
func demonstrateServerState(conn *noise.NoiseConn) {
	fmt.Println("\n🔍 Server-side Connection State:")
	fmt.Printf("  Local Address:  %s\n", conn.LocalAddr())
	fmt.Printf("  Remote Address: %s\n", conn.RemoteAddr())

	// Access Noise-specific state
	fmt.Printf("  Handshake Complete: %v\n", true) // After successful handshake
	fmt.Printf("  Connection State: Active\n")

	fmt.Println()
}

// demonstrateClientState shows client-side state information
func demonstrateClientState(conn *noise.NoiseConn) {
	fmt.Println("\n🔍 Client-side Connection State:")
	fmt.Printf("  Local Address:  %s\n", conn.LocalAddr())
	fmt.Printf("  Remote Address: %s\n", conn.RemoteAddr())

	// Send test messages to demonstrate state
	messages := []string{
		"Hello from state client",
		"Testing state management",
		"Connection state demo",
	}

	for i, msg := range messages {
		fmt.Printf("\n📤 Sending message %d: %s\n", i+1, msg)

		_, err := conn.Write([]byte(msg))
		if err != nil {
			log.Printf("Failed to send message: %v", err)
			continue
		}

		// Read response
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Failed to read response: %v", err)
			continue
		}

		response := string(buffer[:n])
		fmt.Printf("📨 Received response: %s\n", response)

		time.Sleep(500 * time.Millisecond) // Pause between messages
	}

	fmt.Println("\n✅ State demonstration completed!")
}
