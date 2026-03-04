// Example: Transport wrapping demonstration with complete handshakes
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
	args, err := shared.ParseCommonArgs("transport-example")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	shared.HandleDefaultAddress(args, "localhost:8080")

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("transport-example", "Transport wrapping demonstration supporting all Noise patterns")
		return
	}

	// Handle special modes
	if shared.HandleSpecialModes(args, runTransportDemo) {
		return
	}

	// Parse keys for the selected pattern
	staticKey, _, err := shared.ParseKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	fmt.Printf("🚀 Transport Wrapping Example with pattern %s\n", args.Pattern)

	// Run based on mode
	if args.ServerAddr != "" {
		runTransportServer(args, staticKey)
	} else if args.ClientAddr != "" {
		runTransportClient(args, staticKey)
	}
}

// runTransportDemo demonstrates transport wrapping with server and client
func runTransportDemo(args *shared.CommonArgs) {
	fmt.Printf("🎭 Running transport demo with server and client\n")

	// Parse keys for demo
	staticKey, _, err := shared.ParseKeys(args)
	if err != nil {
		log.Fatalf("Failed to parse keys for demo: %v", err)
	}

	// Start server in background
	go runTransportServer(args, staticKey)
	time.Sleep(200 * time.Millisecond) // Wait for server to start

	// Run client to connect to server
	clientArgs := *args
	clientArgs.ClientAddr = args.ServerAddr
	clientArgs.ServerAddr = "" // Clear server mode for client
	runTransportClient(&clientArgs, staticKey)
}

// runTransportServer runs a server demonstrating transport wrapping
func runTransportServer(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting transport server on %s with pattern %s\n", args.ServerAddr, args.Pattern)

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
		log.Fatalf("Failed to start transport server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("✓ Transport server listening on: %s\n", listener.Addr())

	// Accept connections and demonstrate transport wrapping
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handleTransportConnection(conn)
	}
}

// runTransportClient runs a client demonstrating transport wrapping
func runTransportClient(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("📱 Starting transport client connecting to %s\n", args.ClientAddr)

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

	// Demonstrate transport functionality
	demonstrateTransportClient(conn)
}

// handleTransportConnection handles a connection and demonstrates transport features
func handleTransportConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New connection from: %s\n", clientAddr)

	// Check if this is a Noise connection to access transport features
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

		// Demonstrate transport features
		demonstrateTransportServer(noiseConn)
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

		// Echo back with transport info
		response := fmt.Sprintf("Transport echo: %s", message)
		conn.Write([]byte(response))
	}
}

// demonstrateTransportServer shows server-side transport features
func demonstrateTransportServer(conn *noise.NoiseConn) {
	fmt.Println("\n🔍 Server-side Transport Features:")
	fmt.Printf("  Local Address:  %s\n", conn.LocalAddr())
	fmt.Printf("  Remote Address: %s\n", conn.RemoteAddr())
	fmt.Printf("  Transport: Noise Protocol\n")
	fmt.Printf("  Encryption: Active\n")
	fmt.Println()
}

// demonstrateTransportClient shows client-side transport features
func demonstrateTransportClient(conn *noise.NoiseConn) {
	fmt.Println("\n🔍 Client-side Transport Features:")
	fmt.Printf("  Local Address:  %s\n", conn.LocalAddr())
	fmt.Printf("  Remote Address: %s\n", conn.RemoteAddr())
	fmt.Printf("  Transport: Noise Protocol\n")
	fmt.Printf("  Encryption: Active\n")

	// Send test messages to demonstrate transport
	messages := []string{
		"Hello from transport client",
		"Testing transport wrapping",
		"Secure communication demo",
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

	fmt.Println("\n✅ Transport demonstration completed!")
}
