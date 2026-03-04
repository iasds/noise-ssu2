// Example: Transport wrapping demonstration with complete handshakes
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
	shared.RunDemo2(args, "transport", runTransportServer, runTransportClient)
}

// runTransportServer runs a server demonstrating transport wrapping
func runTransportServer(args *shared.CommonArgs, staticKey []byte) {
	shared.RunServer(args, staticKey, "transport", func(conn net.Conn) {
		shared.HandleConnection(conn, "Transport", demonstrateTransportServer)
	})
}

// runTransportClient runs a client demonstrating transport wrapping
func runTransportClient(args *shared.CommonArgs, staticKey []byte) {
	shared.RunClient(args, staticKey, nil, "transport", demonstrateTransportClient)
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
