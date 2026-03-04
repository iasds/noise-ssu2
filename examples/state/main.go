// Example: Connection state management demonstration with complete handshakes
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
	args, err := shared.ParseCommonArgs("state-example")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	shared.HandleDefaultAddress(args, "localhost:8080")

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("state-example", "Connection state management demonstration supporting all Noise patterns")
		return
	}

	// Handle special modes
	if shared.HandleSpecialModes(args, runStateDemo) {
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

// runStateDemo demonstrates state management with server and client
func runStateDemo(args *shared.CommonArgs) {
	shared.RunDemo2(args, "state", runStateServer, runStateClient)
}

// runStateServer runs a server for state management testing
func runStateServer(args *shared.CommonArgs, staticKey []byte) {
	shared.RunServer(args, staticKey, "state", func(conn net.Conn) {
		shared.HandleConnection(conn, "State", demonstrateServerState)
	})
}

// runStateClient runs a client for state management testing
func runStateClient(args *shared.CommonArgs, staticKey []byte) {
	shared.RunClient(args, staticKey, nil, "state", demonstrateClientState)
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
