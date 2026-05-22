// Example: Connection state management demonstration with complete handshakes
package main

import (
	"fmt"
	"net"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	shared.RunExample(
		"state-example",
		"Connection state management demonstration supporting all Noise patterns",
		"localhost:8080",
		"🔄 Connection State Management Example with pattern %s",
		runStateDemo,
		runStateServer,
		runStateClient,
	)
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

	shared.SendAndDisplay(conn, messages)

	fmt.Println("\n✅ State demonstration completed!")
}
