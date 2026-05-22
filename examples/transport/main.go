// Example: Transport wrapping demonstration with complete handshakes
package main

import (
	"fmt"
	"net"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	shared.RunExample(
		"transport-example",
		"Transport wrapping demonstration supporting all Noise patterns",
		"localhost:8080",
		"🚀 Transport Wrapping Example with pattern %s",
		runTransportDemo,
		runTransportServer,
		runTransportClient,
	)
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

	shared.SendAndDisplay(conn, messages)

	fmt.Println("\n✅ Transport demonstration completed!")
}
