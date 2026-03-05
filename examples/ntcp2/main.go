// Example: NTCP2 addressing and connection demonstration for I2P router addressing
package main

import (
	"fmt"
	"log"
	"net"

	shared "github.com/go-i2p/go-noise/examples/ntcp2-shared"
	"github.com/go-i2p/go-noise/ntcp2"
)

func main() {
	shared.RunNTCP2Example(
		"ntcp2-demo",
		"NTCP2 addressing and connection demonstration",
		"",
		func(args *shared.NTCP2Args) {
			shared.RunNTCP2Demo()
			demonstrateNTCP2Addressing()
		},
		func(args *shared.NTCP2Args, routerHash, remoteRouterHash, destHash, staticKey []byte) {
			if args.ServerAddr != "" || args.ClientAddr != "" {
				fmt.Println("🚧 NTCP2 server/client functionality coming in future examples")
				fmt.Println("This example demonstrates NTCP2 addressing only")
				fmt.Println()
			}
			demonstrateNTCP2AddressingWithKeys(routerHash, remoteRouterHash, destHash, staticKey)
		},
	)
}

// demonstrateNTCP2Addressing shows basic NTCP2 addressing examples
func demonstrateNTCP2Addressing() {
	fmt.Println("📍 NTCP2 Addressing Examples:")
	fmt.Println("============================")

	// Create a TCP address for the underlying connection
	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP("192.168.1.100"),
		Port: 7654,
	}

	// Create a sample router hash (32 bytes)
	routerHash := make([]byte, 32)
	copy(routerHash, []byte("example_router_hash_32_bytes...."))

	// Create an NTCP2 address for an initiator
	ntcpAddr, err := ntcp2.NewNTCP2Addr(tcpAddr, routerHash, "initiator")
	if err != nil {
		log.Fatalf("Failed to create NTCP2 address: %v", err)
	}

	fmt.Printf("Basic NTCP2 Address:\n")
	fmt.Printf("  Network: %s\n", ntcpAddr.Network())
	fmt.Printf("  String:  %s\n", ntcpAddr.String())
	fmt.Printf("  Role:    %s\n", ntcpAddr.Role())
	fmt.Printf("  IdentHash: %x\n", ntcpAddr.IdentHash())
	fmt.Println()

	// Demonstrate net.Addr interface compliance
	var netAddr net.Addr = ntcpAddr
	fmt.Printf("net.Addr Interface Compliance:\n")
	fmt.Printf("  Network(): %s\n", netAddr.Network())
	fmt.Printf("  String():  %s\n", netAddr.String())
	fmt.Println()
}

// displayAddressInfo prints NTCP2 address details
func displayAddressInfo(ntcpAddr *ntcp2.NTCP2Addr, routerHash []byte) {
	fmt.Printf("NTCP2 Address with User Router Hash:\n")
	fmt.Printf("  Network: %s\n", ntcpAddr.Network())
	fmt.Printf("  String:  %s\n", ntcpAddr.String())
	fmt.Printf("  Role:    %s\n", ntcpAddr.Role())
	fmt.Printf("  Router Hash: %x...\n", routerHash[:8])
	fmt.Println()
}

// displayKeyMaterial shows the optional key material
func displayKeyMaterial(remoteRouterHash, staticKey, destHash []byte) {
	if remoteRouterHash != nil {
		fmt.Printf("Remote Router Information:\n")
		fmt.Printf("  Remote Router Hash: %x...\n", remoteRouterHash[:8])
		fmt.Println()
	}
	if staticKey != nil {
		fmt.Printf("Static Key Information:\n")
		fmt.Printf("  Static Key: %x...\n", staticKey[:8])
		fmt.Println()
	}
	if destHash != nil {
		fmt.Printf("Destination Hash:\n")
		fmt.Printf("  Destination Hash: %x...\n", destHash[:8])
		fmt.Println()
	}
}

// demonstrateNTCP2AddressingWithKeys shows NTCP2 addressing with user-provided keys
func demonstrateNTCP2AddressingWithKeys(routerHash, remoteRouterHash, destHash, staticKey []byte) {
	fmt.Println("📍 NTCP2 Addressing with User Keys:")
	fmt.Println("===================================")

	if routerHash == nil {
		fmt.Println("⚠️  No router hash provided - using demo mode")
		demonstrateNTCP2Addressing()
		return
	}

	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 7654,
	}

	ntcpAddr, err := ntcp2.NewNTCP2Addr(tcpAddr, routerHash, "initiator")
	if err != nil {
		log.Fatalf("Failed to create NTCP2 address: %v", err)
	}

	displayAddressInfo(ntcpAddr, routerHash)
	displayKeyMaterial(remoteRouterHash, staticKey, destHash)

	fmt.Println("✅ NTCP2 addressing demonstration completed!")
	fmt.Println("🔗 Use NTCP2 listener/client examples for full connection functionality")
}
