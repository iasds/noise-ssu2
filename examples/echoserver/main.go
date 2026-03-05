// Example: Echo Server using Noise Protocol with complete handshake
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	shared.RunExample(
		"echoserver",
		"Noise Protocol echo server supporting all patterns",
		"localhost:8080",
		"",
		func(_ *shared.CommonArgs) { shared.RunDemo() },
		runEchoServer,
		nil,
	)
}

// runEchoServer starts an echo server with complete Noise handshake
func runEchoServer(args *shared.CommonArgs, staticKey []byte) {
	shared.RunServer(args, staticKey, "echo", func(conn net.Conn) {
		handleEchoConnection(conn, args)
	})
}

// performServerHandshake performs the Noise handshake for a server connection
func performServerHandshake(conn net.Conn, clientAddr string, timeout time.Duration) bool {
	if noiseConn, ok := conn.(*noise.NoiseConn); ok {
		fmt.Printf("🔐 Starting handshake with %s...\n", clientAddr)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		err := noiseConn.Handshake(ctx)
		if err != nil {
			log.Printf("Handshake failed with %s: %v", clientAddr, err)
			return false
		}
		fmt.Printf("✅ Handshake completed with %s\n", clientAddr)
	}
	return true
}

// runEchoLoop reads messages and echoes them back until disconnect
func runEchoLoop(conn net.Conn, clientAddr string) {
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error from %s: %v", clientAddr, err)
			}
			break
		}
		message := strings.TrimSpace(string(buffer[:n]))
		fmt.Printf("📨 Received from %s: %q\n", clientAddr, message)
		if message == "quit" {
			fmt.Printf("👋 Client %s requested disconnect\n", clientAddr)
			break
		}
		response := fmt.Sprintf("Echo: %s", message)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("Write error to %s: %v", clientAddr, err)
			break
		}
		fmt.Printf("📤 Sent to %s: %q\n", clientAddr, response)
	}
}

// handleEchoConnection handles a single echo connection with handshake
func handleEchoConnection(conn net.Conn, args *shared.CommonArgs) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New client connected: %s\n", clientAddr)

	if !performServerHandshake(conn, clientAddr, args.HandshakeTimeout) {
		return
	}

	runEchoLoop(conn, clientAddr)

	fmt.Printf("🔌 Client %s disconnected\n", clientAddr)
}
