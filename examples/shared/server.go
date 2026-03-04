// Package shared provides common utilities for go-noise examples
package shared

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/go-i2p/go-noise"
)

// RunServer creates a Noise listener and runs an accept loop, dispatching
// connections to the provided handler function. This consolidates the common
// server setup pattern duplicated across state, transport, and other examples.
func RunServer(args *CommonArgs, staticKey []byte, label string, handler func(net.Conn)) {
	fmt.Printf("🚀 Starting %s server on %s with pattern %s\n", label, args.ServerAddr, args.Pattern)

	config := noise.NewListenerConfig(args.Pattern).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	listener, err := noise.ListenNoise("tcp", args.ServerAddr, config)
	if err != nil {
		log.Fatalf("Failed to start %s server: %v", label, err)
	}
	defer listener.Close()

	fmt.Printf("✓ %s server listening on: %s\n", capitalize(label), listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handler(conn)
	}
}

// RunClient creates a Noise connection and invokes the provided callback
// with the established connection. This consolidates the common client
// setup pattern duplicated across state, transport, and other examples.
// Pass nil for remoteKey when the pattern does not require one.
func RunClient(args *CommonArgs, staticKey, remoteKey []byte, label string, postConnect func(*noise.NoiseConn)) {
	fmt.Printf("📱 Starting %s client connecting to %s\n", label, args.ClientAddr)

	config := noise.NewConnConfig(args.Pattern, true).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	if remoteKey != nil {
		config = config.WithRemoteKey(remoteKey)
	}

	conn, err := noise.DialNoise("tcp", args.ClientAddr, config)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	fmt.Printf("✓ Connected to server: %s\n", conn.RemoteAddr())

	postConnect(conn)
}

// HandleConnection handles a Noise connection with handshake, optional
// post-handshake callback, and echo loop. This consolidates the common
// connection handler pattern duplicated across state, transport, and other examples.
func HandleConnection(conn net.Conn, echoPrefix string, postHandshake func(*noise.NoiseConn)) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New connection from: %s\n", clientAddr)

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

		if postHandshake != nil {
			postHandshake(noiseConn)
		}
	}

	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("Client %s disconnected\n", clientAddr)
			return
		}

		message := string(buffer[:n])
		fmt.Printf("📨 Received from %s: %s\n", clientAddr, message)

		response := fmt.Sprintf("%s echo: %s", echoPrefix, message)
		conn.Write([]byte(response))
	}
}

// RunDemo2 starts a server in the background, waits briefly, then runs a client.
// This consolidates the common demo pattern duplicated across state, transport,
// and other examples.
func RunDemo2(args *CommonArgs, label string, serverFunc, clientFunc func(*CommonArgs, []byte)) {
	fmt.Printf("🎭 Running %s demo with server and client\n", label)

	staticKey, _, err := ParseKeys(args)
	if err != nil {
		log.Fatalf("Failed to parse keys for demo: %v", err)
	}

	go serverFunc(args, staticKey)
	time.Sleep(200 * time.Millisecond)

	clientArgs := *args
	clientArgs.ClientAddr = args.ServerAddr
	clientArgs.ServerAddr = ""
	clientFunc(&clientArgs, staticKey)
}

// capitalize returns the string with the first letter uppercased.
func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
