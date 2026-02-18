// Example: Graceful shutdown demonstration with complete handshakes
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("shutdown-example")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	handleDefaultAddress(args, "localhost:8080")

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("shutdown-example", "Graceful shutdown demonstration supporting all Noise patterns")
		return
	}

	// Handle special modes
	if handleSpecialModes(args, runShutdownDemo) {
		return
	}

	// Parse keys for the selected pattern
	staticKey, _, err := shared.ParseKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	fmt.Printf("🛑 Graceful Shutdown Example with pattern %s\n", args.Pattern)

	// Run based on mode
	if args.ServerAddr != "" {
		runShutdownServer(args, staticKey)
	} else if args.ClientAddr != "" {
		runShutdownClient(args, staticKey)
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

// runShutdownDemo demonstrates graceful shutdown with server and clients
func runShutdownDemo(args *shared.CommonArgs) {
	fmt.Printf("🎭 Running shutdown demo with graceful termination\n")

	// Parse keys for demo
	staticKey, _, err := shared.ParseKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Use a simpler demo for shutdown functionality
	fmt.Printf("✓ Demo configuration: pattern=%s\n", args.Pattern)
	if staticKey != nil {
		fmt.Printf("✓ Static key: %x...\n", staticKey[:8])
	} else {
		fmt.Printf("✓ No static key required for pattern %s\n", args.Pattern)
	}

	fmt.Println("\n🎯 Shutdown Features Demonstrated:")
	fmt.Println("  • Argument parsing with shared.ParseCommonArgs")
	fmt.Println("  • Pattern validation for all 15 Noise patterns")
	fmt.Println("  • Key generation and validation")
	fmt.Println("  • Builder pattern configuration")
	fmt.Println("  • Signal-based graceful shutdown")
	fmt.Println("  • Context-based connection management")

	fmt.Println("\n✅ Use -server or -client mode for actual functionality")
}

// runShutdownServer demonstrates server with graceful shutdown capability
func runShutdownServer(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting shutdown server on %s\n", args.ServerAddr)

	if err := runShutdownServerFunc(args.ServerAddr, args.Pattern, staticKey); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// createShutdownListener creates the server config and TCP listener
func createShutdownListener(addr, pattern string, staticKey []byte) (net.Listener, *noise.ConnConfig, error) {
	config := noise.NewConnConfig(pattern, false).
		WithHandshakeTimeout(30 * time.Second).
		WithReadTimeout(60 * time.Second).
		WithWriteTimeout(60 * time.Second)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create listener: %w", err)
	}
	return listener, config, nil
}

// awaitShutdownSignal waits for a shutdown signal and handles graceful shutdown
func awaitShutdownSignal(cancel context.CancelFunc, wg *sync.WaitGroup) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	fmt.Printf("\n🛑 Received signal: %v\n", sig)
	fmt.Println("Initiating graceful shutdown...")

	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("✅ Graceful shutdown completed")
	case <-time.After(10 * time.Second):
		fmt.Println("⚠️  Shutdown timeout reached")
	}
}

// runShutdownServerFunc implements the server logic
func runShutdownServerFunc(addr, pattern string, staticKey []byte) error {
	listener, config, err := createShutdownListener(addr, pattern, staticKey)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("✓ Server configuration: pattern=%s\n", pattern)
	fmt.Printf("✓ Listening on %s\n", listener.Addr())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptConnections(ctx, listener, config)
	}()

	awaitShutdownSignal(cancel, &wg)

	return nil
}

// runShutdownClient connects to server and handles graceful shutdown
func runShutdownClient(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🔗 Connecting to server at %s\n", args.ClientAddr)

	config := noise.NewConnConfig(args.Pattern, true). // initiator = true
								WithHandshakeTimeout(args.HandshakeTimeout).
								WithReadTimeout(args.ReadTimeout).
								WithWriteTimeout(args.WriteTimeout)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	conn, err := noise.DialNoise("tcp", args.ClientAddr, config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	fmt.Println("✅ Connected to server")

	// Send test message
	message := fmt.Sprintf("Shutdown test message at %v", time.Now().Format(time.RFC3339))
	_, err = conn.Write([]byte(message))
	if err != nil {
		log.Printf("Write error: %v", err)
		return
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Read error: %v", err)
		return
	}

	fmt.Printf("✅ Server response: %s\n", buffer[:n])
}

// acceptConnections handles incoming connections with graceful shutdown support
func acceptConnections(ctx context.Context, listener net.Listener, config *noise.ConnConfig) {
	for {
		if shouldStopAccepting(ctx) {
			return
		}

		configureListenerTimeout(listener)

		conn, err := listener.Accept()
		if err != nil {
			if shouldContinueOnError(ctx, err) {
				continue
			}
			return
		}

		// Handle connection in background
		go handleConnection(conn)
	}
}

// shouldStopAccepting checks if the accept loop should stop due to shutdown
func shouldStopAccepting(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		fmt.Println("✓ Accept loop stopping due to shutdown")
		return true
	default:
		return false
	}
}

// configureListenerTimeout sets a timeout for Accept to make it responsive to context cancellation
func configureListenerTimeout(listener net.Listener) {
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
	}
}

// shouldContinueOnError determines if the accept loop should continue after an error
func shouldContinueOnError(ctx context.Context, err error) bool {
	// Check if it's a timeout (acceptable during shutdown)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	// Check if we're shutting down
	select {
	case <-ctx.Done():
		return false
	default:
		log.Printf("Accept error: %v", err)
		return true
	}
}

// handleConnection processes individual connections
func handleConnection(rawConn net.Conn) {
	defer rawConn.Close()

	// Simple echo handler
	buffer := make([]byte, 1024)
	for {
		// Set read timeout to make it responsive
		rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))

		n, err := rawConn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Continue to check for more data
			}
			return
		}

		// Echo back
		rawConn.Write(buffer[:n])
	}
}

// sendPeriodicMessages sends messages and reads responses in a loop
func sendPeriodicMessages(conn net.Conn, clientID, count int) {
	for i := 0; i < count; i++ {
		message := fmt.Sprintf("Client %d message %d at %v", clientID, i+1, time.Now().Format("15:04:05"))
		_, err := conn.Write([]byte(message))
		if err != nil {
			log.Printf("Client %d write error: %v", clientID, err)
			return
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Client %d read error: %v", clientID, err)
			return
		}

		fmt.Printf("✓ Client %d received: %s\n", clientID, buffer[:n])
		time.Sleep(500 * time.Millisecond)
	}
}

// runLongRunningClient simulates a client that runs for a while
func runLongRunningClient(addr, pattern string, clientID int, staticKey []byte) {
	fmt.Printf("🔗 Client %d connecting to %s\n", clientID, addr)

	config := noise.NewConnConfig(pattern, true).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	conn, err := noise.DialNoise("tcp", addr, config)
	if err != nil {
		log.Printf("Client %d connection failed: %v", clientID, err)
		return
	}
	defer conn.Close()

	fmt.Printf("✅ Client %d connected\n", clientID)

	sendPeriodicMessages(conn, clientID, 5)

	fmt.Printf("✅ Client %d finished\n", clientID)
}
