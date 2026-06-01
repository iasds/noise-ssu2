package exampleutil

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// AwaitShutdownSignal blocks until SIGINT or SIGTERM is received.
// It then calls cancel and waits for wg to finish (with a 10-second timeout).
func AwaitShutdownSignal(cancel context.CancelFunc, wg *sync.WaitGroup) {
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
