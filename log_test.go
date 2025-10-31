package noise

import (
	"os"
	"testing"

	"github.com/go-i2p/logger"
)

func TestLoggerInitialization(t *testing.T) {
	// Test that the global logger is initialized
	if log == nil {
		t.Errorf("Global logger should not be nil")
	}

	// Test that it's a go-i2p logger instance
	// Since log is already *logger.Logger, we just need to verify it's not nil
	if log == nil {
		t.Errorf("log should be a valid Logger instance")
	}
}

func TestLoggerAccess(t *testing.T) {
	// Test that we can access the logger
	testLogger := logger.GetGoI2PLogger()
	if testLogger == nil {
		t.Errorf("GetGoI2PLogger should not return nil")
	}

	// Test that multiple calls return the same instance (singleton pattern)
	testLogger2 := logger.GetGoI2PLogger()
	if testLogger != testLogger2 {
		t.Errorf("GetGoI2PLogger should return the same instance")
	}

	// Test that our global log variable is the same instance
	if log != testLogger {
		t.Errorf("Global log variable should be the same as GetGoI2PLogger()")
	}
}

func TestLoggerUsage(t *testing.T) {
	// Test that we can use the logger without panics
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Logger usage should not panic: %v", r)
		}
	}()

	// These should not panic
	log.Debug("Test debug message")
	log.Info("Test info message")
	log.Warn("Test warn message")
}

// TestLoggerWithStructuredFields verifies structured logging works correctly
func TestLoggerWithStructuredFields(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Structured logging should not panic: %v", r)
		}
	}()

	// Test WithField
	log.WithField("test_key", "test_value").Debug("Test with single field")

	// Test WithFields
	log.WithFields(logger.Fields{
		"pattern":     "XX",
		"initiator":   true,
		"local_addr":  "127.0.0.1:8080",
		"remote_addr": "127.0.0.1:9090",
	}).Info("Test with multiple fields")

	// Test WithError
	testErr := os.ErrNotExist
	log.WithError(testErr).Error("Test with error context")

	// Test chaining
	log.WithField("key1", "value1").
		WithField("key2", "value2").
		WithError(testErr).
		Warn("Test chained logging")
}

// TestLoggerEnvironmentControl tests logging behavior with environment variables
func TestLoggerEnvironmentControl(t *testing.T) {
	tests := []struct {
		name       string
		debugValue string
		warnFail   string
		shouldLog  bool
	}{
		{
			name:       "Logging disabled by default",
			debugValue: "",
			warnFail:   "",
			shouldLog:  false,
		},
		{
			name:       "Debug logging enabled",
			debugValue: "debug",
			warnFail:   "",
			shouldLog:  true,
		},
		{
			name:       "Fast-fail mode enabled",
			debugValue: "debug",
			warnFail:   "true",
			shouldLog:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original environment
			originalDebug := os.Getenv("DEBUG_I2P")
			originalWarnFail := os.Getenv("WARNFAIL_I2P")
			defer func() {
				if originalDebug != "" {
					os.Setenv("DEBUG_I2P", originalDebug)
				} else {
					os.Unsetenv("DEBUG_I2P")
				}
				if originalWarnFail != "" {
					os.Setenv("WARNFAIL_I2P", originalWarnFail)
				} else {
					os.Unsetenv("WARNFAIL_I2P")
				}
			}()

			// Set test environment
			if tt.debugValue != "" {
				os.Setenv("DEBUG_I2P", tt.debugValue)
			} else {
				os.Unsetenv("DEBUG_I2P")
			}
			if tt.warnFail != "" {
				os.Setenv("WARNFAIL_I2P", tt.warnFail)
			} else {
				os.Unsetenv("WARNFAIL_I2P")
			}

			// Test that logging doesn't panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Logging should not panic with environment %s: %v", tt.name, r)
				}
			}()

			log.WithFields(logger.Fields{
				"test":        tt.name,
				"debug_value": tt.debugValue,
				"warn_fail":   tt.warnFail,
			}).Debug("Test environment configuration")
		})
	}
}

// TestLoggerConcurrentUsage verifies thread-safety of logging
func TestLoggerConcurrentUsage(t *testing.T) {
	const numGoroutines = 10
	const numLogsPerGoroutine = 100

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Goroutine %d panicked: %v", id, r)
				}
				done <- true
			}()

			for j := 0; j < numLogsPerGoroutine; j++ {
				log.WithFields(logger.Fields{
					"goroutine": id,
					"iteration": j,
				}).Debug("Concurrent logging test")
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestLoggerLevels tests different log levels
func TestLoggerLevels(t *testing.T) {
	// Save original environment
	originalDebug := os.Getenv("DEBUG_I2P")
	defer func() {
		if originalDebug != "" {
			os.Setenv("DEBUG_I2P", originalDebug)
		} else {
			os.Unsetenv("DEBUG_I2P")
		}
	}()

	// Enable debug logging for this test
	os.Setenv("DEBUG_I2P", "debug")

	tests := []struct {
		name  string
		logFn func(string)
	}{
		{"Debug level", func(msg string) { log.Debug(msg) }},
		{"Info level", func(msg string) { log.Info(msg) }},
		{"Warn level", func(msg string) { log.Warn(msg) }},
		{"Error level", func(msg string) { log.Error(msg) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Log level %s should not panic: %v", tt.name, r)
				}
			}()

			tt.logFn("Test message for " + tt.name)
		})
	}
}
