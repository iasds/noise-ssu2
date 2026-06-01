//go:build !ntcp2_debug

package ntcp2

// debug_stub.go — no-op stubs for NTCP2 wire-dump helpers.
//
// When the ntcp2_debug build tag is absent (the default), these stubs replace
// the real implementations in debug.go so that production binaries carry zero
// diagnostic I/O surface and no file-system or env-var reads.

import "sync/atomic"

// msg1WireDumpRemaining and msg3WireDumpRemaining are the zero-value no-op
// counterparts to the atomic counters declared in debug.go. They always read
// as zero so all Load() > 0 guards in the production code path are never
// taken.
var (
	msg1WireDumpRemaining atomic.Int32
	msg3WireDumpRemaining atomic.Int32
)

func dumpMsg1IfEnabled(_ *Config, _ interface{}, _, _ []byte)                 {}
func dumpInboundMsg1IfEnabled(_ *Config, _ interface{}, _, _ []byte, _ error) {}
func classifyMsg2ReadFailure(_ *Config, _ interface{}, _ int, _ error)        {}
func dumpMsg3IfEnabled(_ *Config, _ interface{}, _, _ []byte, _ uint16)       {}
