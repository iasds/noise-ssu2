package server

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/go-i2p/logger"
)

// incomingPacket holds a received packet and its source address for worker processing.
type incomingPacket struct {
	data       []byte
	remoteAddr *net.UDPAddr
}

// packetWorkers is the number of goroutines in the packet processing pool.
const packetWorkers = 8

// packetQueueSize is the buffer size for the incoming packet channel.
// Packets arriving when the queue is full are dropped.
const packetQueueSize = 256

// receiveLoop continuously reads packets from the underlying connection
// and routes them to appropriate sessions or creates new sessions.
// M-2: Blocking ReadFrom is used instead of 100ms deadline polling.
// The loop exits when the underlying connection is closed by Close().
//
// Design:
// - Reads UDP datagrams from the underlying PacketConn
// - Copies each datagram into the packet queue for worker pool processing
// - Implements exponential backoff on ReadFrom errors to prevent CPU spin
// - Drops packets silently when the queue is full (tracked in droppedPackets)
//
// Thread safety: This is the sole goroutine reading from the underlying socket.
func (l *SSU2Listener) receiveLoop() {
	log.WithFields(logger.Fields{"pkg": "server", "func": "receiveLoop"}).Debug("receiveLoop: starting packet receive loop")
	defer l.wg.Done()

	buf := make([]byte, MaxPacketSizeIPv4)

	const (
		backoffMin = 5 * time.Millisecond
		backoffMax = time.Second
	)
	backoff := backoffMin

	for {
		n, remoteAddr, err := l.underlying.ReadFrom(buf)
		if err != nil {
			// Check if we're shutting down
			select {
			case <-l.shutdownChan:
				return
			default:
			}
			// Log non-shutdown errors and apply exponential backoff to
			// prevent CPU-spin when the socket enters a persistent error state.
			log.WithFields(logger.Fields{"pkg": "server", "func": "receiveLoop"}).
				WithError(err).Warn("receiveLoop: ReadFrom error; backing off")
			select {
			case <-l.shutdownChan:
				return
			case <-time.After(backoff):
			}
			if backoff < backoffMax {
				backoff *= 2
				if backoff > backoffMax {
					backoff = backoffMax
				}
			}
			continue
		}
		// Reset backoff on successful read.
		backoff = backoffMin

		udpAddr, ok := remoteAddr.(*net.UDPAddr)
		if !ok {
			continue
		}

		log.WithFields(logger.Fields{
			"pkg":        "server",
			"func":       "receiveLoop",
			"bytes":      n,
			"remoteAddr": udpAddr.String(),
		}).Info("receiveLoop: received UDP packet")

		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		select {
		case l.packetQueue <- incomingPacket{data: packetData, remoteAddr: udpAddr}:
		default:
			// packetQueue is full - drop packet and warn
			atomic.AddUint64(&l.droppedPackets, 1)
			log.WithFields(logger.Fields{
				"pkg":        "server",
				"func":       "receiveLoop",
				"remoteAddr": udpAddr.String(),
				"dropped":    atomic.LoadUint64(&l.droppedPackets),
			}).Warn("packetQueue full, dropping packet")
		}
	}
}

// packetWorker drains the packet queue and processes packets.
// Multiple workers run concurrently as a bounded pool.
//
// Design:
// - Each worker runs in its own goroutine (pool size = packetWorkers)
// - Workers block on packetQueue until a packet arrives or shutdown is signaled
// - Packet processing is delegated to handleIncomingPacket
//
// Thread safety: Multiple workers run concurrently; packet processing must be safe.
func (l *SSU2Listener) packetWorker() {
	log.WithFields(logger.Fields{"pkg": "server", "func": "packetWorker"}).Debug("packetWorker: starting packet processing worker")
	defer l.wg.Done()

	for {
		select {
		case pkt, ok := <-l.packetQueue:
			if !ok {
				return
			}
			l.handleIncomingPacket(pkt.data, pkt.remoteAddr)
		case <-l.shutdownChan:
			return
		}
	}
}

// handleIncomingPacket processes a received packet and routes it appropriately.
// This is called in a goroutine for each received packet.
//
// Architecture (matching i2pd SSU2Server::ProcessNextPacket):
//
//  1. FAST PATH — connID-only demux: If the listener has an intro key, extract
//     the destination connID from the raw packet using ONLY the intro key
//     (per SSU2 spec, connID is always masked with receiver's intro key regardless
//     of packet phase). If a registered session matches, deliver the raw bytes
//     to the session for full decryption with its own session-specific keys.
//     This avoids the listener needing to know session-derived keys.
//
//  2. SLOW PATH — full parse: For new-session packets (SessionRequest, TokenRequest)
//     where no session exists yet, fall back to full header-protection decrypt +
//     Deserialize, then route via PacketRouter which creates new sessions.
//
// This two-phase approach fixes the root cause where SessionCreated packets
// (encrypted with SessCreateHeader key) were silently dropped because the
// listener's intro-key-based header protector couldn't fully decrypt them.
func (l *SSU2Listener) handleIncomingPacket(data []byte, remoteAddr *net.UDPAddr) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "handleIncomingPacket", "remote_addr": remoteAddr.String(), "data_len": len(data)}).Debug("handleIncomingPacket: processing received packet")

	// FAST PATH: Extract connID from raw bytes and route to existing session.
	// Per SSU2 spec, the destination connID (bytes 0-7) is ALWAYS masked with
	// the receiver's intro key, regardless of packet phase. This lets us demux
	// without knowing session-specific keys.
	if l.introHeaderProtector != nil && len(data) >= 32 {
		introKey := l.getIntroKey()
		if len(introKey) == 32 {
			if connID, err := ExtractConnIDWithIntroKey(data, introKey); err == nil {
				log.WithFields(logger.Fields{
					"pkg":        "server",
					"func":       "handleIncomingPacket",
					"connID":     connID,
					"remoteAddr": remoteAddr.String(),
				}).Info("handleIncomingPacket: fast path connID extracted")
				if conn := l.router.GetSession(connID); conn != nil {
					// Existing session found — deliver raw bytes for session-level
					// decryption using session-specific keys.
					conn.DeliverRawPacket(data, remoteAddr)
					return
				}
				log.WithFields(logger.Fields{
					"pkg":    "server",
					"func":   "handleIncomingPacket",
					"connID": connID,
				}).Info("handleIncomingPacket: fast path no session found for connID")
			} else {
				log.WithFields(logger.Fields{
					"pkg":    "server",
					"func":   "handleIncomingPacket",
					"error":  err.Error(),
				}).Info("handleIncomingPacket: fast path connID extraction failed")
			}
		}
	}

	// SLOW PATH: Full parse for new-session packets.
	log.WithFields(logger.Fields{
		"pkg":        "server",
		"func":       "handleIncomingPacket",
		"remoteAddr": remoteAddr.String(),
		"data_len":   len(data),
	}).Info("handleIncomingPacket: entering slow path for new session")
	packet, ok := l.parseInboundPacket(data)
	if !ok {
		log.WithFields(logger.Fields{
			"pkg":        "server",
			"func":       "handleIncomingPacket",
			"remoteAddr": remoteAddr.String(),
		}).Info("handleIncomingPacket: slow path parse failed, dropping packet")
		return
	}

	// Route packet to appropriate handler
	if err := l.router.RoutePacket(packet, remoteAddr); err != nil {
		// Routing failed, check if this is a token request
		if packet.MessageType == MessageTypeTokenRequest {
			_ = l.processTokenRequest(packet, remoteAddr)
		}
		// Otherwise ignore error
	}
}
