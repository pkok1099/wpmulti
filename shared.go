package wireproxy

// Shared-stack multi-session: ONE gVisor netstack shared by N WireGuard
// devices in one process. Outbound packets are dispatched per-flow
// (5-tuple) — round-robin for new flows, sticky affinity for existing
// ones — so a TCP connection never splits across tunnels (which would
// break it: the server would see two source IPs for one connection).
//
// Memory: ~12MB for the single stack + ~0.3MB per WireGuard device,
// vs ~13MB per session when every session carries its own full stack.
//
// ponytail: reuse netstack.CreateNetTUN for the stack; only the
// tun.Device fan-out (flowMux + deviceTun) is new.

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

type flowEntry struct {
	devIdx   int
	lastSeen time.Time
}

// noStickyBind wraps conn.Bind to disable wireguard-go's netlink route
// listener (sticky sockets). Each device otherwise creates a netlink
// socket bound to RTMGRP_IPV4_ROUTE, and kernels (notably Android's)
// cap multicast group memberships — killing us at ~75 devices with
// EINVAL. We don't need route-change notifications for short-lived
// proxied connections. startRouteListener skips non-*StdNetBind types.
type noStickyBind struct {
	conn.Bind
}

// flowMux demultiplexes outbound packets from the shared stack to N
// WireGuard devices, with per-flow tunnel affinity.
type flowMux struct {
	tun     tun.Device
	queues  []chan []byte
	alive   []int // indices of working devices
	aliveMu sync.RWMutex
	flows   map[string]*flowEntry
	flowsMu sync.Mutex
	rr      uint64
	closed  chan struct{}
	wg      sync.WaitGroup
	dropped uint64
}

func newFlowMux(t tun.Device, n int) *flowMux {
	m := &flowMux{
		tun:    t,
		queues: make([]chan []byte, n),
		flows:  make(map[string]*flowEntry),
		closed: make(chan struct{}),
	}
	for i := range m.queues {
		m.queues[i] = make(chan []byte, 512)
	}
	return m
}

// setAlive records which device indices actually came up; round-robin
// only picks from these. Called once after startup.
func (m *flowMux) setAlive(alive []int) {
	m.aliveMu.Lock()
	m.alive = alive
	m.aliveMu.Unlock()
}

func (m *flowMux) pickAlive() int {
	m.aliveMu.RLock()
	defer m.aliveMu.RUnlock()
	if len(m.alive) == 0 {
		return 0
	}
	n := atomic.AddUint64(&m.rr, 1)
	return m.alive[(n-1)%uint64(len(m.alive))]
}

// start launches the dispatcher and idle-flow sweeper.
func (m *flowMux) start() {
	m.wg.Add(1)
	go m.dispatch()
	m.wg.Add(1)
	go m.sweep()
}

func (m *flowMux) dispatch() {
	defer m.wg.Done()
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 65536)
	sizes := make([]int, 1)
	for {
		select {
		case <-m.closed:
			return
		default:
		}
		n, err := m.tun.Read(bufs, sizes, 0)
		if err != nil {
			select {
			case <-m.closed:
				return
			default:
				log.Printf("flowMux read: %v", err)
				continue
			}
		}
		for i := 0; i < n; i++ {
			pkt := make([]byte, sizes[i])
			copy(pkt, bufs[0][:sizes[i]])
			m.route(pkt)
		}
	}
}

func (m *flowMux) route(pkt []byte) {
	key := flowKey(pkt)
	m.flowsMu.Lock()
	e, ok := m.flows[key]
	if !ok {
		e = &flowEntry{devIdx: m.pickAlive()}
		m.flows[key] = e
	}
	e.lastSeen = time.Now()
	idx := e.devIdx
	m.flowsMu.Unlock()

	// Drop (don't block) on a full queue: TCP retransmits, and this
	// stops one slow tunnel from stalling all the others.
	select {
	case m.queues[idx] <- pkt:
	default:
		atomic.AddUint64(&m.dropped, 1)
	}
}

// sweep drops flows idle for >10 minutes so the table stays bounded.
func (m *flowMux) sweep() {
	defer m.wg.Done()
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.closed:
			return
		case <-t.C:
			cutoff := time.Now().Add(-10 * time.Minute)
			m.flowsMu.Lock()
			for k, e := range m.flows {
				if e.lastSeen.Before(cutoff) {
					delete(m.flows, k)
				}
			}
			m.flowsMu.Unlock()
		}
	}
}

func (m *flowMux) close() {
	close(m.closed)
	m.wg.Wait()
	for _, q := range m.queues {
		close(q)
	}
	if d := atomic.LoadUint64(&m.dropped); d > 0 {
		log.Printf("flowMux: %d paket dibuang (queue penuh)", d)
	}
}

// deviceTun is the tun.Device seen by ONE WireGuard device. Read pops
// outbound packets assigned to this device; Write injects inbound
// packets into the shared stack. Everything else delegates to the
// underlying shared device.
type deviceTun struct {
	tun.Device // Name, File, Events, MTU, BatchSize
	q          chan []byte
}

func (d *deviceTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-d.q
	if !ok {
		return 0, os.ErrClosed
	}
	n := copy(bufs[0][offset:], pkt)
	sizes[0] = n
	return 1, nil
}

// Close is a no-op: the underlying device is shared and closed by flowMux.
func (d *deviceTun) Close() error { return nil }

// flowKey extracts a 5-tuple (3-tuple for non-TCP/UDP) from an IP packet.
// Unparseable packets share the "" flow.
func flowKey(pkt []byte) string {
	if len(pkt) < 1 {
		return ""
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return ""
		}
		proto := pkt[9]
		src, dst := pkt[12:16], pkt[16:20]
		if proto != 6 && proto != 17 {
			return fmt.Sprintf("%d|%x|%x", proto, src, dst)
		}
		hlen := int(pkt[0]&0x0f) * 4
		if len(pkt) < hlen+4 {
			return fmt.Sprintf("%d|%x|%x", proto, src, dst)
		}
		return fmt.Sprintf("%d|%x|%x|%d|%d", proto, src, dst,
			binary.BigEndian.Uint16(pkt[hlen:]),
			binary.BigEndian.Uint16(pkt[hlen+2:]))
	case 6:
		if len(pkt) < 40 {
			return ""
		}
		proto := pkt[6]
		src, dst := pkt[8:24], pkt[24:40]
		if proto != 6 && proto != 17 {
			return fmt.Sprintf("%d|%x|%x", proto, src, dst)
		}
		// NB: IPv6 extension headers not handled (our traffic has none).
		if len(pkt) < 44 {
			return fmt.Sprintf("%d|%x|%x", proto, src, dst)
		}
		return fmt.Sprintf("%d|%x|%x|%d|%d", proto, src, dst,
			binary.BigEndian.Uint16(pkt[40:]),
			binary.BigEndian.Uint16(pkt[40+2:]))
	}
	return ""
}
