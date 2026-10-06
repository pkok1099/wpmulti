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
                // Optimasi RAM: 128 slot (sebelumnya 512). Dengan 1200 sesi,
                // 512 slot/channel = ~6MB channel + paket-paket yang menumpuk
                // di dalamnya. 128 cukup: queue penuh -> drop -> TCP di
                // netstack retransmit (jalur penanganannya sudah ada).
                m.queues[i] = make(chan []byte, 128)
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
//
// Dipanggil untuk SETIAP paket keluar (jalur panas): key dibangun ke
// buffer stack tanpa fmt.Sprintf (sebelumnya beberapa alokasi + boxing
// per paket -> tekanan GC tinggi saat throughput besar).
func flowKey(pkt []byte) string {
        if len(pkt) < 1 {
                return ""
        }
        var buf [80]byte // v6 + ports = 73 byte maksimum
        switch pkt[0] >> 4 {
        case 4:
                if len(pkt) < 20 {
                        return ""
                }
                proto := pkt[9]
                if proto != 6 && proto != 17 {
                        return string(appendKey(buf[:0], proto,
                                pkt[12:16], pkt[16:20], 0, 0, false))
                }
                hlen := int(pkt[0]&0x0f) * 4
                if len(pkt) < hlen+4 {
                        return string(appendKey(buf[:0], proto,
                                pkt[12:16], pkt[16:20], 0, 0, false))
                }
                return string(appendKey(buf[:0], proto,
                        pkt[12:16], pkt[16:20],
                        binary.BigEndian.Uint16(pkt[hlen:]),
                        binary.BigEndian.Uint16(pkt[hlen+2:]), true))
        case 6:
                if len(pkt) < 40 {
                        return ""
                }
                proto := pkt[6]
                // NB: IPv6 extension headers not handled (our traffic has none).
                if (proto != 6 && proto != 17) || len(pkt) < 44 {
                        return string(appendKey(buf[:0], proto,
                                pkt[8:24], pkt[24:40], 0, 0, false))
                }
                return string(appendKey(buf[:0], proto,
                        pkt[8:24], pkt[24:40],
                        binary.BigEndian.Uint16(pkt[40:]),
                        binary.BigEndian.Uint16(pkt[42:]), true))
        }
        return ""
}

// appendKey menulis "proto|src|dst[|p1|p2]" ke dst (kapasitas cukup).
func appendKey(dst []byte, proto byte, src, dstA []byte,
        p1, p2 uint16, ports bool) []byte {
        dst = append(dst, proto, '|')
        dst = appendHex(dst, src)
        dst = append(dst, '|')
        dst = appendHex(dst, dstA)
        if ports {
                dst = append(dst, '|')
                dst = append(dst, byte(p1>>8), byte(p1), '|')
                dst = append(dst, byte(p2>>8), byte(p2))
        }
        return dst
}

func appendHex(dst, s []byte) []byte {
        const hexd = "0123456789abcdef"
        for _, c := range s {
                dst = append(dst, hexd[c>>4], hexd[c&0x0f])
        }
        return dst
}
