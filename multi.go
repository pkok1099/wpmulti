package wireproxy

// Multi-session support: N WireGuard sessions sharing ONE userspace
// network stack in ONE process, with flows distributed per-connection
// across tunnels by flowMux. This gives N distinct egress IPs at roughly
// the RAM cost of 1 stack + N lightweight WireGuard devices.
//
// ponytail: reuse StartWireguard's config parsing/CreateIPCRequest and
// netstack.CreateNetTUN as-is; the only new logic is the tun.Device
// fan-out (shared.go). No per-session stacks.

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// endpointRe menemukan baris "Endpoint = host:port" di config WireGuard.
var endpointRe = regexp.MustCompile(`(?im)^\s*endpoint\s*=\s*([^\s:;\]]+)(:\d+)?\s*$`)

// resolveHostFallback resolve hostname pakai DNS sistem dulu,
// fallback ke DNS publik kalau DNS sistem mati (mis. [::1]:53 refused).
func resolveHostFallback(host string, cache map[string]string) (string, error) {
	if ip, ok := cache[host]; ok {
		return ip, nil
	}
	resolve := func() (string, error) {
		if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
			return pickIP(ips), nil
		}
		for _, dns := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "udp", dns)
				},
			}
			if ips, err := r.LookupHost(context.Background(), host); err == nil && len(ips) > 0 {
				return pickIP(ips), nil
			}
		}
		return "", fmt.Errorf("DNS gagal untuk %s (sistem + 1.1.1.1 + 8.8.8.8)", host)
	}
	ip, err := resolve()
	if err != nil {
		return "", err
	}
	cache[host] = ip
	return ip, nil
}

// pickIP pilih IPv4 dulu (endpoint WARP paling aman via v4), else ambil yang ada.
func pickIP(ips []string) string {
	for _, s := range ips {
		if addr, err := netip.ParseAddr(s); err == nil && addr.Is4() {
			return s
		}
	}
	return ips[0]
}

// rewriteEndpoints ganti hostname di baris Endpoint= menjadi IP literal,
// supaya ParseConfig tidak tergantung DNS sistem yang bisa mati.
// Hostname yang gagal di-resolve dibiarkan apa adanya (ParseConfig yang akan error jelas).
func rewriteEndpoints(content []byte, cache map[string]string) []byte {
	return endpointRe.ReplaceAllFunc(content, func(m []byte) []byte {
		sub := endpointRe.FindSubmatch(m)
		host := string(sub[1])
		port := string(sub[2])
		if _, err := netip.ParseAddr(host); err == nil {
			return m // sudah IP
		}
		_, cached := cache[host]
		ip, err := resolveHostFallback(host, cache)
		if err != nil {
			log.Printf("peringatan: %v", err)
			return m
		}
		if !cached {
			log.Printf("endpoint %s -> %s%s", host, ip, port)
		}
		return []byte("Endpoint = " + ip + port)
	})
}

// MultiTun holds N WireGuard sessions sharing ONE userspace network
// stack in one process. Tunnel selection happens per-flow inside flowMux
// (round-robin for new flows, sticky after), so proxy dials just use the
// shared stack and never need to pick a session.
type MultiTun struct {
	tnet *netstack.Net
	devs []*device.Device
	mux  *flowMux
	tun  tun.Device // underlying shared device (closed on Close)
}

// StartMultiTun parses every *.conf in confDir and brings up one WireGuard
// session per file, all sharing a single network stack. Each file only
// needs [Interface] + [Peer] (a plain wgcf-profile.conf works); proxy
// sections, if present, are ignored — listeners are configured separately.
// OnSessionUpHook dipanggil tiap sesi berhasil up selama StartMultiTun.
// Nil = mati (default, dipakai CLI). Package mobile mengisinya untuk
// progress callback ke Java/Kotlin. Dipanggil dari worker goroutine.
var OnSessionUpHook func(up, total int)

// TempParentDir overrides the parent directory for temporary files created
// by StartMultiTun (which uses os.MkdirTemp). Empty = system default.
// The mobile package sets this to the app's cache dir because Android apps
// cannot write to the default temp dir (/data/local/tmp).
// (More reliable than TMPDIR env var across Go versions.)
var TempParentDir = ""

func StartMultiTun(confDir string, logLevel int) (*MultiTun, error) {
	entries, err := os.ReadDir(confDir)
	if err != nil {
		return nil, fmt.Errorf("baca conf dir: %w", err)
	}
	var paths []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".conf" {
			paths = append(paths, filepath.Join(confDir, e.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("tidak ada *.conf di %s", confDir)
	}

	// Tulis ulang conf ke temp dir dengan endpoint hostname -> IP,
	// agar tidak tergantung DNS sistem (yang bisa mati total).
	tmpdir, err := os.MkdirTemp(TempParentDir, "wpm-conf-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpdir) }()
	dnsCache := map[string]string{}
	var fixedPaths []string
	for _, p := range paths {
		content, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("baca %s: %w", p, err)
		}
		content = rewriteEndpoints(content, dnsCache)
		fp := filepath.Join(tmpdir, filepath.Base(p))
		if err := os.WriteFile(fp, content, 0600); err != nil {
			return nil, err
		}
		fixedPaths = append(fixedPaths, fp)
	}

	// Satu stack untuk semua sesi. Alamat/DNS/MTU diambil dari conf
	// pertama (setup wgcf-copy: semua conf identik).
	first, err := ParseConfig(fixedPaths[0])
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", paths[0], err)
	}
	setting, err := CreateIPCRequest(first.Device)
	if err != nil {
		return nil, err
	}
	tunDev, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		return nil, fmt.Errorf("buat shared stack: %w", err)
	}

	m := &MultiTun{tnet: tnet, tun: tunDev, mux: newFlowMux(tunDev, len(fixedPaths))}
	var mu sync.Mutex
	var alive []int
	failed := 0
	// Startup paralel (8 worker): tiap sesi independen, jadi aman.
	// Sequential 100 sesi ~90 dtk di HP; paralel ~15 dtk.
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, p := range fixedPaths {
		wg.Add(1)
		go func(i int, p string, origPath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			conf, err := ParseConfig(p)
			if err != nil {
				log.Printf("parse %s: %v (dilewati)", origPath, err)
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			dtun := &deviceTun{Device: tunDev, q: m.mux.queues[i]}
			// noStickyBind: skip netlink route listener (kernel caps them)
			dev := device.NewDevice(dtun, &noStickyBind{conn.NewDefaultBind()}, device.NewLogger(logLevel, ""))
			setting, err := CreateIPCRequest(conf.Device)
			if err != nil {
				dev.Close()
				log.Printf("ipc %s: %v (dilewati)", origPath, err)
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			if err := dev.IpcSet(setting.IpcRequest); err != nil {
				dev.Close()
				log.Printf("ipcset %s: %v (dilewati)", origPath, err)
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			if err := dev.Up(); err != nil {
				dev.Close()
				log.Printf("up %s: %v (dilewati)", origPath, err)
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			mu.Lock()
			m.devs = append(m.devs, dev)
			alive = append(alive, i)
			n := len(m.devs)
			total := len(fixedPaths)
			mu.Unlock()
			log.Printf("sesi %d up: %s", n, origPath)
			if OnSessionUpHook != nil {
				OnSessionUpHook(n, total)
			}
		}(i, p, paths[i])
	}
	wg.Wait()
	if len(m.devs) == 0 {
		_ = tunDev.Close()
		return nil, fmt.Errorf("tidak ada sesi yang berhasil up (%d gagal)", failed)
	}
	if failed > 0 {
		log.Printf("peringatan: %d/%d sesi gagal, lanjut dengan %d sesi",
			failed, len(fixedPaths), len(m.devs))
	}
	m.mux.setAlive(alive)
	m.mux.start()
	return m, nil
}

// Count returns the number of active sessions.
func (m *MultiTun) Count() int { return len(m.devs) }

// SessionStatsJSON returns per-session stats as JSON:
// [{"index":0,"handshake_age_sec":12,"tx_bytes":1234,"rx_bytes":5678}, ...]
// handshake_age_sec = -1 if no handshake yet.
func (m *MultiTun) SessionStatsJSON() string {
	var sb strings.Builder
	sb.WriteString("[")
	now := time.Now().Unix()
	for i, d := range m.devs {
		if i > 0 {
			sb.WriteString(",")
		}
		hsAge := int64(-1)
		var tx, rx int64
		if ipc, err := d.IpcGet(); err == nil {
			for _, line := range strings.Split(ipc, "\n") {
				if strings.HasPrefix(line, "last_handshake_time_sec=") {
					var sec int64
					_, _ = fmt.Sscanf(line, "last_handshake_time_sec=%d", &sec)
					if sec > 0 {
						hsAge = now - sec
					}
				} else if strings.HasPrefix(line, "tx_bytes=") {
					_, _ = fmt.Sscanf(line, "tx_bytes=%d", &tx)
				} else if strings.HasPrefix(line, "rx_bytes=") {
					_, _ = fmt.Sscanf(line, "rx_bytes=%d", &rx)
				}
			}
		}
		fmt.Fprintf(&sb, `{"index":%d,"handshake_age_sec":%d,"tx_bytes":%d,"rx_bytes":%d}`,
			i, hsAge, tx, rx)
	}
	sb.WriteString("]")
	return sb.String()
}

// Close shuts down all sessions and the shared stack.
func (m *MultiTun) Close() {
	for _, d := range m.devs {
		d.Close()
	}
	m.devs = nil
	m.mux.close()
	m.tun.Close()
}

// DialContext dials through the shared stack; flowMux picks the tunnel.
func (m *MultiTun) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return m.tnet.DialContext(ctx, network, address)
}

// dial is the non-context variant for the HTTP proxy.
func (m *MultiTun) dial(network, address string) (net.Conn, error) {
	return m.tnet.Dial(network, address)
}

// Resolve resolves hostnames via the shared stack's DNS (socks5 resolver).
func (m *MultiTun) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := m.tnet.LookupHost(name)
	if err != nil {
		return ctx, nil, err
	}
	for _, s := range addrs {
		if ip := net.ParseIP(s); ip != nil {
			return ctx, ip, nil
		}
	}
	return ctx, nil, fmt.Errorf("tidak ada IP untuk %s", name)
}

// newSocks5Server builds the shared SOCKS5 server (one for all sessions).
func (m *MultiTun) newSocks5Server() *socks5.Server {
	options := []socks5.Option{
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.NoAuthAuthenticator{}}),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
		socks5.WithDial(m.DialContext),
		socks5.WithResolver(m),
	}
	return socks5.NewServer(options...)
}

// ServeSocks5 serves SOCKS5 on a pre-bound listener (for library use,
// where bind errors must be reported instead of log.Fatal).
func (m *MultiTun) ServeSocks5(ln net.Listener) error {
	return m.newSocks5Server().Serve(ln)
}

// SpawnSocks5 starts ONE SOCKS5 listener shared by all sessions.
// Tunnel selection happens per-flow inside flowMux.
func (m *MultiTun) SpawnSocks5(bindAddress string) {
	server := m.newSocks5Server()
	log.Printf("SOCKS5 %s -> %d sesi (shared stack)", bindAddress, m.Count())
	if err := server.ListenAndServe("tcp", bindAddress); err != nil {
		log.Fatal(err)
	}
}

// newHTTPServer builds the shared HTTP proxy server (one for all sessions).
func (m *MultiTun) newHTTPServer(bindAddress string) *HTTPServer {
	return &HTTPServer{
		config: &HTTPConfig{BindAddress: bindAddress},
		dial:   m.dial,
		auth:   CredentialValidator{},
	}
}

// ServeHTTP serves the HTTP proxy on a pre-bound listener (for library use,
// where bind errors must be reported instead of log.Fatal).
func (m *MultiTun) ServeHTTP(ln net.Listener) error {
	return m.newHTTPServer("").Serve(ln)
}

// SpawnHTTP starts ONE HTTP proxy listener shared by all sessions.
func (m *MultiTun) SpawnHTTP(bindAddress string) {
	server := m.newHTTPServer(bindAddress)
	log.Printf("HTTP %s -> %d sesi (shared stack)", bindAddress, m.Count())
	if err := server.ListenAndServe("tcp", bindAddress); err != nil {
		log.Fatal(err)
	}
}
