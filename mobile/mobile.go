// Package mobile exposes wpmulti as a mobile library via gomobile.
//
// Build AAR: gomobile bind -target android/arm64 -o wireproxy.aar github.com/pkok1099/wpmulti/mobile
//
// Semua signature memakai tipe yang didukung gomobile: string, int, bool,
// dan interface. Tanpa channel, tanpa func value, tanpa struct kompleks.
//
// Threading: Start memblokir sampai siap (panggil dari background thread di
// Java/Kotlin). Callback OnSessionUp dipanggil dari worker goroutine —
// implementasi Java harus thread-safe.
package mobile

import (
	"time"
	"net"
	"os"
	"sync"

	wireproxy "github.com/pkok1099/wpmulti"
	"golang.zx2c4.com/wireguard/device"
)

// StatusListener menerima callback status dari engine.
// Implementasikan di Java/Kotlin (atau Swift). Boleh nil = tanpa callback.
type StatusListener interface {
	// OnSessionUp dipanggil tiap sesi berhasil up (bisa dari goroutine berbeda).
	OnSessionUp(up int, total int)
	// OnReady dipanggil sekali saat semua sesi siap dan proxy listen.
	OnReady(total int)
	// OnError dipanggil saat Start gagal.
	OnError(message string)
}

var (
	mu       sync.Mutex
	mt       *wireproxy.MultiTun
	socksLn  net.Listener
	httpLn   net.Listener
	listener StatusListener
	running  bool
)

// SetStatusListener mendaftarkan penerima callback (nil untuk menghapus).
func SetStatusListener(l StatusListener) {
	mu.Lock()
	listener = l
	mu.Unlock()
}

func getListener() StatusListener {
	mu.Lock()
	defer mu.Unlock()
	return listener
}

// SetTempDir sets the directory for temporary files.
// WAJIB dipanggil sebelum Start di Android, dengan context.getCacheDir():
// Go's os.MkdirTemp defaults to /data/local/tmp which apps cannot write.
func SetTempDir(dir string) {
	wireproxy.TempParentDir = dir
	if dir == "" {
		os.Unsetenv("TMPDIR")
	} else {
		os.Setenv("TMPDIR", dir)
	}
}

// Start menjalankan engine: N sesi WireGuard + SOCKS5 + HTTP proxy.
// Memblokir sampai semua sesi siap (~10 detik untuk 1200 sesi).
// Mengembalikan "" jika sukses, pesan error jika gagal.
func Start(configDir, socksAddr, httpAddr string) string {
	mu.Lock()
	if running {
		mu.Unlock()
		return "engine sudah berjalan"
	}
	mu.Unlock()

	// Hook progress ke core tanpa mengubah API CLI.
	wireproxy.OnSessionUpHook = func(up, total int) {
		if l := getListener(); l != nil {
			l.OnSessionUp(up, total)
		}
	}
	defer func() { wireproxy.OnSessionUpHook = nil }()

	m, err := wireproxy.StartMultiTun(configDir, int(device.LogLevelSilent))
	if err != nil {
		wireproxy.OnSessionUpHook = nil
		if l := getListener(); l != nil {
			l.OnError(err.Error())
		}
		return err.Error()
	}

	// Pre-bind kedua listener SEBELUM return sukses, agar error bind
	// (port dipakai) terlaporkan, bukan log.Fatal di goroutine.
	sln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		m.Close()
		wireproxy.OnSessionUpHook = nil
		msg := "socks5 listen: " + err.Error()
		if l := getListener(); l != nil {
			l.OnError(msg)
		}
		return msg
	}
	hln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		sln.Close()
		m.Close()
		wireproxy.OnSessionUpHook = nil
		msg := "http listen: " + err.Error()
		if l := getListener(); l != nil {
			l.OnError(msg)
		}
		return msg
	}

	go m.ServeSocks5(sln)
	go m.ServeHTTP(hln)

	mu.Lock()
	mt = m
	socksLn = sln
	httpLn = hln
	running = true
	mu.Unlock()

	if l := getListener(); l != nil {
		l.OnReady(m.Count())
	}
	return ""
}

// Stop mematikan engine dan menutup listener. Aman dipanggil saat tidak berjalan.
func Stop() {
	mu.Lock()
	m := mt
	sl := socksLn
	hl := httpLn
	mt = nil
	socksLn = nil
	httpLn = nil
	running = false
	mu.Unlock()
	if sl != nil {
		sl.Close()
	}
	if hl != nil {
		hl.Close()
	}
	if m != nil {
		// Close dengan timeout: jangan hang selamanya kalau ada deadlock.
		done := make(chan struct{})
		go func() { m.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

// IsRunning melaporkan apakah engine berjalan.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

// SessionCount mengembalikan jumlah sesi aktif (0 jika tidak berjalan).
func SessionCount() int {
	mu.Lock()
	defer mu.Unlock()
	if mt == nil {
		return 0
	}
	return mt.Count()
}
