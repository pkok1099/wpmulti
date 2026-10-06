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
	"encoding/json"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sync"
	"time"

	wireproxy "github.com/pkok1099/wpmulti"
	"golang.zx2c4.com/wireguard/device"
)

func init() {
	// Optimasi RAM (permintaan): GC lebih agresif menahan heap Go
	// ~25-30% lebih kecil dibanding default GOGC=100, dengan biaya
	// CPU yang kecil untuk beban proxy. Aman: tidak pernah gagal
	// alokasi, frekuensi GC saja yang naik.
	debug.SetGCPercent(50)
}

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
	// starting menutup TOCTOU Start(): dua pemanggil konkuren bisa
	// lolos cek "running" karena StartMultiTun memblokir belasan
	// detik -> dua engine penuh. Dengan starting, pemanggil kedua
	// langsung ditolak sejak frame pertama, bukan setelah spin-up.
	starting bool
	logFile  *os.File
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

// SetLogFile mengarahkan output log standar Go (log.Printf) ke file.
// Dipanggil ulang aman: file lama ditutup. Path kosong = kembali ke stderr.
func SetLogFile(path string) {
	mu.Lock()
	defer mu.Unlock()
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
	if path == "" {
		log.SetOutput(os.Stderr)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("setLogFile %s: %v", path, err)
		return
	}
	// Rotasi sederhana anti-disk-penuh: >5MB -> geser ke path.old,
	// mulai file baru. (Sebelumnya O_APPEND tanpa batas: log tumbuh
	// tanpa henti selama app terpasang berminggu-minggu.)
	if fi, serr := f.Stat(); serr == nil && fi.Size() > 5<<20 {
		f.Close()
		os.Rename(path, path+".old")
		f, err = os.OpenFile(path,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0600)
		if err != nil {
			log.Printf("setLogFile rotate %s: %v", path, err)
			return
		}
	}
	logFile = f
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags)
}

// Start menjalankan engine: N sesi WireGuard + SOCKS5 + HTTP proxy.
// Memblokir sampai semua sesi siap (~10 detik untuk 1200 sesi).
// Mengembalikan "" jika sukses, pesan error jika gagal.
func Start(configDir, socksAddr, httpAddr string) string {
	mu.Lock()
	if running || starting {
		mu.Unlock()
		return "engine sudah berjalan"
	}
	starting = true
	mu.Unlock()
	// Semua jalur keluar di bawah ini WAJIB starting = false.
	defer func() { mu.Lock(); starting = false; mu.Unlock() }()

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

// SessionStats mengembalikan statistik per sesi sebagai JSON array:
// [{"index":0,"handshake_age_sec":12,"tx_bytes":1234,"rx_bytes":5678}, ...]
// Mengembalikan "[]" saat engine tidak berjalan.
func SessionStats() string {
	mu.Lock()
	m := mt
	mu.Unlock()
	if m == nil {
		return "[]"
	}
	return m.SessionStatsJSON()
}

// MemStats mengembalikan statistik memori runtime Go sebagai JSON
// (dalam byte): {"sys":..,"heapAlloc":..,"heapIdle":..,"heapInuse":..}
func MemStats() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	b, err := json.Marshal(map[string]uint64{
		"sys":       m.Sys,
		"heapAlloc": m.HeapAlloc,
		"heapIdle":  m.HeapIdle,
		"heapInuse": m.HeapInuse,
	})
	if err != nil {
		return "{}"
	}
	return string(b)
}

// GoroutineCount mengembalikan jumlah goroutine aktif.
func GoroutineCount() int {
	return runtime.NumGoroutine()
}

// WriteGoroutineProfile menulis dump stack semua goroutine ke path
// (format pprof debug=2, terbaca sebagai teks). Mengembalikan "" jika
// sukses, pesan error jika gagal.
func WriteGoroutineProfile(path string) string {
	f, err := os.Create(path)
	if err != nil {
		return err.Error()
	}
	defer f.Close()
	p := pprof.Lookup("goroutine")
	if p == nil {
		return "profil goroutine tidak tersedia"
	}
	if err := p.WriteTo(f, 2); err != nil {
		return err.Error()
	}
	return ""
}

// WriteHeapProfile menulis heap profile (pprof) ke path. Mengembalikan ""
// jika sukses, pesan error jika gagal.
func WriteHeapProfile(path string) string {
	f, err := os.Create(path)
	if err != nil {
		return err.Error()
	}
	defer f.Close()
	if err := pprof.WriteHeapProfile(f); err != nil {
		return err.Error()
	}
	return ""
}

// FreeOSMemory memaksa GC penuh lalu mengembalikan memori idle ke OS
// (runtime/debug.FreeOSMemory: GC + scavenge seketika, bukan menunggu
// scavenger latar). Dipanggil GoEngineService secara periodik HANYA saat
// engine idle (TX/RX 0 selama beberapa interval berturut-turut) — jangan
// dipanggil saat trafik aktif.
func FreeOSMemory() {
	debug.FreeOSMemory()
}
