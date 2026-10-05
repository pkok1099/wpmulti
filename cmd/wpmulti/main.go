// Command wpmulti: N WireGuard sessions in ONE process (multi-session
// wireproxy fork). Each *.conf in --conf-dir becomes one session = one
// egress IP. Single SOCKS5 + HTTP listeners distribute connections
// round-robin across sessions. RAM-efficient alternative to N processes.
//
// Usage:
// wpmulti --conf-dir ./wp-conf --socks 127.0.0.1:1080 --http 127.0.0.1:2080
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkok1099/wpmulti"
	"golang.zx2c4.com/wireguard/device"
)

func main() {
	confDir := flag.String("conf-dir", "", "direktori berisi *.conf WireGuard (1 file = 1 sesi/IP)")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "alamat listen SOCKS5")
	httpAddr := flag.String("http", "127.0.0.1:2080", "alamat listen HTTP proxy")
	debugAddr := flag.String("debug", "", "alamat listen debug (pprof + /debug/sessions), kosong = mati")
	silent := flag.Bool("s", false, "silent mode (log wireguard mati)")
	flag.Parse()

	if *confDir == "" {
		log.Fatal("--conf-dir wajib diisi")
	}

	logLevel := device.LogLevelVerbose
	if *silent {
		logLevel = device.LogLevelSilent
	}

	m, err := wireproxy.StartMultiTun(*confDir, logLevel)
	if err != nil {
		log.Fatal(err)
	}
	defer m.Close()

	go m.SpawnSocks5(*socksAddr)
	go m.SpawnHTTP(*httpAddr)

	if *debugAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/debug/sessions", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, m.SessionStatsJSON())
		}))
		// pprof: /debug/pprof/
		mux.Handle("/debug/pprof/", http.DefaultServeMux)
		go func() {
			log.Printf("debug di %s", *debugAddr)
			if err := http.ListenAndServe(*debugAddr, mux); err != nil {
				log.Printf("debug server: %v", err)
			}
		}()
	}

	log.Printf("wpmulti siap: %d sesi", m.Count())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("berhenti.")
}
