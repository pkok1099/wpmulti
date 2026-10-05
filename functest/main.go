package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	mobile "github.com/pkok1099/wpmulti/mobile"
)

type listener struct{}

func (listener) OnSessionUp(up, total int) { fmt.Printf("  progress: %d/%d\n", up, total) }
func (listener) OnReady(total int)          { fmt.Println("  ready:", total) }
func (listener) OnError(msg string)         { fmt.Println("  error:", msg) }

func main() {
	mobile.SetStatusListener(listener{})
	fmt.Println("Start...")
	if errStr := mobile.Start("/home/ubuntu/wireproxy-conf", "127.0.0.1:1190", "127.0.0.1:2190"); errStr != "" {
		fmt.Println("GAGAL:", errStr)
		return
	}
	fmt.Println("Running:", mobile.IsRunning(), "Sesi:", mobile.SessionCount())
	time.Sleep(10)
	pu, _ := url.Parse("http://127.0.0.1:2190")
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 20 * time.Second}
	r, err := c.Get("https://api6.ipify.org")
	if err != nil {
		fmt.Println("Request GAGAL:", err)
	} else {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		fmt.Println("IP egress:", string(b))
	}
	mobile.Stop()
	fmt.Println("Setelah Stop - Running:", mobile.IsRunning(), "Sesi:", mobile.SessionCount())
	fmt.Println("FUNCTEST SELESAI")
}
