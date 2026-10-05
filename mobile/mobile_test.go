package mobile

import "testing"

func TestStartInvalidDir(t *testing.T) {
	errStr := Start("/tidak/ada", "127.0.0.1:1080", "127.0.0.1:2080")
	if errStr == "" {
		t.Fatal("harusnya error untuk conf dir tidak ada")
	}
	if IsRunning() {
		t.Fatal("harusnya tidak running setelah Start gagal")
	}
}

func TestStopIdle(t *testing.T) {
	Stop() // tidak boleh panic
	if IsRunning() {
		t.Fatal("harusnya tidak running")
	}
	if SessionCount() != 0 {
		t.Fatal("harusnya 0 sesi")
	}
}

func TestDoubleStart(t *testing.T) {
	// Start pertama gagal (dir tidak ada), start kedua juga harus aman
	_ = Start("/tidak/ada", "127.0.0.1:1080", "127.0.0.1:2080")
	errStr := Start("/tidak/ada", "127.0.0.1:1080", "127.0.0.1:2080")
	if errStr == "" {
		t.Fatal("harusnya tetap error")
	}
	Stop()
}
