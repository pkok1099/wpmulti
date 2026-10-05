package wireproxy

import (
	"strings"
	"testing"
)

func TestRewriteEndpoints(t *testing.T) {
	in := `[Interface]
PrivateKey = abc=
Address = 172.16.0.2/32

[Peer]
PublicKey = xyz=
Endpoint = engage.cloudflareclient.com:2408
AllowedIPs = 0.0.0.0/0
`
	// cache diisi manual agar tidak butuh DNS asli saat test
	cache := map[string]string{"engage.cloudflareclient.com": "162.159.192.1"}
	out := string(rewriteEndpoints([]byte(in), cache))
	if !strings.Contains(out, "Endpoint = 162.159.192.1:2408") {
		t.Fatalf("endpoint tidak di-rewrite:\n%s", out)
	}
	if strings.Contains(out, "engage.cloudflareclient.com") {
		t.Fatalf("hostname masih ada:\n%s", out)
	}

	// endpoint yang sudah IP tidak diubah
	in2 := "[Peer]\nEndpoint = 1.2.3.4:2408\n"
	out2 := string(rewriteEndpoints([]byte(in2), cache))
	if !strings.Contains(out2, "Endpoint = 1.2.3.4:2408") {
		t.Fatalf("IP literal ikut diubah:\n%s", out2)
	}
}

func TestPickIP(t *testing.T) {
	got := pickIP([]string{"2606:4700::1", "162.159.192.1"})
	if got != "162.159.192.1" {
		t.Fatalf("harusnya pilih IPv4, dapat %s", got)
	}
}

func TestFlowKey(t *testing.T) {
	// IPv4 TCP: 20-byte header, src 1.2.3.4:1234 -> dst 5.6.7.8:80
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[9] = 6    // TCP
	copy(pkt[12:16], []byte{1, 2, 3, 4})
	copy(pkt[16:20], []byte{5, 6, 7, 8})
	pkt[20] = 0x04 // src port 1234
	pkt[21] = 0xD2
	pkt[22] = 0x00 // dst port 80
	pkt[23] = 0x50
	k1 := flowKey(pkt)
	if k1 == "" {
		t.Fatal("flowKey kosong untuk paket IPv4 TCP valid")
	}
	// Paket balasan (arah berlawanan) harus beda key
	pkt2 := make([]byte, 40)
	copy(pkt2, pkt)
	copy(pkt2[12:16], []byte{5, 6, 7, 8})
	copy(pkt2[16:20], []byte{1, 2, 3, 4})
	if flowKey(pkt2) == k1 {
		t.Fatal("arah berlawanan harus beda flow")
	}
	// Port beda -> flow beda
	pkt3 := make([]byte, 40)
	copy(pkt3, pkt)
	pkt3[21] = 0xD3 // src port 1235
	if flowKey(pkt3) == k1 {
		t.Fatal("port beda harus beda flow")
	}
	// IPv6 UDP
	p6 := make([]byte, 48)
	p6[0] = 0x60 // version 6
	p6[6] = 17   // UDP
	p6[40] = 0x04
	p6[41] = 0xD2
	if flowKey(p6) == "" {
		t.Fatal("flowKey kosong untuk paket IPv6 UDP valid")
	}
	// Paket rusak -> ""
	if flowKey([]byte{0x45}) != "" {
		t.Fatal("paket truncated harus key kosong")
	}
	if flowKey(nil) != "" {
		t.Fatal("nil harus key kosong")
	}
}
