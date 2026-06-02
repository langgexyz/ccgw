package contract

import (
	"testing"
	"time"
)

func TestLeaseSecretRoundTrip(t *testing.T) {
	cases := []LeaseSecret{
		{Bearer: "sk-abc123", ProxyURL: ""},
		{Bearer: "sk-abc123", ProxyURL: "http://user:pass@1.2.3.4:8080"},
		{Bearer: "tok", ProxyURL: "socks5://10.0.0.1:1080"},
		{Bearer: "", ProxyURL: "http://1.2.3.4:8080"},
		{Bearer: "bearer|with|pipes\nand\x00nul", ProxyURL: "http://u:p|x@h:1?q=#frag"},
	}
	for _, in := range cases {
		got, err := decodeLeaseSecret(in.encode())
		if err != nil {
			t.Fatalf("decode(%q) err: %v", in, err)
		}
		if got.Bearer != in.Bearer || got.ProxyURL != in.ProxyURL {
			t.Fatalf("round-trip mismatch: in=%+v got=%+v", in, got)
		}
	}
}

func TestSealOpenLeaseSecret(t *testing.T) {
	secret := []byte("shared-seal-secret-32-bytes-long!!")
	const id = "ccd-1"
	in := LeaseSecret{Bearer: "sk-xyz", ProxyURL: "http://u:p@9.9.9.9:3128"}
	sealed, err := SealLeaseSecret(in, id, time.Minute, secret, time.Now)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenLeaseSecret(sealed, id, secret, time.Now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != in {
		t.Fatalf("seal/open mismatch: got=%+v want=%+v", got, in)
	}
	// Wrong ccdirect must fail to open (AAD binding).
	if _, err := OpenLeaseSecret(sealed, "ccd-2", secret, time.Now); err == nil {
		t.Fatal("expected open failure for wrong ccdirectID")
	}
}
