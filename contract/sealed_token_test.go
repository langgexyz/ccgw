//go:build unit

package contract

import (
	"testing"
	"time"
)

func TestSealOpenLeaseToken_RoundTrip(t *testing.T) {
	secret := []byte("center-ccdirect-shared-secret")
	sealed, err := SealLeaseToken("tp-real-upstream-key", "ccdirect-1", time.Minute, secret, time.Now)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed == "tp-real-upstream-key" {
		t.Fatalf("sealed token must not be the plaintext")
	}
	got, err := OpenLeaseToken(sealed, "ccdirect-1", secret, time.Now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != "tp-real-upstream-key" {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestOpenLeaseToken_WrongEdgeRejected(t *testing.T) {
	secret := []byte("s")
	sealed, _ := SealLeaseToken("tok", "ccdirect-1", time.Minute, secret, time.Now)
	if _, err := OpenLeaseToken(sealed, "ccdirect-2", secret, time.Now); err == nil {
		t.Fatalf("token bound to ccdirect-1 must not open for ccdirect-2")
	}
}

func TestOpenLeaseToken_WrongKeyRejected(t *testing.T) {
	sealed, _ := SealLeaseToken("tok", "ccdirect-1", time.Minute, []byte("k1"), time.Now)
	if _, err := OpenLeaseToken(sealed, "ccdirect-1", []byte("k2"), time.Now); err == nil {
		t.Fatalf("token must not open with a different key")
	}
}

func TestOpenLeaseToken_ExpiredRejected(t *testing.T) {
	secret := []byte("s")
	base := time.Unix(1_700_000_000, 0)
	sealed, _ := SealLeaseToken("tok", "ccdirect-1", time.Minute, secret, func() time.Time { return base })
	later := func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := OpenLeaseToken(sealed, "ccdirect-1", secret, later); err == nil {
		t.Fatalf("expired token must be rejected")
	}
}

func TestOpenLeaseToken_TamperRejected(t *testing.T) {
	secret := []byte("s")
	sealed, _ := SealLeaseToken("tok", "ccdirect-1", time.Minute, secret, time.Now)
	tampered := sealed[:len(sealed)-1] + "X"
	if _, err := OpenLeaseToken(tampered, "ccdirect-1", secret, time.Now); err == nil {
		t.Fatalf("tampered token must be rejected")
	}
}
