package contract

import (
	"encoding/binary"
	"errors"
	"time"
)

// LeaseSecret is the plaintext that cchub seals into a lease token. It carries
// the upstream bearer AND the account-bound egress proxy URL, so that an account
// served via a ccdirect egresses through the SAME proxy it would use on the
// central path (account IP identity stays consistent between center and edge).
// The ccdirect never presents its own host IP for a proxied account.
//
// The proxy URL rides INSIDE the sealed (AEAD) envelope, alongside the bearer,
// so a captured lease response leaks neither the upstream credential nor the
// proxy credentials (proxy URLs may embed user:pass).
type LeaseSecret struct {
	Bearer   string // upstream credential (Authorization: Bearer <bearer>)
	ProxyURL string // egress proxy (http/https/socks5...); empty = direct egress
}

// encode serializes the secret as: [uvarint len(bearer)][bearer][uvarint
// len(proxyURL)][proxyURL]. Length-prefixing (not a delimiter) keeps it correct
// for bearers/URLs containing any bytes.
func (s LeaseSecret) encode() []byte {
	out := make([]byte, 0, binary.MaxVarintLen64*2+len(s.Bearer)+len(s.ProxyURL))
	var n [binary.MaxVarintLen64]byte
	w := binary.PutUvarint(n[:], uint64(len(s.Bearer)))
	out = append(out, n[:w]...)
	out = append(out, s.Bearer...)
	w = binary.PutUvarint(n[:], uint64(len(s.ProxyURL)))
	out = append(out, n[:w]...)
	out = append(out, s.ProxyURL...)
	return out
}

// decodeLeaseSecret reverses encode.
func decodeLeaseSecret(plain []byte) (LeaseSecret, error) {
	bearer, rest, err := readLenPrefixed(plain)
	if err != nil {
		return LeaseSecret{}, err
	}
	proxyURL, _, err := readLenPrefixed(rest)
	if err != nil {
		return LeaseSecret{}, err
	}
	return LeaseSecret{Bearer: bearer, ProxyURL: proxyURL}, nil
}

func readLenPrefixed(buf []byte) (string, []byte, error) {
	n, w := binary.Uvarint(buf)
	if w <= 0 {
		return "", nil, errors.New("contract: lease secret bad length prefix")
	}
	buf = buf[w:]
	if uint64(len(buf)) < n {
		return "", nil, errors.New("contract: lease secret truncated")
	}
	return string(buf[:n]), buf[n:], nil
}

// SealLeaseSecret AEAD-seals a LeaseSecret bound to ccdirectID + a TTL-derived
// expiry, reusing the same envelope crypto as SealLeaseToken.
func SealLeaseSecret(sec LeaseSecret, ccdirectID string, ttl time.Duration, secret []byte, now func() time.Time) (string, error) {
	return SealLeaseToken(string(sec.encode()), ccdirectID, ttl, secret, now)
}

// OpenLeaseSecret opens a token sealed by SealLeaseSecret.
func OpenLeaseSecret(sealed, ccdirectID string, secret []byte, now func() time.Time) (LeaseSecret, error) {
	plain, err := OpenLeaseToken(sealed, ccdirectID, secret, now)
	if err != nil {
		return LeaseSecret{}, err
	}
	return decodeLeaseSecret([]byte(plain))
}
