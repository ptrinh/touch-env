package winplat

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"testing"
)

// blob builds a BCRYPT_RSAKEY_BLOB (RSAPUBLICBLOB) the way NCryptExportKey lays it out.
func blob(pub *rsa.PublicKey) []byte {
	e := big.NewInt(int64(pub.E)).Bytes()
	n := pub.N.Bytes()
	out := make([]byte, 24)
	binary.LittleEndian.PutUint32(out[0:], rsaPublicMagic)
	binary.LittleEndian.PutUint32(out[4:], uint32(pub.N.BitLen()))
	binary.LittleEndian.PutUint32(out[8:], uint32(len(e)))
	binary.LittleEndian.PutUint32(out[12:], uint32(len(n)))
	return append(append(out, e...), n...)
}

func TestParseRSAPublicBlob(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseRSAPublicBlob(blob(&key.PublicKey))
	if err != nil || !got.Equal(&key.PublicKey) {
		t.Fatalf("%v", err)
	}
	b := blob(&key.PublicKey)
	for name, bad := range map[string][]byte{"short": b[:20], "truncated": b[:len(b)-1], "magic": append([]byte{0}, b[1:]...)} {
		if _, err := parseRSAPublicBlob(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := parseRSAPublicBlob(blob(&small.PublicKey)); err == nil {
		t.Error("accepted a 1024-bit key")
	}
}
