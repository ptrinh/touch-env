package winplat

import (
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
)

const (
	rsaPublicMagic = 0x31415352 // BCRYPT_RSAPUBLIC_MAGIC "RSA1"
	keyBits        = 2048
)

// parseRSAPublicBlob reads a BCRYPT_RSAKEY_BLOB header and its big-endian exponent and modulus.
func parseRSAPublicBlob(blob []byte) (*rsa.PublicKey, error) {
	if len(blob) < 24 || binary.LittleEndian.Uint32(blob) != rsaPublicMagic {
		return nil, errors.New("not an RSA public key blob")
	}
	expLen := int(binary.LittleEndian.Uint32(blob[8:]))
	modLen := int(binary.LittleEndian.Uint32(blob[12:]))
	if expLen < 1 || expLen > 8 || len(blob) < 24+expLen+modLen {
		return nil, errors.New("bad RSA public key blob")
	}
	e := new(big.Int).SetBytes(blob[24 : 24+expLen])
	n := new(big.Int).SetBytes(blob[24+expLen : 24+expLen+modLen])
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 || n.BitLen() < keyBits {
		return nil, errors.New("bad RSA public key")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
