package core

// Formats shared with the macOS touchenv (touchenv.swift, "Moving to another Mac"), so a file exported on one
// system imports on the other, and the secret store's own sealing, which reuses the same construction.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Export file: "TENV" 1 | receiving key, compressed (33) | ephemeral key, x9.63 (65) | AES-GCM nonce|ciphertext|tag
// over a JSON payload, the key from ECDH + HKDF-SHA256 (salt: the header, info: "touchenv export 1"), the header
// authenticated. Byte for byte what touchenv.swift writes and reads.
var fileMagic = []byte{0x54, 0x45, 0x4E, 0x56, 0x01}

const headerLength = 5 + 33 + 65

// Each stored secret: "TENS" 1 | ephemeral key, x9.63 (65) | AES-GCM nonce|ciphertext|tag, sealed to the store key.
// The key comes from ECDH + HKDF-SHA256 (salt: the header, info: "touchenv secret 1 " + name); the header and the
// name are authenticated, so a sealed value can't be moved to another name.
var secretMagic = []byte{0x54, 0x45, 0x4E, 0x53, 0x01}

const secretHeaderLength = 5 + 65

func p256() ecdh.Curve { return ecdh.P256() }

// compress returns the 33-byte SEC 1 compressed form of an uncompressed P-256 point.
func compress(pub *ecdh.PublicKey) []byte {
	raw := pub.Bytes() // 0x04 | X | Y
	out := make([]byte, 33)
	out[0] = 2 | (raw[64] & 1)
	copy(out[1:], raw[1:33])
	return out
}

// decompress parses a 33-byte compressed P-256 point (CryptoKit's compressedRepresentation).
func decompress(data []byte) (*ecdh.PublicKey, error) {
	if len(data) != 33 {
		return nil, errors.New("bad key length")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), data)
	if x == nil {
		return nil, errors.New("not a P-256 point")
	}
	raw := make([]byte, 65)
	raw[0] = 4
	x.FillBytes(raw[1:33])
	y.FillBytes(raw[33:])
	return p256().NewPublicKey(raw)
}

// RecipientText is the receiving key's public half as text: "tenv1:" and the compressed point in base64url.
func RecipientText(pub *ecdh.PublicKey) string {
	return "tenv1:" + base64.RawURLEncoding.EncodeToString(compress(pub))
}

// ParseRecipient reads a tenv1:… line, as touchenv.swift's parseRecipient does (padding optional).
func ParseRecipient(text string) (*ecdh.PublicKey, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "tenv1:") {
		return nil, errors.New("no tenv1: prefix")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(text[6:], "="))
	if err != nil {
		return nil, err
	}
	return decompress(data)
}

// CheckCode: twelve characters both machines show, from SHA-256 of the compressed key in Crockford-style base32.
func CheckCode(pub *ecdh.PublicKey) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	sum := sha256.Sum256(compress(pub))
	var out []byte
	acc, bits := 0, 0
	for _, b := range sum {
		if len(out) >= 12 {
			break
		}
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 && len(out) < 12 {
			bits -= 5
			out = append(out, alphabet[(acc>>bits)&31])
		}
		acc &= 1<<bits - 1
	}
	return string(out[0:4]) + "-" + string(out[4:8]) + "-" + string(out[8:12])
}

func hkdfKey(shared, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, salt, info, 32)
}

func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil // nonce | ciphertext | tag, as CryptoKit's combined
}

func gcmOpen(key, combined, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(combined) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("too short")
	}
	return gcm.Open(nil, combined[:gcm.NonceSize()], combined[gcm.NonceSize():], aad)
}

// SealExport encrypts an export payload to the receiving key: the whole .tenv file.
func SealExport(recipient *ecdh.PublicKey, payload []byte) ([]byte, error) {
	ephemeral, err := p256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	header := concat(fileMagic, compress(recipient), ephemeral.PublicKey().Bytes())
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	key, err := hkdfKey(shared, header, "touchenv export 1")
	if err != nil {
		return nil, err
	}
	box, err := gcmSeal(key, payload, header)
	if err != nil {
		return nil, err
	}
	return concat(header, box), nil
}

// ExportRecipient returns the receiving key a .tenv file was made for, or an error if it isn't one.
func ExportRecipient(file []byte) (*ecdh.PublicKey, error) {
	if len(file) <= headerLength || !bytes.Equal(file[:len(fileMagic)], fileMagic) {
		return nil, errors.New("not a touchenv export")
	}
	return decompress(file[len(fileMagic) : len(fileMagic)+33])
}

// OpenExport decrypts a .tenv file with the receiving private key.
func OpenExport(key *ecdh.PrivateKey, file []byte) ([]byte, error) {
	if len(file) <= headerLength || !bytes.Equal(file[:len(fileMagic)], fileMagic) {
		return nil, errors.New("not a touchenv export")
	}
	header := file[:headerLength]
	if !bytes.Equal(file[len(fileMagic):len(fileMagic)+33], compress(key.PublicKey())) {
		return nil, errors.New("made for another key")
	}
	ephemeral, err := p256().NewPublicKey(file[len(fileMagic)+33 : headerLength])
	if err != nil {
		return nil, err
	}
	shared, err := key.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	k, err := hkdfKey(shared, header, "touchenv export 1")
	if err != nil {
		return nil, err
	}
	return gcmOpen(k, file[headerLength:], header)
}

// SealSecret encrypts one value to the store's public key. Needs no private key, so no Windows Hello prompt.
func SealSecret(store *ecdh.PublicKey, name string, value []byte) ([]byte, error) {
	ephemeral, err := p256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	header := concat(secretMagic, ephemeral.PublicKey().Bytes())
	shared, err := ephemeral.ECDH(store)
	if err != nil {
		return nil, err
	}
	key, err := hkdfKey(shared, header, "touchenv secret 1 "+name)
	if err != nil {
		return nil, err
	}
	box, err := gcmSeal(key, value, concat(header, []byte(name)))
	if err != nil {
		return nil, err
	}
	return concat(header, box), nil
}

// OpenSecret decrypts one stored value with the store's private key.
func OpenSecret(store *ecdh.PrivateKey, name string, sealed []byte) ([]byte, error) {
	if len(sealed) <= secretHeaderLength || !bytes.Equal(sealed[:len(secretMagic)], secretMagic) {
		return nil, errors.New("not a sealed secret")
	}
	header := sealed[:secretHeaderLength]
	ephemeral, err := p256().NewPublicKey(sealed[len(secretMagic):secretHeaderLength])
	if err != nil {
		return nil, err
	}
	shared, err := store.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	key, err := hkdfKey(shared, header, "touchenv secret 1 "+name)
	if err != nil {
		return nil, err
	}
	return gcmOpen(key, sealed[secretHeaderLength:], concat(header, []byte(name)))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
