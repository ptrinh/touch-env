package core

// The store: %LOCALAPPDATA%\touchenv\store.json, readable by the user only.
//
// A P-256 "store key" seals each secret (SealSecret), so saving one needs only the public half and no prompt. Its
// private half is kept only RSA-encrypted to touchenv's Windows Hello key: reading anything means one Hello prompt to
// decrypt it, for however many secrets the command needs. The store key's public half is signed by the Hello key when
// the store is made, and touchenv checks that signature against the live Hello key before sealing anything: a program
// that swaps in a store key of its own (to read what you save next) needs a signature, so a Hello prompt of its own.

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const storeFormat = "touchenv-windows-store-1"

type pendingImport struct {
	Created time.Time `json:"created"`
	Public  []byte    `json:"public"`  // receiving key, uncompressed
	Wrapped []byte    `json:"wrapped"` // its private scalar, RSA-encrypted to the Hello key
}

type storeFile struct {
	Format      string            `json:"format"`
	StoreKey    []byte            `json:"store_key"`     // P-256 public, uncompressed
	Signature   []byte            `json:"store_key_sig"` // Hello key's signature over storeKeyDigest(StoreKey)
	Wrapped     []byte            `json:"wrapped_store_key"`
	Secrets     map[string][]byte `json:"secrets"`
	SSHKeys     map[string]string `json:"ssh_keys,omitempty"` // secrets from touchenv ssh add: their public key line
	Import      *pendingImport    `json:"pending_import,omitempty"`
	path        string
	helloKey    *rsa.PublicKey
	storePublic *ecdh.PublicKey
}

func storeKeyDigest(pub []byte) []byte {
	sum := sha256.Sum256(concat([]byte("touchenv store key 1\x00"), pub))
	return sum[:]
}

type fail struct {
	msg  string
	code int
}

func (f fail) Error() string { return f.msg }

func die(code int, format string, a ...any) error { return fail{fmt.Sprintf(format, a...), code} }

func storePath(p Platform) (string, error) {
	dir, err := p.DataDir()
	if err != nil {
		return "", die(1, "touchenv: %v", err)
	}
	return filepath.Join(dir, "store.json"), nil
}

// loadStore reads the store; nil (no error) when there is none yet.
func loadStore(p Platform) (*storeFile, error) {
	path, err := storePath(p)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, die(1, "touchenv: can't read %s: %v", path, err)
	}
	var s storeFile
	if err := json.Unmarshal(data, &s); err != nil || s.Format != storeFormat {
		return nil, die(1, "touchenv: %s is damaged or from a newer touchenv", path)
	}
	if s.Secrets == nil {
		s.Secrets = map[string][]byte{}
	}
	s.path = path
	return &s, nil
}

func (s *storeFile) save(p Platform) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	if err := p.WriteFilePrivate(s.path, data); err != nil {
		return die(1, "touchenv: can't write %s: %v", s.path, err)
	}
	return nil
}

func (s *storeFile) names() []string {
	out := make([]string, 0, len(s.Secrets))
	for name := range s.Secrets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// verify checks the store key against the live Windows Hello key: same key that signed it, signature good. No prompt.
func (s *storeFile) verify(h Hello) error {
	if s.storePublic != nil {
		return nil
	}
	key, err := h.PublicKey(false)
	if errors.Is(err, ErrNoKey) {
		return die(1, "touchenv: the Windows Hello key touchenv made is gone (Hello was reset, or the PIN was removed).\n"+
			"  The secrets in %s can't be read any more. Move it aside and store them again.", s.path)
	}
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, storeKeyDigest(s.StoreKey), s.Signature) != nil {
		return die(1, "touchenv: %s was changed outside touchenv: its key isn't signed by your Windows Hello key.\n"+
			"  Nothing was read or stored. Move the file aside and store your secrets again.", s.path)
	}
	pub, err := p256().NewPublicKey(s.StoreKey)
	if err != nil {
		return die(1, "touchenv: %s is damaged", s.path)
	}
	s.helloKey, s.storePublic = key, pub
	return nil
}

// unlock asks for Windows Hello (showing message) and returns the store's private key.
func (s *storeFile) unlock(h Hello, message string) (*ecdh.PrivateKey, error) {
	if err := s.verify(h); err != nil {
		return nil, err
	}
	if err := h.Ready(); err != nil {
		return nil, die(1, "touchenv: %v", err)
	}
	raw, err := h.Decrypt(message, s.Wrapped)
	if errors.Is(err, ErrCancelled) {
		return nil, die(1, "touchenv: not approved")
	}
	if err != nil {
		return nil, die(1, "touchenv: Windows Hello: %v", err)
	}
	defer wipe(raw)
	key, err := p256().NewPrivateKey(raw)
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), s.StoreKey) {
		return nil, die(1, "touchenv: %s is damaged: its key doesn't match", s.path)
	}
	return key, nil
}

// openOrCreateStore returns the store, making it (and the Windows Hello key) the first time. Making it asks for
// Hello once, to sign the new store key.
func openOrCreateStore(p Platform, h Hello) (*storeFile, error) {
	s, err := loadStore(p)
	if err != nil || s != nil {
		return s, err
	}
	if err := h.Ready(); err != nil {
		return nil, die(1, "touchenv: %v", err)
	}
	helloKey, err := h.PublicKey(true)
	if err != nil {
		return nil, die(1, "touchenv: can't make a Windows Hello key: %v", err)
	}
	storeKey, err := p256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, die(1, "touchenv: %v", err)
	}
	priv := storeKey.Bytes()
	defer wipe(priv)
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, helloKey, priv)
	if err != nil {
		return nil, die(1, "touchenv: %v", err)
	}
	pub := storeKey.PublicKey().Bytes()
	sig, err := h.Sign("touchenv: set up the place your secrets are kept on this PC (once)", storeKeyDigest(pub))
	if errors.Is(err, ErrCancelled) {
		return nil, die(1, "touchenv: not approved")
	}
	if err != nil {
		return nil, die(1, "touchenv: Windows Hello: %v", err)
	}
	if rsa.VerifyPKCS1v15(helloKey, crypto.SHA256, storeKeyDigest(pub), sig) != nil {
		return nil, die(1, "touchenv: Windows Hello returned a bad signature")
	}
	path, err := storePath(p)
	if err != nil {
		return nil, err
	}
	s = &storeFile{Format: storeFormat, StoreKey: pub, Signature: sig, Wrapped: wrapped,
		Secrets: map[string][]byte{}, path: path}
	if err := s.save(p); err != nil {
		return nil, err
	}
	return s, nil
}
