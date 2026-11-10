package core

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// testdata/swift-export.json was made by touchenv.swift's own export code (CryptoKit), to a throwaway receiving key.
type swiftVector struct {
	CheckCode     string `json:"check_code"`
	File          string `json:"file_base64"`
	Private       string `json:"receiving_private_hex"`
	RecipientText string `json:"recipient_text"`
}

func loadVector(t *testing.T) swiftVector {
	data, err := os.ReadFile("testdata/swift-export.json")
	if err != nil {
		t.Fatal(err)
	}
	var v swiftVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestOpensMacExport(t *testing.T) {
	v := loadVector(t)
	raw, _ := hex.DecodeString(v.Private)
	key, err := p256().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := RecipientText(key.PublicKey()); got != v.RecipientText {
		t.Fatalf("recipient text %q, Swift %q", got, v.RecipientText)
	}
	parsed, err := ParseRecipient(v.RecipientText)
	if err != nil || !bytes.Equal(parsed.Bytes(), key.PublicKey().Bytes()) {
		t.Fatalf("parse: %v", err)
	}
	if got := CheckCode(parsed); got != v.CheckCode {
		t.Fatalf("check code %q, Swift %q", got, v.CheckCode)
	}
	file, _ := base64.StdEncoding.DecodeString(v.File)
	plain, err := OpenExport(key, file)
	if err != nil {
		t.Fatal(err)
	}
	var p exportPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		t.Fatal(err)
	}
	if p.From != "Test Mac" || len(p.Secrets) != 2 || p.Secrets[0].Name != "API_KEY" ||
		string(p.Secrets[0].Data) != "sk-test-alpha" || !p.Secrets[0].Sync ||
		!bytes.Equal(p.Secrets[1].Data, []byte{0, 1, 2, 255, 10}) {
		t.Fatalf("payload %+v", p)
	}
	file[len(file)-1] ^= 1
	if _, err := OpenExport(key, file); err == nil {
		t.Fatal("opened a damaged file")
	}
}

// TestWriteForMac writes a Go-made export for the Swift harness to open (see conformance/README):
// TOUCHENV_INTEROP_OUT=dir go test -run TestWriteForMac ./internal/core
func TestWriteForMac(t *testing.T) {
	out := os.Getenv("TOUCHENV_INTEROP_OUT")
	if out == "" {
		t.Skip("TOUCHENV_INTEROP_OUT not set")
	}
	key, _ := p256().GenerateKey(rand.Reader)
	plain, _ := json.Marshal(exportPayload{From: "Test PC", Secrets: []exportEntry{{Name: "API_KEY", Data: []byte("sk-from-windows")}}})
	file, err := SealExport(key.PublicKey(), plain)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(out+"/go.tenv", file, 0o600)
	os.WriteFile(out+"/go.key", []byte(hex.EncodeToString(key.Bytes())), 0o600)
	os.WriteFile(out+"/go.code", []byte(CheckCode(key.PublicKey())+"\n"+RecipientText(key.PublicKey())), 0o600)
}
