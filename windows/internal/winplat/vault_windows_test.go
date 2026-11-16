package winplat

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The codes file: encrypted to this account, in a folder for this account, SYSTEM and administrators only.
func TestVaultKeepsCodesEncrypted(t *testing.T) {
	useTempAppData(t)
	dir, err := vaultDir()
	if err != nil {
		t.Fatal(err)
	}
	v := &fileVault{dir: dir}
	if data, err := v.Load(); err != nil || data != nil {
		t.Fatalf("nothing saved yet: %q %v", data, err)
	}
	secret := []byte("the key behind the codes and sk-a-copy")
	if err := v.Save(secret); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, vaultFile))
	if err != nil || bytes.Contains(onDisk, []byte("sk-a-copy")) || len(onDisk) <= len(secret) {
		t.Fatalf("the file isn't encrypted: %v, %d bytes", err, len(onDisk))
	}
	if got, err := v.Load(); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("%q %v", got, err)
	}
	sid, err := userSID()
	if err != nil {
		t.Fatal(err)
	}
	acl := sddl(t, dir)
	if !strings.Contains(acl, "D:P") || strings.Count(acl, "(A;") != 3 || !strings.Contains(acl, ";;;SY)") || !strings.Contains(acl, ";;;BA)") {
		t.Errorf("folder DACL: %s (this account: %s)", acl, sid)
	}
	for _, world := range []string{";;;WD)", ";;;BU)", ";;;AU)", ";;;IU)"} {
		if strings.Contains(acl, world) || strings.Contains(sddl(t, filepath.Join(dir, vaultFile)), world) {
			t.Errorf("open to %s: %s", world, acl)
		}
	}
	// Replaced whole; a damaged file is an error, not an empty vault; nothing to keep removes the file.
	if err := v.Save([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Load(); string(got) != "second" {
		t.Fatalf("%q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, vaultFile), []byte("not a DPAPI blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load(); err == nil {
		t.Error("a damaged codes file loaded")
	}
	if err := v.Save(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, vaultFile)); !os.IsNotExist(err) {
		t.Errorf("the file is still there: %v", err)
	}
	// Outside Windows' service profiles the service keeps no codes.
	if serviceVault() != nil {
		t.Error("a vault outside ServiceProfiles")
	}
}
