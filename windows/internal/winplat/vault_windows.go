package winplat

// Where the service keeps codes from an authenticator app and the secrets allowed from afar (core/totp.go): one
// file in the service account's own profile (%LOCALAPPDATA%\touchenv\codes.bin, under
// C:\Windows\ServiceProfiles\touchenv), in a folder only that account, SYSTEM and administrators can open, and
// encrypted with DPAPI to that account. Programs running as you can't read it; an administrator can.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"golang.org/x/sys/windows"
)

const vaultFile = "codes.bin"

type fileVault struct{ dir string }

// vaultDir is the folder for the codes file in the profile of the account this process runs as.
func vaultDir() (string, error) {
	base, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "touchenv"), nil
}

// serviceVault is the running service's vault; nil when its account has no profile folder to keep it in, or that
// folder isn't under Windows' own (codes are then refused).
func serviceVault() core.Vault {
	dir, err := vaultDir()
	if err != nil {
		return nil
	}
	root := filepath.Join(os.Getenv("SystemRoot"), "ServiceProfiles") + string(filepath.Separator)
	if os.Getenv("SystemRoot") == "" || !strings.HasPrefix(strings.ToLower(dir), strings.ToLower(root)) {
		return nil
	}
	return &fileVault{dir: dir}
}

// installedVaultDir is where the service's vault is, as the uninstaller (an administrator) finds it.
func installedVaultDir() string {
	return filepath.Join(os.Getenv("SystemRoot"), "ServiceProfiles", serviceName, "AppData", "Local", "touchenv")
}

// mkdirVault makes dir with a protected DACL: this account, SYSTEM and administrators (who remove it at uninstall).
func mkdirVault(dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New(dir + " is not a folder")
		}
		return nil
	}
	sid, err := userSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	return windows.CreateDirectory(utf16z(dir), sa)
}

func dataBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// dpapi encrypts data to this account (or undoes that), never asking anything on screen.
func dpapi(data []byte, protect bool) ([]byte, error) {
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(dataBlob(data), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(dataBlob(data), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	got := unsafe.Slice(out.Data, out.Size)
	result := append([]byte(nil), got...)
	if !protect {
		clear(got)
	}
	return result, nil
}

func (v *fileVault) Load() ([]byte, error) {
	sealed, err := os.ReadFile(filepath.Join(v.dir, vaultFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return dpapi(sealed, false)
}

// Save replaces the file through a new one moved into place, so a crash leaves the old one; nothing to keep
// removes it.
func (v *fileVault) Save(data []byte) error {
	path := filepath.Join(v.dir, vaultFile)
	if len(data) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := mkdirVault(v.dir); err != nil {
		return err
	}
	sealed, err := dpapi(data, true)
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil { // inherits the folder's DACL
		return err
	}
	if err := windows.MoveFileEx(utf16z(tmp), utf16z(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
