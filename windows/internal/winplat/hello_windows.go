package winplat

// touchenv's Windows Hello key: an RSA-2048 key in the Microsoft Passport key storage provider (the provider that
// holds Windows Hello keys), made by touchenv for the signed-in user, usable for decrypt and sign, never imported,
// with "NgcCacheType" = 1 (AUTH_MANDATORY): Windows asks for Hello on every use, however recently the user signed in.
// Decrypt and Sign show touchenv's message in the Hello dialog through NCRYPT_USE_CONTEXT_PROPERTY.
//
// The provider name, the "NgcCacheType" property and NgcGetDefaultDecryptionKeyName are not in Microsoft's public
// documentation; KeePassWinHello has used them the same way since 2019. See README, Windows.

import (
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"golang.org/x/sys/windows"
)

var (
	ncrypt                    = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider   = ncrypt.NewProc("NCryptOpenStorageProvider")
	procOpenKey               = ncrypt.NewProc("NCryptOpenKey")
	procCreatePersistedKey    = ncrypt.NewProc("NCryptCreatePersistedKey")
	procSetProperty           = ncrypt.NewProc("NCryptSetProperty")
	procGetProperty           = ncrypt.NewProc("NCryptGetProperty")
	procFinalizeKey           = ncrypt.NewProc("NCryptFinalizeKey")
	procDecrypt               = ncrypt.NewProc("NCryptDecrypt")
	procSignHash              = ncrypt.NewProc("NCryptSignHash")
	procExportKey             = ncrypt.NewProc("NCryptExportKey")
	procFreeObject            = ncrypt.NewProc("NCryptFreeObject")
	cryptngc                  = windows.NewLazySystemDLL("cryptngc.dll")
	procNgcDefaultDecryptName = cryptngc.NewProc("NgcGetDefaultDecryptionKeyName")
	user32                    = windows.NewLazySystemDLL("user32.dll")
	procGetForegroundWindow   = user32.NewProc("GetForegroundWindow")
	procGetSystemMetrics      = user32.NewProc("GetSystemMetrics")
	procGetProcessWinStation  = user32.NewProc("GetProcessWindowStation")
	procGetUserObjectInfo     = user32.NewProc("GetUserObjectInformationW")
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
)

const (
	passportProvider = "Microsoft Passport Key Storage Provider" // MS_NGC_KEY_STORAGE_PROVIDER in ncrypt.h

	ncryptSilentFlag   = 0x00000040
	ncryptPadPKCS1     = 0x00000002 // NCRYPT_PAD_PKCS1_FLAG, BCRYPT_PAD_PKCS1
	allowDecrypt       = 0x00000001
	allowSigning       = 0x00000002
	allowKeyImport     = 0x00000008
	ngcAuthMandatory   = 0x00000001 // NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG
	smRemoteSession    = 0x1000
	uoiFlags           = 1
	wsfVisible         = 1
	nteBadKeyset       = 0x80090016
	nteNoKey           = 0x8009000D
	nteNotFound        = 0x80090011
	nteUserCancelled   = 0x80090036
	nteSilentContext   = 0x80090022
	hresultCancelled   = 0x800704C7 // HRESULT_FROM_WIN32(ERROR_CANCELLED)
	winbioDataProtFail = 0x80098046
	tpm20Handle        = 0x8028008B
	tpm20Size          = 0x80280095
	tpm20Error159      = 0x80280159
)

// Hello implements core.Hello with the Passport key storage provider.
type Hello struct{}

func NewHello() *Hello { return &Hello{} }

type status uintptr

func (s status) Error() string {
	code := uint32(s)
	switch code {
	case nteUserCancelled, hresultCancelled:
		return "cancelled"
	}
	if msg := windows.Errno(code).Error(); msg != "" {
		return fmt.Sprintf("%s (0x%08X)", msg, code)
	}
	return fmt.Sprintf("error 0x%08X", code)
}

// call runs an ncrypt function. Arguments may be pointers converted to uintptr: uintptrescapes keeps what they
// point to alive and in place for the call, as for LazyProc.Call itself.
//
//go:uintptrescapes
func call(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return fmt.Errorf("%s isn't available on this Windows: %v", p.Name, err)
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return status(r)
	}
	return nil
}

func isStatus(err error, codes ...uint32) bool {
	var s status
	if !errors.As(err, &s) {
		return false
	}
	for _, c := range codes {
		if uint32(s) == c {
			return true
		}
	}
	return false
}

func utf16z(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil { // a NUL inside: never for touchenv's own strings
		p, _ = windows.UTF16PtrFromString("touchenv")
	}
	return p
}

// keyName follows the "<SID>//<domain>/<subdomain>/<name>" form the Passport provider accepts for app keys.
func keyName() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String() + "//touchenv//store", nil
}

func currentSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// Ready fails closed wherever a Hello prompt can't be shown to the person at the PC.
func (h *Hello) Ready() error {
	if r, _, _ := procGetSystemMetrics.Call(smRemoteSession); r != 0 {
		return errors.New("Windows Hello can't ask in a Remote Desktop session: run touchenv at the PC itself")
	}
	var session uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) == nil && session == 0 {
		return errors.New("no desktop to show Windows Hello on (a service, or an SSH session): run touchenv in a window on the PC")
	}
	if !windowStationVisible() {
		return errors.New("no desktop to show Windows Hello on (a service, or an SSH session): run touchenv in a window on the PC")
	}
	sid, err := currentSID()
	if err != nil {
		return err
	}
	if procNgcDefaultDecryptName.Find() == nil {
		var name *uint16
		r, _, _ := procNgcDefaultDecryptName.Call(uintptr(unsafe.Pointer(utf16z(sid))), 0, 0, uintptr(unsafe.Pointer(&name)))
		if name != nil {
			defer windows.CoTaskMemFree(unsafe.Pointer(name))
		}
		if r != 0 || name == nil || windows.UTF16PtrToString(name) == "" {
			return errors.New("Windows Hello isn't set up for you: add a PIN (and a fingerprint or face if you like) in Settings > Accounts > Sign-in options")
		}
	}
	return nil
}

func windowStationVisible() bool {
	station, _, _ := procGetProcessWinStation.Call()
	if station == 0 {
		return false
	}
	var flags struct {
		Inherit  int32
		Reserved int32
		Flags    uint32
	}
	var needed uint32
	r, _, _ := procGetUserObjectInfo.Call(station, uoiFlags, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags),
		uintptr(unsafe.Pointer(&needed)))
	return r != 0 && flags.Flags&wsfVisible != 0
}

type handle uintptr

func (k handle) free() {
	if k != 0 {
		procFreeObject.Call(uintptr(k))
	}
}

func openProvider() (handle, error) {
	var prov handle
	if err := call(procOpenStorageProvider, uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(utf16z(passportProvider))), 0); err != nil {
		return 0, fmt.Errorf("Windows Hello's key store won't open: %w", err)
	}
	return prov, nil
}

// openKey opens touchenv's key; silent means without any UI (for reading the public key).
func openKey(silent bool) (handle, error) {
	prov, err := openProvider()
	if err != nil {
		return 0, err
	}
	defer prov.free()
	name, err := keyName()
	if err != nil {
		return 0, err
	}
	var flags uintptr
	if silent {
		flags = ncryptSilentFlag
	}
	var key handle
	err = call(procOpenKey, uintptr(prov), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16z(name))), 0, flags)
	if isStatus(err, nteBadKeyset, nteNoKey, nteNotFound) {
		return 0, core.ErrNoKey
	}
	if err != nil {
		return 0, fmt.Errorf("can't open the Windows Hello key: %w", err)
	}
	return key, nil
}

func setBytes(obj handle, property string, data []byte) error {
	var p uintptr
	if len(data) > 0 {
		p = uintptr(unsafe.Pointer(&data[0]))
	}
	return call(procSetProperty, uintptr(obj), uintptr(unsafe.Pointer(utf16z(property))), p, uintptr(len(data)), 0)
}

func setDword(obj handle, property string, v uint32) error {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return setBytes(obj, property, b)
}

func setString(obj handle, property, value string) error {
	u, err := windows.UTF16FromString(value)
	if err != nil {
		return err
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2)
	return setBytes(obj, property, b)
}

func getDword(obj handle, property string) (uint32, error) {
	var v, got uint32
	err := call(procGetProperty, uintptr(obj), uintptr(unsafe.Pointer(utf16z(property))), uintptr(unsafe.Pointer(&v)), 4,
		uintptr(unsafe.Pointer(&got)), 0)
	return v, err
}

// cacheType reads NgcCacheType, under its current name or the older one.
func cacheType(key handle) (uint32, error) {
	v, err := getDword(key, "NgcCacheType")
	if err != nil {
		v, err = getDword(key, "NgcCacheTypeProperty")
	}
	return v, err
}

// checkKey refuses a key touchenv would not have made: imported (someone knows the private key), Hello not asked
// on every use, or not RSA-2048 for decrypt and sign.
func checkKey(key handle) error {
	usage, err := getDword(key, "Key Usage")
	if err != nil {
		return fmt.Errorf("can't read the Windows Hello key's usage: %w", err)
	}
	if usage&allowKeyImport != 0 || usage&(allowDecrypt|allowSigning) != allowDecrypt|allowSigning {
		return errors.New("the Windows Hello key named for touchenv wasn't made by touchenv (imported, or wrong usage): not using it")
	}
	cache, err := cacheType(key)
	if err != nil || cache != ngcAuthMandatory {
		return errors.New("the Windows Hello key named for touchenv doesn't ask for Hello on every use: not using it")
	}
	if bits, err := getDword(key, "Length"); err != nil || bits < keyBits {
		return errors.New("the Windows Hello key named for touchenv is not RSA-2048: not using it")
	}
	return nil
}

func exportPublic(key handle) (*rsa.PublicKey, error) {
	blobType := utf16z("RSAPUBLICBLOB")
	var size uint32
	if err := call(procExportKey, uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0); err != nil {
		return nil, fmt.Errorf("can't read the Windows Hello public key: %w", err)
	}
	blob := make([]byte, size)
	if err := call(procExportKey, uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&blob[0])),
		uintptr(size), uintptr(unsafe.Pointer(&size)), 0); err != nil {
		return nil, fmt.Errorf("can't read the Windows Hello public key: %w", err)
	}
	return parseRSAPublicBlob(blob[:size])
}

// PublicKey opens touchenv's key without a prompt, checks it, and returns its public half; makes it with create.
func (h *Hello) PublicKey(create bool) (*rsa.PublicKey, error) {
	key, err := openKey(true)
	if errors.Is(err, core.ErrNoKey) && create {
		if err := makeKey(); err != nil {
			return nil, err
		}
		key, err = openKey(true)
	}
	if err != nil {
		return nil, err
	}
	defer key.free()
	if err := checkKey(key); err != nil {
		return nil, err
	}
	return exportPublic(key)
}

func makeKey() error {
	prov, err := openProvider()
	if err != nil {
		return err
	}
	defer prov.free()
	name, err := keyName()
	if err != nil {
		return err
	}
	var key handle
	if err := call(procCreatePersistedKey, uintptr(prov), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16z("RSA"))),
		uintptr(unsafe.Pointer(utf16z(name))), 0, 0); err != nil {
		return fmt.Errorf("can't make a Windows Hello key: %w", err)
	}
	defer key.free()
	if err := setDword(key, "Length", keyBits); err != nil {
		return fmt.Errorf("Windows Hello key length: %w", err)
	}
	if err := setDword(key, "Key Usage", allowDecrypt|allowSigning); err != nil {
		return fmt.Errorf("Windows Hello key usage: %w", err)
	}
	if err := setDword(key, "NgcCacheType", ngcAuthMandatory); err != nil {
		if err := setDword(key, "NgcCacheTypeProperty", ngcAuthMandatory); err != nil {
			// Without it Windows would not ask on every use: refuse rather than make a weaker key.
			return fmt.Errorf("this Windows can't make a key that asks for Hello on every use: %w", err)
		}
	}
	setUI(key, "touchenv: make the key that keeps your secrets on this PC") // creation reveals nothing
	if err := call(procFinalizeKey, uintptr(key), 0); err != nil {
		if isStatus(err, nteUserCancelled, hresultCancelled) {
			return core.ErrCancelled
		}
		return fmt.Errorf("can't make a Windows Hello key: %w", err)
	}
	return nil
}

// setUI parents the Hello dialog to the window the person is looking at, and puts touchenv's message in it.
func setUI(key handle, message string) error {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		hwnd, _, _ = procGetConsoleWindow.Call()
	}
	if hwnd != 0 {
		b := make([]byte, unsafe.Sizeof(hwnd))
		if unsafe.Sizeof(hwnd) == 8 {
			binary.LittleEndian.PutUint64(b, uint64(hwnd))
		} else {
			binary.LittleEndian.PutUint32(b, uint32(hwnd))
		}
		setBytes(key, "HWND Handle", b) // only placement: a failure here changes nothing that matters
	}
	return setString(key, "Use Context", message)
}

// withPrompt opens the key for use, checks it, shows message, and runs op; Windows asks for Hello inside op.
// A few TPM and biometric errors are known to be passing (KeePassWinHello #42, #68, #77, #93): one retry.
func withPrompt(message string, op func(key handle) error) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var key handle
		key, err = openKey(false)
		if err != nil {
			return err
		}
		if err = checkKey(key); err != nil {
			key.free()
			return err
		}
		// Without touchenv's message the prompt wouldn't say who asks or why: refuse rather than ask blind.
		if err = setUI(key, message); err != nil {
			key.free()
			return fmt.Errorf("can't put touchenv's message in the Windows Hello prompt: %w", err)
		}
		setDword(key, "PinCacheIsGestureRequired", 1) // NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY
		err = op(key)
		key.free()
		if !isStatus(err, winbioDataProtFail, tpm20Handle, tpm20Size, tpm20Error159) {
			break
		}
	}
	switch {
	case err == nil:
		return nil
	case isStatus(err, nteUserCancelled, hresultCancelled):
		return core.ErrCancelled
	case isStatus(err, nteSilentContext):
		return errors.New("Windows Hello couldn't show its prompt here")
	}
	return err
}

func (h *Hello) Decrypt(message string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("nothing to decrypt")
	}
	var out []byte
	err := withPrompt(message, func(key handle) error {
		buf := make([]byte, len(ciphertext))
		var n uint32
		if err := call(procDecrypt, uintptr(key), uintptr(unsafe.Pointer(&ciphertext[0])), uintptr(len(ciphertext)), 0,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), ncryptPadPKCS1); err != nil {
			return err
		}
		out = buf[:n]
		return nil
	})
	return out, err
}

func (h *Hello) Sign(message string, digest []byte) ([]byte, error) {
	var out []byte
	err := withPrompt(message, func(key handle) error {
		padding := struct{ alg *uint16 }{utf16z("SHA256")} // BCRYPT_PKCS1_PADDING_INFO
		buf := make([]byte, keyBits/8*2)
		var n uint32
		if err := call(procSignHash, uintptr(key), uintptr(unsafe.Pointer(&padding)), uintptr(unsafe.Pointer(&digest[0])),
			uintptr(len(digest)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), ncryptPadPKCS1); err != nil {
			return err
		}
		out = buf[:n]
		return nil
	})
	return out, err
}
