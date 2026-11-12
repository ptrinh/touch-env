package winplat

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var procWTSQuerySessionInfo = wtsapi32.NewProc("WTSQuerySessionInformationW")

const wtsSessionInfoEx = 25 // WTS_INFO_CLASS WTSSessionInfoEx

// sessionInfoEx reads the session's WTSINFOEXW (wtsinfo.go).
func sessionInfoEx(session uint32) (id, flags uint32, ok bool) {
	if procWTSQuerySessionInfo.Find() != nil {
		return 0, 0, false
	}
	var buf *byte
	var n uint32
	r, _, _ := procWTSQuerySessionInfo.Call(0 /* WTS_CURRENT_SERVER_HANDLE */, uintptr(session), wtsSessionInfoEx,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return 0, 0, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return parseSessionInfoEx(unsafe.Slice(buf, n))
}

// sessionLocked: whether session is showing the lock screen. known is false when Windows doesn't say (then touchenv
// asks as before: a prompt behind the lock screen waits until you unlock, it isn't shown to anyone else).
func sessionLocked(session uint32) (locked, known bool) {
	id, flags, ok := sessionInfoEx(session)
	if !ok || id != session {
		return false, false
	}
	return lockedFromFlags(flags)
}
