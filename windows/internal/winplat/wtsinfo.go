package winplat

import "encoding/binary"

// Reading WTSINFOEXW (WTSQuerySessionInformationW with WTSSessionInfoEx), kept free of Windows calls so it is tested
// on any OS. The struct is a DWORD Level (always 1) and then the WTSINFOEX_LEVEL1_W union, which holds LARGE_INTEGERs
// and so starts at offset 8 on x64 and arm64: SessionId at 8, SessionState at 12, SessionFlags at 16.
const (
	wtsSessionStateLock    = 0          // WTS_SESSIONSTATE_LOCK
	wtsSessionStateUnlock  = 1          // WTS_SESSIONSTATE_UNLOCK
	wtsSessionStateUnknown = 0xFFFFFFFF // WTS_SESSIONSTATE_UNKNOWN
	wtsInfoExMinSize       = 20
)

// parseSessionInfoEx returns the session id and SessionFlags from a WTSINFOEXW; ok is false if it isn't one.
func parseSessionInfoEx(b []byte) (session, flags uint32, ok bool) {
	if len(b) < wtsInfoExMinSize || binary.LittleEndian.Uint32(b) != 1 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(b[8:]), binary.LittleEndian.Uint32(b[16:]), true
}

// lockedFromFlags: whether SessionFlags says the session is locked, and whether it says anything. Microsoft documents
// that on Windows 7 and Server 2008 R2 the LOCK and UNLOCK values are swapped; touchenv needs Windows 10 or 11, where
// they mean what they say, so this doesn't try to tell the versions apart.
func lockedFromFlags(flags uint32) (locked, known bool) {
	switch flags {
	case wtsSessionStateLock:
		return true, true
	case wtsSessionStateUnlock:
		return false, true
	}
	return false, false
}
