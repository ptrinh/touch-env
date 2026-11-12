package winplat

import (
	"encoding/binary"
	"testing"
)

func TestParseSessionInfoEx(t *testing.T) {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b, 1)
	binary.LittleEndian.PutUint32(b[8:], 3)  // SessionId
	binary.LittleEndian.PutUint32(b[12:], 0) // WTSActive
	for flags, want := range map[uint32][2]bool{0: {true, true}, 1: {false, true}, 0xFFFFFFFF: {false, false}, 7: {false, false}} {
		binary.LittleEndian.PutUint32(b[16:], flags)
		session, got, ok := parseSessionInfoEx(b)
		if !ok || session != 3 || got != flags {
			t.Fatalf("%d: %d %d %v", flags, session, got, ok)
		}
		if locked, known := lockedFromFlags(got); locked != want[0] || known != want[1] {
			t.Errorf("flags %d: locked %v known %v", flags, locked, known)
		}
	}
	if _, _, ok := parseSessionInfoEx(b[:19]); ok {
		t.Fatal("short buffer read")
	}
	binary.LittleEndian.PutUint32(b, 2)
	if _, _, ok := parseSessionInfoEx(b); ok {
		t.Fatal("level 2 read as level 1")
	}
}
