package winplat

// Runs on Windows (CI). The pieces the SSH agent added in 1.7.3 that work without Windows Hello: noticing a client
// that went away, reading the session's lock state, rewriting a file the user owns without touching its ACL, and
// telling touchenv's agent from another program serving its pipe.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// cmdPID starts a cmd.exe that waits, as a stand-in for some other program, and returns its pid.
func cmdPID(t *testing.T) uint32 {
	t.Helper()
	cmd := exec.Command("cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return uint32(cmd.Process.Pid)
}

func TestPipeClientGone(t *testing.T) {
	sid, err := userSID()
	if err != nil {
		t.Fatal(err)
	}
	sa, err := pipeAttributes("D:P(A;;GA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(`\\.\pipe\touchenv-test-gone-%d`, windows.GetCurrentProcessId())
	server, err := createInstance(utf16z(path), sa, true)
	if err != nil {
		t.Fatal(err)
	}
	client, err := windows.CreateFile(utf16z(path), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		windows.CloseHandle(server)
		t.Fatal(err)
	}
	stop, _ := windows.CreateEvent(nil, 1, 0, nil)
	defer windows.CloseHandle(stop)
	if err := waitConnect(server, stop); err != nil {
		t.Fatal(err)
	}
	conn, err := newPipeConn(server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.ClientGone() {
		t.Fatal("a connected client counted as gone")
	}
	windows.CloseHandle(client)
	if !conn.ClientGone() {
		t.Fatal("a client that closed its end still counted as there")
	}
}

// Checks wtsinfo.go's offsets against real Windows: the session id read from WTSINFOEXW is this process's own.
func TestSessionLockState(t *testing.T) {
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		t.Fatal(err)
	}
	id, flags, ok := sessionInfoEx(session)
	if !ok || id != session {
		t.Fatalf("WTSSessionInfoEx for session %d: id %d, ok %v", session, id, ok)
	}
	if flags != wtsSessionStateLock && flags != wtsSessionStateUnlock && flags != wtsSessionStateUnknown {
		t.Fatalf("SessionFlags %#x: not a value Windows documents (the offsets are wrong?)", flags)
	}
	locked, known := sessionLocked(session)
	t.Logf("session %d: flags %#x, locked %v, known %v", session, flags, locked, known)
}

func TestRewriteFileKeepsACL(t *testing.T) {
	sid, _ := userSID()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid + ")(A;;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(utf16z(path), windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	before := sddl(t, path)
	if err := (Platform{}).RewriteFile(path, []byte("Host *\n")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "Host *\n" {
		t.Fatalf("%q", data)
	}
	if after := sddl(t, path); after != before {
		t.Fatalf("DACL changed: %s -> %s", before, after)
	}
	if left, _ := filepath.Glob(path + ".new-*"); len(left) != 0 {
		t.Fatal("temp file left:", left)
	}
	fresh := filepath.Join(dir, "new")
	if err := (Platform{}).RewriteFile(fresh, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := sddl(t, fresh); got != only(t, "", sid) {
		t.Fatalf("a new file's DACL %s", got)
	}
}

// probePipe on nothing: not answered.
func TestProbeNoPipe(t *testing.T) {
	start := time.Now()
	if a := probePipe(fmt.Sprintf(`\\.\pipe\touchenv-test-none-%d`, windows.GetCurrentProcessId())); a.answered || a.ours {
		t.Fatalf("%+v", a)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("probing a missing pipe waited")
	}
}
