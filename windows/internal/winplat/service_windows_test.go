package winplat

// Runs on Windows (CI). The service's pieces over a real named pipe, with a test name and a DACL for the current
// user (CI runners may not be interactive logons). The installed service itself is checked by the workflow.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"golang.org/x/sys/windows"
)

func TestProcessTableSeesThisProcess(t *testing.T) {
	table := processTable()
	me, ok := table[windows.GetCurrentProcessId()]
	if !ok {
		t.Fatal("this process isn't in the table")
	}
	if me.Parent != uint32(os.Getppid()) || me.Start == 0 || !strings.HasSuffix(strings.ToLower(me.Name), ".exe") {
		t.Fatalf("%+v (parent should be %d)", me, os.Getppid())
	}
	var session uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session)
	if me.Session != session {
		t.Fatalf("session %d, want %d", me.Session, session)
	}
	if start := startTime(windows.GetCurrentProcessId()); start != me.Start {
		t.Fatalf("start %d, GetProcessTimes says %d", me.Start, start)
	}
	if lineage := table.Lineage(windows.GetCurrentProcessId()); len(lineage) < 2 {
		t.Fatalf("lineage %v", lineage)
	}
}

func testPipe(t *testing.T, h *core.Holder) string {
	t.Helper()
	var r [8]byte
	rand.Read(r[:])
	path := `\\.\pipe\touchenv-test-` + hex.EncodeToString(r[:])
	sid, err := userSID()
	if err != nil {
		t.Fatal(err)
	}
	stop, _ := windows.CreateEvent(nil, 1, 0, nil)
	done := make(chan struct{})
	served := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		served <- servePipe(path, "D:P(A;;GA;;;SY)(A;;0x12019b;;;"+sid+")", h, stop, done, func() { close(ready) })
	}()
	select { // never os.Stat a pipe to wait for it: that opens it, and uses up an instance
	case <-ready:
	case err := <-served:
		t.Fatalf("servePipe: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the pipe never appeared")
	}
	t.Cleanup(func() {
		close(done)
		windows.SetEvent(stop)
		select {
		case err := <-served:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("the pipe server didn't stop")
		}
		windows.CloseHandle(stop)
	})
	return path
}

func TestPipeServesWithIdentityFromWindows(t *testing.T) {
	h := &core.Holder{Now: time.Now, Procs: processTable, Alloc: lockedAlloc, Free: lockedFree}
	path := testPipe(t, h)
	ask := func(req core.Request) core.Reply {
		t.Helper()
		// Pretend the test's own process is the service, so dial's server check passes.
		conn, err := dial(path, windows.GetCurrentProcessId)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		reply, err := core.Ask(conn, req)
		if err != nil {
			t.Fatalf("%s: %v", req.Op, err)
		}
		t.Logf("%s: %+v", req.Op, reply)
		return reply
	}
	if reply := ask(core.Request{Op: "status"}); !reply.OK || reply.Version != core.Version {
		t.Fatalf("status: %+v", reply)
	}
	// get is refused: the client is winplat.test.exe, not touchenv.exe. That shows the service identified the
	// client (an identity failure would say "can't tell who is asking: ...") and looked it up in the real process
	// list by the pid Windows gave it.
	if reply := ask(core.Request{Op: "get", Names: []string{"A"}}); reply.OK || reply.Error != "only touchenv.exe may ask the touchenv service" {
		t.Fatalf("get: %+v", reply)
	}
	// Many clients at once: never "not found" or "busy" while the server runs.
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			conn, err := dial(path, windows.GetCurrentProcessId)
			if err == nil {
				_, err = core.Ask(conn, core.Request{Op: "status"})
				conn.Close()
			}
			errs <- err
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-errs; err != nil {
			t.Errorf("client %d: %v", i, err)
		}
	}
}

func TestClientIdentityIsThisUser(t *testing.T) {
	var r [8]byte
	rand.Read(r[:])
	path := `\\.\pipe\touchenv-test-` + hex.EncodeToString(r[:])
	sid, _ := userSID()
	sa, err := pipeAttributes("D:P(A;;GA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	server, err := windows.CreateNamedPipe(utf16z(path), windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, sa)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(server)
	client, err := windows.CreateFile(utf16z(path), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(client)
	// Windows lets the server look at the client only after it has read from the pipe.
	var n1 uint32
	if err := windows.WriteFile(client, []byte{1}, &n1, nil); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if err := windows.ReadFile(server, one[:], &n1, nil); err != nil {
		t.Fatal(err)
	}
	var session uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session)
	caller, err := clientIdentity(server)
	if err != nil {
		t.Fatal(err)
	}
	if caller.User != sid || caller.PID != windows.GetCurrentProcessId() || caller.Session != session {
		t.Fatalf("%+v, want %s pid %d session %d", caller, sid, windows.GetCurrentProcessId(), session)
	}
	if user, err := tokenUser(server, session); err != nil || user != sid {
		t.Fatalf("token: %q %v", user, err)
	}
	// The fallback, when the service may not open the client's token: report rather than fail.
	if user, err := wtsUser(windows.GetCurrentProcessId(), session); err != nil || user != sid {
		t.Logf("WTS fallback: %q %v", user, err)
	}
	// Identification level: the server can read the token but can't act as the client.
	var thread windows.Token
	if r, _, e := procImpersonateNamedPipe.Call(uintptr(server)); r == 0 {
		t.Fatal(e)
	}
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &thread)
	windows.RevertToSelf()
	if err != nil {
		t.Fatal(err)
	}
	defer thread.Close()
	var level, n uint32
	windows.GetTokenInformation(thread, windows.TokenImpersonationLevel, (*byte)(unsafe.Pointer(&level)), 4, &n)
	if level != windows.SecurityIdentification {
		t.Fatalf("impersonation level %d, want identification", level)
	}
}

// A program that holds the pipe's name isn't the service: touchenv refuses to talk to it.
func TestDialRefusesAnImpostor(t *testing.T) {
	sid, _ := userSID()
	sa, _ := pipeAttributes("D:P(A;;GA;;;" + sid + ")")
	var r [8]byte
	rand.Read(r[:])
	path := `\\.\pipe\touchenv-test-` + hex.EncodeToString(r[:])
	// A fresh waiting instance for each attempt: an instance whose client closed stays taken until its server
	// disconnects it, and this impostor never does (it would just look busy).
	instance := func() {
		t.Helper()
		p, err := windows.CreateNamedPipe(utf16z(path), windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE,
			windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, sa)
		if err != nil {
			t.Fatalf("CreateNamedPipe: %v", err)
		}
		t.Cleanup(func() { windows.CloseHandle(p) })
	}
	instance()
	if _, err := dial(path, func() uint32 { return 0 }); !errors.Is(err, core.ErrNotService) {
		t.Fatalf("no service running: %v", err)
	}
	instance()
	start := time.Now()
	_, err := dial(path, func() uint32 { return 4 })
	if !errors.Is(err, core.ErrNotService) || time.Since(start) > time.Second {
		t.Fatalf("another process is the service: %v (after %v)", err, time.Since(start))
	}
	t.Logf("refused: %v", err)
	if _, err := dial(path+"-none", func() uint32 { return 0 }); !errors.Is(err, core.ErrNoService) {
		t.Fatalf("no pipe: %v", err)
	}
}

func TestLockedMemory(t *testing.T) {
	b := lockedAlloc(100)
	if len(b) != 100 {
		t.Fatal(len(b))
	}
	copy(b, "secret")
	lockedFree(b)
	lockedFree(make([]byte, 3)) // not ours: wiped, nothing freed
}

func TestSessionOf(t *testing.T) {
	n := windows.WTSSESSION_NOTIFICATION{Size: 8, SessionID: 7}
	if s, ok := sessionOf(uintptr(unsafe.Pointer(&n))); !ok || s != 7 {
		t.Fatal(s, ok)
	}
	if _, ok := sessionOf(0); ok {
		t.Fatal("nil event data")
	}
}
