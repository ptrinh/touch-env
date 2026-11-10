package winplat

// The touchenv service: holds grants and 5-minute approvals (core.Holder) in its own memory, as the virtual account
// NT SERVICE\touchenv, reached by touchenv.exe over \\.\pipe\touchenv. A program running as you can't read or change
// a service's memory without administrator rights, so the time limit, the use count and lock are kept here, not in
// a process of yours. Nothing is written to disk or to the event log.
//
// Who asks is taken from Windows, never from the request: the client's token (user SID, session, integrity) through
// identification-level impersonation of the pipe client, its pid from the pipe, and the process tree from the
// system's process list.

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName = "touchenv"
	pipeName    = `\\.\pipe\touchenv`
	// Interactive users may read and write, but not create pipe instances: FILE_GENERIC_READ|FILE_GENERIC_WRITE
	// without FILE_CREATE_PIPE_INSTANCE (0x4).
	clientAccess = "0x12019b"
)

// pipeSDDL: a protected DACL with SYSTEM and the account that serves the pipe (the service's own account) in full,
// interactive users as clients, network logons denied. The serving account is named outright: every instance after
// the first needs FILE_CREATE_PIPE_INSTANCE on this DACL, and "OWNER RIGHTS" depends on which owner the token
// puts on new objects. No label: Windows treats it as medium, so low-integrity and AppContainer processes can't
// write to it.
func pipeSDDL(server, clients string) string {
	return "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;" + server + ")(A;;" + clientAccess + ";;;" + clients + ")"
}

// pipeTrace, when set (tests), hears every pipe error and every instance made, with Windows' codes.
var pipeTrace func(format string, a ...any)

func trace(format string, a ...any) {
	if pipeTrace != nil {
		pipeTrace(format, a...)
	}
}

var (
	advapi32                      = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipe      = advapi32.NewProc("ImpersonateNamedPipeClient")
	procGetNamedPipeClientSession = kernel32.NewProc("GetNamedPipeClientSessionId")
	wtsapi32                      = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateProcessesEx   = wtsapi32.NewProc("WTSEnumerateProcessesExW")
	procWTSFreeMemoryEx           = wtsapi32.NewProc("WTSFreeMemoryExW")
)

// MARK: the process list

// processTable lists every process with its parent, start time, image name and session, from
// NtQuerySystemInformation(SystemProcessInformation), which needs no handle to the processes.
func processTable() core.ProcTable {
	size := uint32(256 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		buf := make([]byte, size)
		var need uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(&buf[0]), size, &need)
		if errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			size = max(need, size*2) + 64<<10
			continue
		}
		if err != nil {
			return core.ProcTable{}
		}
		t := core.ProcTable{}
		for off := uint32(0); int(off)+int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{})) <= len(buf); {
			p := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buf[off]))
			name := ""
			if p.ImageName.Buffer != nil && p.ImageName.Length > 0 {
				name = windows.UTF16ToString(unsafe.Slice(p.ImageName.Buffer, p.ImageName.Length/2))
			}
			t[uint32(p.UniqueProcessID)] = core.ProcInfo{Parent: uint32(p.InheritedFromUniqueProcessID),
				Start: uint64(p.CreateTime), Name: name, Session: p.SessionID}
			if p.NextEntryOffset == 0 {
				break
			}
			off += p.NextEntryOffset
		}
		return t
	}
	return core.ProcTable{}
}

// MARK: who is on the other end of the pipe

func pipeClientSession(pipe windows.Handle) (uint32, error) {
	var session uint32
	if r, _, e := procGetNamedPipeClientSession.Call(uintptr(pipe), uintptr(unsafe.Pointer(&session))); r == 0 {
		return 0, e
	}
	return session, nil
}

func tokenDword(t windows.Token, class uint32) (uint32, error) {
	var v, n uint32
	err := windows.GetTokenInformation(t, class, (*byte)(unsafe.Pointer(&v)), 4, &n)
	return v, err
}

const (
	tokenIsAppContainer = 29
	mandatoryMediumRID  = 0x2000 // SECURITY_MANDATORY_MEDIUM_RID
)

// clientIdentity: the pipe client's user, session and pid as Windows reports them. The client connects at
// identification level, so the service can read its token but never act as it.
func clientIdentity(pipe windows.Handle) (core.Caller, error) {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &pid); err != nil {
		return core.Caller{}, err
	}
	session, err := pipeClientSession(pipe)
	if err != nil {
		return core.Caller{}, err
	}
	user, err := tokenUser(pipe, session)
	if err != nil {
		user, err = wtsUser(pid, session)
	}
	if err != nil {
		return core.Caller{}, err
	}
	return core.Caller{User: user, Session: session, PID: pid}, nil
}

// tokenUser reads the client's token: its user, and that it is in the pipe's session, at medium integrity or above,
// and not an AppContainer.
func tokenUser(pipe windows.Handle, session uint32) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, e := procImpersonateNamedPipe.Call(uintptr(pipe)); r == 0 {
		return "", e
	}
	var t windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &t)
	if rerr := windows.RevertToSelf(); rerr != nil {
		// Never go on serving as someone else.
		panic("touchenv service: RevertToSelf failed: " + rerr.Error())
	}
	if err != nil {
		return "", err
	}
	defer t.Close()
	u, err := t.GetTokenUser()
	if err != nil {
		return "", err
	}
	if s, err := tokenDword(t, windows.TokenSessionId); err != nil || s != session {
		return "", errors.New("the client's token is from another session")
	}
	if ac, err := tokenDword(t, tokenIsAppContainer); err == nil && ac != 0 {
		return "", errors.New("AppContainer clients are refused")
	}
	var label [64]byte
	var n uint32
	if err := windows.GetTokenInformation(t, windows.TokenIntegrityLevel, &label[0], uint32(len(label)), &n); err != nil {
		return "", err
	}
	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&label[0])).Label.Sid
	if c := sid.SubAuthorityCount(); c == 0 || sid.SubAuthority(uint32(c)-1) < mandatoryMediumRID {
		return "", errors.New("low-integrity clients are refused")
	}
	return u.User.Sid.String(), nil
}

// wtsProcessInfoEx is WTS_PROCESS_INFO_EXW.
type wtsProcessInfoEx struct {
	SessionID, ProcessID uint32
	ProcessName          *uint16
	UserSid              *windows.SID
	NumberOfThreads      uint32
	HandleCount          uint32
	PagefileUsage        uint32
	PeakPagefileUsage    uint32
	WorkingSetSize       uint32
	PeakWorkingSetSize   uint32
	UserTime, KernelTime int64
}

// wtsUser is the fallback when the service may not open the client's token: the user of the client process as
// Remote Desktop Services lists it. The pipe's own label and DACL still keep out low-integrity and AppContainer
// clients.
func wtsUser(pid, session uint32) (string, error) {
	level := uint32(1)
	var info uintptr
	var count uint32
	if r, _, e := procWTSEnumerateProcessesEx.Call(0, uintptr(unsafe.Pointer(&level)), uintptr(session),
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&count))); r == 0 {
		return "", fmt.Errorf("can't tell who the client is: %v", e)
	}
	defer procWTSFreeMemoryEx.Call(1, info, uintptr(count)) // WTSTypeProcessInfoLevel1
	list := unsafe.Slice(*(**wtsProcessInfoEx)(unsafe.Pointer(&info)), count)
	for _, p := range list {
		if p.ProcessID == pid && p.SessionID == session && p.UserSid != nil {
			return p.UserSid.String(), nil
		}
	}
	return "", errors.New("can't tell who the client is")
}

// MARK: the pipe

var errTimeout = errors.New("timed out")

// pipeConn does overlapped I/O on a server pipe handle with a time limit, through a buffer of its own (the
// buffer and the OVERLAPPED stay put in the heap while Windows uses them), wiped after each use.
type pipeConn struct {
	h       windows.Handle
	ov      *windows.Overlapped
	buf     []byte
	timeout uint32
}

func newPipeConn(h windows.Handle) (*pipeConn, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	return &pipeConn{h: h, ov: &windows.Overlapped{HEvent: ev}, buf: make([]byte, 64<<10), timeout: 5000}, nil
}

func (p *pipeConn) do(write bool, n int) (int, error) {
	windows.ResetEvent(p.ov.HEvent)
	var done uint32
	var err error
	if write {
		err = windows.WriteFile(p.h, p.buf[:n], &done, p.ov)
	} else {
		err = windows.ReadFile(p.h, p.buf[:n], &done, p.ov)
	}
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		ev, _ := windows.WaitForSingleObject(p.ov.HEvent, p.timeout)
		if ev != windows.WAIT_OBJECT_0 {
			windows.CancelIoEx(p.h, p.ov)
			windows.GetOverlappedResult(p.h, p.ov, &done, true)
			return 0, errTimeout
		}
		err = windows.GetOverlappedResult(p.h, p.ov, &done, true)
	}
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) || (err == nil && !write && done == 0) {
		return 0, io.EOF
	}
	return int(done), err
}

func (p *pipeConn) Read(b []byte) (int, error) {
	n, err := p.do(false, min(len(b), len(p.buf)))
	copy(b, p.buf[:n])
	clear(p.buf[:n])
	return n, err
}

func (p *pipeConn) Write(b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n := copy(p.buf, b[written:])
		got, err := p.do(true, n)
		clear(p.buf[:n])
		written += got
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (p *pipeConn) Close() error {
	windows.CloseHandle(p.ov.HEvent)
	// No DisconnectNamedPipe: it would throw away a reply the client hasn't read yet. Closing lets it read to the end.
	return windows.CloseHandle(p.h)
}

func pipeAttributes(sddl string) (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

// pipeListeners: instances kept waiting for a client at all times. With only one, there is a moment after each
// connection when no instance exists, and a client's CreateFile then fails with ERROR_FILE_NOT_FOUND, not
// ERROR_PIPE_BUSY (CI saw exactly that).
const pipeListeners = 4

func createInstance(name *uint16, sa *windows.SecurityAttributes, first bool) (windows.Handle, error) {
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	return windows.CreateNamedPipe(name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, sa)
}

// servePipe accepts connections until stop is signalled; ready (if not nil) is called once the pipe exists. The
// first instance is made with FILE_FLAG_FIRST_PIPE_INSTANCE: if anything else holds the name, the service doesn't
// start (and clients check that the pipe's server is this service's process anyway).
func servePipe(path, sddl string, h *core.Holder, stopEvent windows.Handle, done <-chan struct{}, ready func()) error {
	sa, err := pipeAttributes(sddl)
	if err != nil {
		return err
	}
	name := utf16z(path)
	first, err := createInstance(name, sa, true)
	if err != nil {
		trace("first CreateNamedPipe: %v (0x%X)", err, errnoOf(err))
		return fmt.Errorf("can't create %s: %w", path, err)
	}
	if ready != nil {
		ready()
	}
	slots := make(chan struct{}, 64)
	var handlers, listeners sync.WaitGroup
	for i := 0; i < pipeListeners; i++ {
		p := windows.Handle(0)
		if i == 0 {
			p = first
		}
		listeners.Add(1)
		go func() {
			defer listeners.Done()
			listen(i, p, name, sa, h, stopEvent, done, slots, &handlers)
		}()
	}
	listeners.Wait()
	handlers.Wait()
	return nil
}

// listen keeps one instance waiting: wait for a client, hand it to a goroutine, make the next instance at once.
// Serving never holds up the next instance.
func listen(id int, p windows.Handle, name *uint16, sa *windows.SecurityAttributes, h *core.Holder, stopEvent windows.Handle,
	done <-chan struct{}, slots chan struct{}, handlers *sync.WaitGroup) {
	defer func() {
		if p != 0 {
			windows.CloseHandle(p)
		}
	}()
	for {
		if p == 0 {
			var err error
			if p, err = createInstance(name, sa, false); err != nil {
				trace("listener %d: CreateNamedPipe: %v (0x%X)", id, err, errnoOf(err))
				p = 0
				select {
				case <-done:
					return
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			trace("listener %d: instance made", id)
		}
		if err := waitConnect(p, stopEvent); err != nil {
			windows.CloseHandle(p)
			p = 0
			select {
			case <-done:
				return
			default:
			}
			// ERROR_NO_DATA: the client came and went before we got to it. Anything else is worth knowing.
			trace("listener %d: ConnectNamedPipe: %v (0x%X)", id, err, errnoOf(err))
			continue
		}
		conn := p
		p = 0
		select {
		case slots <- struct{}{}:
		default: // too many at once: refuse this one rather than queue
			trace("listener %d: too many clients, one refused", id)
			windows.CloseHandle(conn)
			continue
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { <-slots }()
			handleClient(h, conn, done)
		}()
	}
}

var errStopped = errors.New("stopping")

// waitConnect waits for a client on p, or for stop. ERROR_PIPE_CONNECTED (the client got there first) is a client.
func waitConnect(p, stopEvent windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	ov := &windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(p, ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return err
	}
	which, err := windows.WaitForMultipleObjects([]windows.Handle{ev, stopEvent}, false, windows.INFINITE)
	var n uint32
	if which != windows.WAIT_OBJECT_0 {
		windows.CancelIoEx(p, ov)
		windows.GetOverlappedResult(p, ov, &n, true)
		if which == windows.WAIT_OBJECT_0+1 {
			return errStopped
		}
		return fmt.Errorf("waiting for a client: %d %v", which, err)
	}
	return windows.GetOverlappedResult(p, ov, &n, true)
}

func handleClient(h *core.Holder, p windows.Handle, done <-chan struct{}) {
	conn, err := newPipeConn(p)
	if err != nil {
		windows.CloseHandle(p)
		return
	}
	defer conn.Close()
	h.Serve(conn, func() (core.Caller, error) { return clientIdentity(p) }, core.Version, done)
}

// MARK: memory for held secrets

var locked struct {
	sync.Mutex
	regions map[*byte]uintptr // first byte -> region size
}

func pageRound(n int) uintptr { return (uintptr(n) + 4095) &^ 4095 }

// lockedAlloc gives memory outside Go's heap, locked so Windows doesn't write it to the pagefile (when the working
// set allows; if not, it is still used, only not locked). Hibernation and crash dumps can still hold it.
func lockedAlloc(n int) []byte {
	size := pageRound(max(n, 1))
	addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return make([]byte, n)
	}
	windows.VirtualLock(addr, size)
	b := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&addr))), n)
	locked.Lock()
	if locked.regions == nil {
		locked.regions = map[*byte]uintptr{}
	}
	locked.regions[unsafe.SliceData(b)] = size
	locked.Unlock()
	return b
}

func lockedFree(b []byte) {
	clear(b)
	if cap(b) == 0 {
		return
	}
	first := unsafe.SliceData(b)
	locked.Lock()
	size, ok := locked.regions[first]
	delete(locked.regions, first)
	locked.Unlock()
	if !ok {
		return
	}
	addr := uintptr(unsafe.Pointer(first))
	windows.VirtualUnlock(addr, size)
	windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
}

// MARK: the service

type service struct{ offerKeep bool }

// sessionOf reads the session id from a session-change notification (copied with ReadProcessMemory from our own
// process, which keeps a pointer held as an integer out of Go's sight).
func sessionOf(eventData uintptr) (uint32, bool) {
	var n windows.WTSSESSION_NOTIFICATION
	if eventData == 0 {
		return 0, false
	}
	err := windows.ReadProcessMemory(windows.CurrentProcess(), eventData, (*byte)(unsafe.Pointer(&n)), unsafe.Sizeof(n), nil)
	return n.SessionID, err == nil
}

func (s *service) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	h := &core.Holder{Now: time.Now, Procs: processTable, Alloc: lockedAlloc, Free: lockedFree, OfferKeep: s.offerKeep}
	stopEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return true, 1
	}
	defer windows.CloseHandle(stopEvent)
	done := make(chan struct{})
	served := make(chan error, 1)
	listening := make(chan struct{})
	self, err := userSID() // NT SERVICE\touchenv
	if err != nil {
		return true, 1
	}
	go func() {
		served <- servePipe(pipeName, pipeSDDL(self, "IU"), h, stopEvent, done, func() { close(listening) })
	}()
	// Running only once the pipe exists, so a client right after "touchenv service install" finds it.
	select {
	case <-listening:
	case <-served: // another program holds the name
		return true, 1
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange}
	code := uint32(0)
loop:
	for {
		select {
		case <-tick.C:
			h.Tick()
		case <-served:
			code = 1 // the pipe couldn't be made (another program holds the name?)
			break loop
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			case svc.SessionChange:
				if session, ok := sessionOf(r.EventData); ok {
					switch r.EventType {
					case windows.WTS_SESSION_LOGOFF:
						h.SessionEnded(session)
					case windows.WTS_SESSION_LOCK:
						h.SessionLocked(session)
					}
				}
			}
		}
	}
	status <- svc.Status{State: svc.StopPending}
	close(done)
	windows.SetEvent(stopEvent)
	h.LockAll()
	return code != 0, code
}

// RunService runs as the touchenv service (started by the Service Control Manager as "touchenv service run").
func RunService(args []string) int {
	s := &service{}
	for _, a := range args {
		if a == "--offer-5-minutes" {
			s.offerKeep = true
		}
	}
	if err := svc.Run(serviceName, s); err != nil {
		return 1
	}
	return 0
}
