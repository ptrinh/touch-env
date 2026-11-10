package winplat

// touchenv.exe's side of the touchenv service: connecting (and checking it is really the service), the
// "Don't ask again for 5 minutes?" question, starting the tray, and installing or removing the service.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	shell32                = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteEx     = shell32.NewProc("ShellExecuteExW")
	procWaitNamedPipe      = kernel32.NewProc("WaitNamedPipeW")
	trayMutexName          = `Local\touchenv-tray` // Local: one per Windows session
	serviceAccount         = `NT SERVICE\touchenv`
	errServiceNotAnswering = errors.New("the touchenv service is running but not answering (touchenv service install again restarts it)")
)

// Service implements core.Service.
type Service struct{}

func NewService() *Service { return &Service{} }

// servicePID is the pid of the running touchenv service, from the Service Control Manager (0 if it isn't running).
func servicePID() uint32 {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0
	}
	defer windows.CloseServiceHandle(scm)
	s, err := windows.OpenService(scm, utf16z(serviceName), windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need) != nil ||
		st.CurrentState != windows.SERVICE_RUNNING {
		return 0
	}
	return st.ProcessId
}

// Dial opens the pipe at identification level (the service can read who we are, never act as us) and checks
// that the process serving it is the touchenv service the Service Control Manager started, so a program that
// grabbed the name first never receives a secret.
func (Service) Dial() (io.ReadWriteCloser, error) { return dial(pipeName, servicePID) }

func dial(path string, servicePID func() uint32) (io.ReadWriteCloser, error) {
	name := utf16z(path)
	var h windows.Handle
	var err error
	busy, missing := 0, 0
	for {
		h, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			if servicePID() == 0 {
				return nil, core.ErrNoService
			}
			// Running, but no instance waiting this instant (between two clients, or just started): try again
			// for up to 2 seconds.
			if missing++; missing <= 40 {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("%w (CreateFile %s: %v)", errServiceNotAnswering, path, err)
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return nil, fmt.Errorf("%w (it only answers programs in a desktop session on this PC, not over SSH or from a service)", core.ErrNoService)
		case errors.Is(err, windows.ERROR_PIPE_BUSY):
			if busy++; busy <= 3 {
				procWaitNamedPipe.Call(uintptr(unsafe.Pointer(name)), 2000)
				continue
			}
		}
		return nil, fmt.Errorf("can't reach the touchenv service: CreateFile %s: %v (0x%X)", path, err, errnoOf(err))
	}
	var server uint32
	serr := windows.GetNamedPipeServerProcessId(h, &server)
	want := servicePID()
	if serr != nil || server == 0 || server != want {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w (pipe server pid %d, error %v; the service's pid is %d)", core.ErrNotService, server, serr, want)
	}
	return os.NewFile(uintptr(h), path), nil
}

func errnoOf(err error) uint32 {
	var e windows.Errno
	if errors.As(err, &e) {
		return uint32(e)
	}
	return 0
}

const (
	mbYesNoCancel   = 0x3
	mbIconQuestion  = 0x20
	mbDefButton2    = 0x100
	mbSetForeground = 0x10000
	mbTopmost       = 0x40000
	idYes           = 6
	idNo            = 7
)

// AskKeep asks in a plain Windows message box, No preselected: Yes keeps for 5 minutes, No is this once,
// Cancel stops.
func (Service) AskKeep(text string) (bool, bool, error) {
	owner, _, _ := procGetConsoleWindow.Call()
	r, err := windows.MessageBox(windows.HWND(owner), utf16z(text), utf16z("touchenv"),
		mbYesNoCancel|mbIconQuestion|mbDefButton2|mbSetForeground|mbTopmost)
	if r == 0 {
		return false, false, err
	}
	return r == idYes || r == idNo, r == idYes, nil
}

// StartTray starts "touchenv tray" in this session unless one runs already. Best effort.
func (Service) StartTray() {
	if h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, utf16z(trayMutexName)); err == nil {
		windows.CloseHandle(h)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "tray")
	cmd.Env = os.Environ() // touchenv's own environment: the secrets only ever go into the command's
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if cmd.Start() == nil {
		cmd.Process.Release()
	}
}

// MARK: install and uninstall

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// shellExecuteInfo is SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	Size        uint32
	Mask        uint32
	Hwnd        uintptr
	Verb        *uint16
	File        *uint16
	Parameters  *uint16
	Directory   *uint16
	Show        int32
	InstApp     uintptr
	IDList      uintptr
	Class       *uint16
	KeyClass    uintptr
	HotKey      uint32
	IconMonitor uintptr
	Process     windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x40
	seeMaskNoAsync        = 0x100
	swHide                = 0
)

// Exit codes of the elevated copy, so it needs to write nowhere the user could point it at.
var elevatedFailures = map[uint32]string{
	10: "couldn't copy touchenv.exe to Program Files",
	11: "the Service Control Manager refused",
	12: "the service didn't start",
	13: "couldn't remove the service",
	14: "this must run as administrator",
}

// runElevated runs touchenv.exe args as administrator: Windows shows its UAC prompt, which only a person can approve.
func runElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	info := shellExecuteInfo{Mask: seeMaskNoCloseProcess | seeMaskNoAsync, Verb: utf16z("runas"), File: utf16z(exe),
		Parameters: utf16z(windows.ComposeCommandLine(args)), Show: swHide}
	info.Size = uint32(unsafe.Sizeof(info))
	if r, _, e := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		if errors.Is(e, windows.ERROR_CANCELLED) {
			return errors.New("not approved: Windows asked for administrator approval and it was declined")
		}
		return fmt.Errorf("couldn't ask for administrator approval: %v", e)
	}
	defer windows.CloseHandle(info.Process)
	windows.WaitForSingleObject(info.Process, windows.INFINITE)
	var code uint32
	windows.GetExitCodeProcess(info.Process, &code)
	if code != 0 {
		if msg, ok := elevatedFailures[code]; ok {
			return errors.New(msg)
		}
		return fmt.Errorf("failed (exit %d)", code)
	}
	return nil
}

func (s Service) Install(offerKeep bool, out io.Writer) error {
	args := []string{"service", "install-elevated"}
	if offerKeep {
		args = append(args, "--offer-5-minutes")
	}
	var err error
	if elevated() {
		if code := Elevated(args[1:]); code != 0 {
			err = errors.New(elevatedFailures[uint32(code)])
		}
	} else {
		fmt.Fprintln(out, "Windows will ask for administrator approval to install the touchenv service.")
		err = runElevated(args)
	}
	if err != nil {
		return err
	}
	// Check from here, as you: the service answers, and is the one just installed.
	conn, err := s.Dial()
	if errors.Is(err, core.ErrNoService) && err != core.ErrNoService {
		// Installed and running, but this session isn't one it answers (SSH, a service, a CI runner).
		fmt.Fprintf(out, "touchenv service installed and running, as %s, from %s. It can't be reached from here: %v.\n",
			serviceAccount, installedExe(), err)
		return nil
	}
	if err != nil {
		return fmt.Errorf("installed, but it doesn't answer: %v", err)
	}
	reply, err := core.Ask(conn, core.Request{Op: "status"})
	conn.Close()
	if err != nil || !reply.OK {
		return fmt.Errorf("installed, but it doesn't answer properly: %v %s", err, reply.Error)
	}
	keep := "5-minute approvals are off (touchenv service install --offer-5-minutes offers them)."
	if reply.OfferKeep {
		keep = "touchenv run offers \"Don't ask again for 5 minutes\"."
	}
	fmt.Fprintf(out, "touchenv service %s installed and running, as %s, from %s.\n"+
		"touchenv grant works now. %s Installing again (a new version) ends every grant and approval.\n",
		reply.Version, serviceAccount, installedExe(), keep)
	return nil
}

func (Service) Uninstall(out io.Writer) error {
	var err error
	if elevated() {
		if code := Elevated([]string{"uninstall-elevated"}); code != 0 {
			err = errors.New(elevatedFailures[uint32(code)])
		}
	} else {
		fmt.Fprintln(out, "Windows will ask for administrator approval to remove the touchenv service.")
		err = runElevated([]string{"service", "uninstall-elevated"})
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "touchenv service removed: every grant and 5-minute approval ended. touchenv run asks Windows Hello every time.")
	return nil
}

func installDir() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		dir = os.Getenv("ProgramFiles")
	}
	return filepath.Join(dir, "touchenv")
}

func installedExe() string { return filepath.Join(installDir(), "touchenv.exe") }

// Elevated runs "touchenv service install-elevated|uninstall-elevated" (args without "service"), as administrator.
// Returns the process exit code (elevatedFailures).
func Elevated(args []string) int {
	if !elevated() {
		return 14
	}
	switch {
	case len(args) >= 1 && args[0] == "install-elevated":
		offer := len(args) == 2 && args[1] == "--offer-5-minutes"
		return installService(offer)
	case len(args) == 1 && args[0] == "uninstall-elevated":
		return uninstallService()
	}
	return 14
}

func stopService(s *mgr.Service) {
	st, err := s.Control(svc.Stop)
	for i := 0; err == nil && st.State != svc.Stopped && i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		st, err = s.Query()
	}
}

// copyExe puts this touchenv.exe in Program Files, which only administrators can change: the service never runs a
// file you (or a program running as you) could replace.
func copyExe() error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	dst := installedExe()
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	if err := os.MkdirAll(installDir(), 0o755); err != nil { // inherits Program Files' ACL
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	for i := 0; ; i++ {
		err = windows.MoveFileEx(utf16z(tmp), utf16z(dst), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if err == nil || i >= 50 { // the old service may hold the file for a moment after it stops
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// serviceRequiredPrivilegesInfo is SERVICE_REQUIRED_PRIVILEGES_INFOW.
type serviceRequiredPrivilegesInfo struct {
	RequiredPrivileges *uint16 // MULTI_SZ
}

func installService(offerKeep bool) int {
	m, err := mgr.Connect()
	if err != nil {
		return 11
	}
	defer m.Disconnect()
	existing, err := m.OpenService(serviceName)
	if err == nil {
		stopService(existing) // an update: every grant held ends here
	}
	if err := copyExe(); err != nil {
		if existing != nil {
			existing.Close()
		}
		return 10
	}
	args := []string{"service", "run"}
	if offerKeep {
		args = append(args, "--offer-5-minutes")
	}
	cfg := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      "touchenv",
		Description:      "Keeps touchenv grants and 5-minute approvals in memory, nothing on disk. touchenv lock ends them.",
		ServiceStartName: serviceAccount, // a virtual account: no password, no rights beyond what is granted to it
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	s := existing
	if s != nil {
		cfg.BinaryPathName = windows.ComposeCommandLine(append([]string{installedExe()}, args...))
		err = s.UpdateConfig(cfg)
	} else {
		s, err = m.CreateService(serviceName, installedExe(), cfg, args...)
	}
	if err != nil {
		return 11
	}
	defer s.Close()
	// Every privilege the account would have is dropped except SeChangeNotifyPrivilege (which Windows always keeps).
	privs, _ := windows.UTF16FromString("SeChangeNotifyPrivilege")
	privs = append(privs, 0)
	info := serviceRequiredPrivilegesInfo{RequiredPrivileges: &privs[0]}
	if windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info))) != nil {
		return 11
	}
	s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 24*60*60)
	if err := s.Start(); err != nil {
		return 12
	}
	for i := 0; i < 100; i++ {
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 12
}

func uninstallService() int {
	m, err := mgr.Connect()
	if err != nil {
		return 11
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		stopService(s)
		err = s.Delete()
		s.Close()
		if err != nil {
			return 13
		}
	}
	dir := installDir()
	if exe, err := os.Executable(); err == nil && strings.EqualFold(filepath.Dir(exe), dir) {
		// Running from there: Windows removes it at the next restart.
		windows.MoveFileEx(utf16z(installedExe()), nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		return 0
	}
	for i := 0; i < 25; i++ {
		if os.RemoveAll(dir) == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0
}
