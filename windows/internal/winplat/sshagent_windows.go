package winplat

// touchenv's SSH agent on Windows: core.SSHHost. The agent is touchenv.exe itself ("touchenv ssh agent serve"),
// running in your session (it has to: Windows Hello asks there, and only your account can open the store), started
// at every logon by a value under HKCU\...\Run and at once by install. It serves the named pipe
// \\.\pipe\touchenv-ssh-<your SID>, which only your account (and SYSTEM) may open, never from the network. Windows
// OpenSSH finds it through IdentityAgent in .ssh\config. Uninstall signals a named event the agent waits on.

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
	"golang.org/x/sys/windows/registry"
)

const (
	runKey      = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue    = "touchenv ssh agent"
	sshPipeBase = `\\.\pipe\touchenv-ssh-`
)

var (
	procShowWindow  = user32.NewProc("ShowWindow")
	procFreeConsole = kernel32.NewProc("FreeConsole")
	procConsoleList = kernel32.NewProc("GetConsoleProcessList")
)

type SSHHost struct{}

func NewSSHHost() *SSHHost { return &SSHHost{} }

func (SSHHost) HomeDir() (string, error) { return os.UserHomeDir() }

func (SSHHost) AgentPipe() (string, error) {
	sid, err := userSID()
	if err != nil {
		return "", err
	}
	return sshPipeBase + sid, nil
}

func stopEventName() (string, error) {
	sid, err := userSID()
	if err != nil {
		return "", err
	}
	return `Local\touchenv-ssh-agent-stop-` + sid, nil
}

func (SSHHost) Procs() core.ProcTable { return processTable() }

// pipeServer: the image name of the process serving pipe, "" if nobody answers.
func pipeServer(pipe string) string {
	h, err := windows.CreateFile(utf16z(pipe), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return "busy"
	}
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var pid uint32
	if windows.GetNamedPipeServerProcessId(h, &pid) != nil {
		return "unknown"
	}
	return processTable()[pid].Name
}

func (s SSHHost) AgentState() (atLogon, running bool) {
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE); err == nil {
		_, _, err = k.GetStringValue(runValue)
		atLogon = err == nil
		k.Close()
	}
	if pipe, err := s.AgentPipe(); err == nil {
		server := pipeServer(pipe)
		running = server == "busy" || strings.EqualFold(server, "touchenv.exe")
	}
	return atLogon, running
}

func (s SSHHost) InstallAgent() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	err = k.SetStringValue(runValue, `"`+exe+`" ssh agent serve`)
	k.Close()
	if err != nil {
		return err
	}
	// Restart it, so the agent is this touchenv.exe (a new version, or a new place) from now on.
	s.stop()
	cmd := exec.Command(exe, "ssh", "agent", "serve")
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	cmd.Process.Release()
	for i := 0; i < 30; i++ {
		if _, running := s.AgentState(); running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (s SSHHost) UninstallAgent() error {
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE); err == nil {
		err = k.DeleteValue(runValue)
		k.Close()
		if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return err
		}
	}
	s.stop()
	return nil
}

// HideConsole: started at logon from the Run key, a console program gets a console window of its own. The agent
// hides it and lets it go (main calls this for "ssh agent serve" only). A console shared with others (serve typed in
// a terminal) is left alone.
func HideConsole() {
	var pids [4]uint32
	if n, _, _ := procConsoleList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids))); n != 1 {
		return
	}
	if w, _, _ := procGetConsoleWindow.Call(); w != 0 {
		procShowWindow.Call(w, 0) // SW_HIDE
		procFreeConsole.Call()
	}
}

// stop tells a running agent to quit and waits (3 seconds at most) for its pipe to go.
func (s SSHHost) stop() {
	name, err := stopEventName()
	if err != nil {
		return
	}
	ev, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, utf16z(name))
	if err != nil {
		return
	}
	windows.SetEvent(ev)
	windows.CloseHandle(ev)
	pipe, _ := s.AgentPipe()
	for i := 0; i < 30 && pipeServer(pipe) != ""; i++ {
		time.Sleep(100 * time.Millisecond)
	}
}

// Serve runs the agent: one per session (the stop event's name says so), serving until stopped.
func (s SSHHost) Serve(handle func(conn io.ReadWriteCloser, clientPID uint32)) error {
	name, err := stopEventName()
	if err != nil {
		return err
	}
	stop, err := windows.CreateEvent(nil, 1, 0, utf16z(name))
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(stop)
		return errors.New("the SSH agent is already running in this session")
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(stop)
	sid, err := userSID()
	if err != nil {
		return err
	}
	pipe, err := s.AgentPipe()
	if err != nil {
		return err
	}
	// Your account and SYSTEM only; never from the network.
	sddl := "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;" + sid + ")"
	done := make(chan struct{})
	ready := make(chan struct{})
	served := make(chan error, 1)
	go func() {
		served <- servePipe(pipe, sddl, func(p windows.Handle) {
			var pid uint32
			if windows.GetNamedPipeClientProcessId(p, &pid) != nil {
				windows.CloseHandle(p)
				return
			}
			conn, err := newPipeConn(p)
			if err != nil {
				windows.CloseHandle(p)
				return
			}
			conn.timeout = windows.INFINITE // ssh keeps the connection while it waits, and while you answer Hello
			handle(conn, pid)
		}, stop, done, func() { close(ready) })
	}()
	select {
	case err := <-served:
		if err == nil {
			err = errors.New("stopped before it started")
		}
		return fmt.Errorf("can't serve %s (another program holds it?): %w", pipe, err)
	case <-ready:
	}
	windows.WaitForSingleObject(stop, windows.INFINITE)
	close(done)
	// Connections still open (an ssh session in progress) end with the process.
	return nil
}
