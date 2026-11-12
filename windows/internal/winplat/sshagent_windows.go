package winplat

// touchenv's SSH agent on Windows: core.SSHHost. The agent is touchenv.exe itself ("touchenv ssh agent serve"),
// running in your session (it has to: Windows Hello asks there, and only your account can open the store), started
// at every logon by a value under HKCU\...\Run and at once by install. It serves the named pipe
// \\.\pipe\touchenv-ssh-<your SID>, which only your account (and SYSTEM) may open, never from the network. Windows
// OpenSSH finds it through IdentityAgent in .ssh\config. Uninstall signals a named event the agent waits on. Each
// signature is made by a short-lived "touchenv ssh agent sign" the agent starts (SignHelper).

import (
	"bytes"
	"context"
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

// ownExe: this executable's full path, links resolved.
func ownExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

// runKeyExe: the program the Run value starts at logon, "" if there is none.
func runKeyExe() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runValue)
	if err != nil || !strings.HasPrefix(v, `"`) {
		return ""
	}
	exe, _, _ := strings.Cut(v[1:], `"`)
	return exe
}

// pipeAnswer is what probePipe found on the agent's pipe.
type pipeAnswer struct {
	answered bool   // something serves it
	ours     bool   // touchenv's agent, run as this user from this touchenv.exe or the one started at logon
	other    string // otherwise, what serves it
}

// probePipe connects to the agent's pipe and checks who serves it: the server process's full image path and the
// account it runs as, as Windows reports them (a program can name itself touchenv.exe, not be this file).
func probePipe(pipe string) pipeAnswer {
	name := utf16z(pipe)
	var h windows.Handle
	var err error
	for attempt := 0; ; attempt++ {
		h, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || attempt == 2 {
			break
		}
		procWaitNamedPipe.Call(uintptr(unsafe.Pointer(name)), 500)
	}
	if errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return pipeAnswer{answered: true, other: "every instance of the pipe is busy, so touchenv couldn't check what serves it; try again"}
	}
	if err != nil {
		return pipeAnswer{}
	}
	defer windows.CloseHandle(h)
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil {
		return pipeAnswer{answered: true, other: fmt.Sprintf("a process touchenv can't identify (%v)", err)}
	}
	return pipeAnswer{answered: true}.checkServer(pid)
}

func (a pipeAnswer) checkServer(pid uint32) pipeAnswer {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		a.other = fmt.Sprintf("process %d, which touchenv can't open (%v)", pid, err)
		return a
	}
	defer windows.CloseHandle(p)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	image := fmt.Sprintf("process %d", pid)
	if windows.QueryFullProcessImageName(p, 0, &buf[0], &size) == nil {
		image = fmt.Sprintf("%s (pid %d)", windows.UTF16ToString(buf[:size]), pid)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &token); err != nil {
		a.other = image + ", running as another account"
		return a
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	mine, err2 := userSID()
	if err != nil || err2 != nil || user.User.Sid.String() != mine {
		a.other = image + ", running as another account"
		return a
	}
	path := windows.UTF16ToString(buf[:size])
	for _, want := range []string{runKeyExe(), func() string { e, _ := ownExe(); return e }()} {
		if want != "" && size > 0 && strings.EqualFold(filepath.Clean(path), filepath.Clean(want)) {
			a.ours = true
			return a
		}
	}
	a.other = image
	return a
}

func (s SSHHost) AgentState() core.AgentState {
	var state core.AgentState
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE); err == nil {
		_, _, err = k.GetStringValue(runValue)
		state.AtLogon = err == nil
		k.Close()
	}
	if pipe, err := s.AgentPipe(); err == nil {
		answer := probePipe(pipe)
		state.Running, state.Other = answer.ours, answer.other
	}
	return state
}

// signHelperTime: how long a signature may wait for Windows Hello before the helper is ended.
const signHelperTime = 3 * time.Minute

// SignHelper runs this touchenv.exe as "ssh agent sign", with no console window.
func (SSHHost) SignHelper(request []byte) ([]byte, error) {
	exe, err := ownExe()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), signHelperTime)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "ssh", "agent", "sign")
	cmd.Stdin = bytes.NewReader(request)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW, HideWindow: true}
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("Windows Hello wasn't answered within %v", signHelperTime)
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return nil, fmt.Errorf("can't run touchenv ssh agent sign: %w", err)
	}
	return out.Bytes(), nil
}

func (s SSHHost) InstallAgent() error {
	exe, err := ownExe()
	if err != nil {
		return err
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
		if s.AgentState().Running {
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
//
// The window still flashes for a moment at logon. Starting the agent as `conhost.exe --headless ...` would avoid
// it, but --headless is conhost's private switch for ConPTY, not documented for starting programs, and security
// tools flag that exact command line as a way malware hides windows. A console-allocation policy in the exe's
// manifest (newer Windows 11 only) is the documented way; not done yet.
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
	for i := 0; i < 30 && probePipe(pipe).answered; i++ {
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
