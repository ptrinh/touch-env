package winplat

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"golang.org/x/sys/windows"
)

// Platform implements core.Platform on Windows.
type Platform struct{}

func New() *Platform { return &Platform{} }

func (Platform) Environ() []string { return os.Environ() }

func (Platform) Hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "another PC"
	}
	return name
}

// MARK: who is asking

type procEntry struct {
	parent uint32
	name   string
}

func snapshot() map[uint32]procEntry {
	out := map[uint32]procEntry{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		out[e.ProcessID] = procEntry{e.ParentProcessID, windows.UTF16ToString(e.ExeFile[:])}
	}
	return out
}

// startTime is when a process started (0 if it can't be read): with the pid, it names one process even after the
// pid is reused.
func startTime(pid uint32) uint64 {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return 0
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
}

// Ancestors walks the parent chain. Windows keeps a parent's pid after it exits, and pids are reused, so the walk
// stops at a "parent" that started after its child.
func (Platform) Ancestors() []core.Process {
	procs := snapshot()
	pid := windows.GetCurrentProcessId()
	childStart := startTime(pid)
	var out []core.Process
	for i := 0; i < 32; i++ {
		parent := procs[pid].parent
		entry, ok := procs[parent]
		if parent == 0 || parent == 4 || !ok {
			break
		}
		start := startTime(parent)
		if start != 0 && childStart != 0 && start > childStart {
			break
		}
		out = append(out, core.Process{Name: entry.name})
		pid, childStart = parent, start
	}
	return out
}

// MARK: files

func userSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// privateAttributes: a protected DACL granting the user alone full control (inherited by what's inside a folder).
func privateAttributes(folder bool) (*windows.SecurityAttributes, error) {
	sid, err := userSID()
	if err != nil {
		return nil, err
	}
	ace := "(A;;FA;;;" + sid + ")"
	if folder {
		ace = "(A;OICI;FA;;;" + sid + ")"
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P" + ace)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func mkdirPrivate(path string) error {
	sa, err := privateAttributes(true)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(utf16z(path), sa)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil
	}
	return err
}

func (Platform) DataDir() (string, error) {
	base, err := os.UserCacheDir() // %LOCALAPPDATA%: this PC only, never roams
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "touchenv")
	return dir, mkdirPrivate(dir)
}

// WriteFilePrivate writes a new private file next to path and moves it into place, so a crash leaves the old one.
func (Platform) WriteFilePrivate(path string, data []byte) error {
	sa, err := privateAttributes(false)
	if err != nil {
		return err
	}
	var suffix [8]byte
	rand.Read(suffix[:])
	tmp := path + ".new-" + hex.EncodeToString(suffix[:])
	h, err := windows.CreateFile(utf16z(tmp), windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = windows.MoveFileEx(utf16z(tmp), utf16z(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

var procReplaceFile = kernel32.NewProc("ReplaceFileW")

const (
	replaceFileIgnoreMergeErrors = 0x2 // REPLACEFILE_IGNORE_MERGE_ERRORS
	replaceFileIgnoreACLErrors   = 0x4 // REPLACEFILE_IGNORE_ACL_ERRORS
)

// RewriteFile writes a new file next to path, private while it is written, and puts it in place with ReplaceFileW,
// which keeps the replaced file's DACL (and its other attributes): the user's file keeps whatever access they gave
// it. If the ACL can't be carried over, the file is left private, never more open. A missing file is made private.
func (p Platform) RewriteFile(path string, data []byte) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return p.WriteFilePrivate(path, data)
	}
	sa, err := privateAttributes(false)
	if err != nil {
		return err
	}
	var suffix [8]byte
	rand.Read(suffix[:])
	tmp := path + ".new-" + hex.EncodeToString(suffix[:])
	h, err := windows.CreateFile(utf16z(tmp), windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if r, _, e := procReplaceFile.Call(uintptr(unsafe.Pointer(utf16z(path))), uintptr(unsafe.Pointer(utf16z(tmp))), 0,
			replaceFileIgnoreMergeErrors|replaceFileIgnoreACLErrors, 0, 0); r == 0 {
			err = e
		}
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

func (Platform) Lock(path string) (func(), error) {
	sa, err := privateAttributes(false)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(utf16z(path), windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	var ol windows.Overlapped
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return func() {
		windows.UnlockFileEx(h, 0, 1, 0, &ol)
		windows.CloseHandle(h)
	}, nil
}

// MARK: console

func isConsole(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// isMsysPty: Git Bash (mintty) and Cygwin terminals are named pipes, not consoles.
func isMsysPty(f *os.File) bool {
	t, err := windows.GetFileType(windows.Handle(f.Fd()))
	if err != nil || t != windows.FILE_TYPE_PIPE {
		return false
	}
	buf := make([]byte, 4+2*windows.MAX_PATH)
	if windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileNameInfo, &buf[0], uint32(len(buf))) != nil {
		return false
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0])) / 2
	if int(n) > (len(buf)-4)/2 {
		return false
	}
	name := windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[4])), n))
	return (strings.Contains(name, "msys-") || strings.Contains(name, "cygwin-")) && strings.Contains(name, "-pty")
}

func (Platform) StdoutIsTerminal() bool { return isConsole(os.Stdout) || isMsysPty(os.Stdout) }

// ReadSecret: from a console, one line with echo off; from a pipe or file, everything.
func (Platform) ReadSecret(stdin io.Reader, stderr io.Writer) ([]byte, error) {
	f, ok := stdin.(*os.File)
	if !ok || !isConsole(f) {
		if ok && isMsysPty(f) {
			return nil, errors.New("Git Bash can't hide what you type: run it as winpty touchenv set NAME, or pipe the secret in")
		}
		return io.ReadAll(stdin)
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	windows.GetConsoleMode(h, &mode)
	fmt.Fprint(stderr, "Secret (not shown): ")
	windows.SetConsoleMode(h, (mode&^windows.ENABLE_ECHO_INPUT)|windows.ENABLE_LINE_INPUT|windows.ENABLE_PROCESSED_INPUT)
	line, err := bufio.NewReader(f).ReadString('\n')
	windows.SetConsoleMode(h, mode)
	fmt.Fprintln(stderr)
	if err != nil && line == "" {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// MARK: :file folders

func runBase() (string, error) {
	dir, err := Platform{}.DataDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(dir, "run")
	return base, mkdirPrivate(base)
}

// NewRunDir: %LOCALAPPDATA%\touchenv\run\<pid>-<start time>-<random>, private to the user. The name lets a later
// run tell whether the touchenv that made it is gone.
func (Platform) NewRunDir() (string, func() error, error) {
	base, err := runBase()
	if err != nil {
		return "", nil, err
	}
	var r [8]byte
	rand.Read(r[:])
	pid := windows.GetCurrentProcessId()
	dir := filepath.Join(base, fmt.Sprintf("%d-%d-%s", pid, startTime(pid), hex.EncodeToString(r[:])))
	sa, err := privateAttributes(true)
	if err != nil {
		return "", nil, err
	}
	if err := windows.CreateDirectory(utf16z(dir), sa); err != nil {
		return "", nil, err
	}
	return dir, func() error { return removeWithRetry(dir) }, nil
}

// removeWithRetry: a command's own children may still hold a file open for a moment after it exits.
func removeWithRetry(dir string) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = os.RemoveAll(dir); err == nil {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return err
}

// SweepRunDirs removes folders whose touchenv is gone (killed, or the console closed before it cleaned up).
func (Platform) SweepRunDirs() {
	base, err := runBase()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		parts := strings.SplitN(e.Name(), "-", 3)
		if len(parts) != 3 {
			continue
		}
		pid, err1 := strconv.ParseUint(parts[0], 10, 32)
		start, err2 := strconv.ParseUint(parts[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if now := startTime(uint32(pid)); now == 0 || now != start {
			os.RemoveAll(filepath.Join(base, e.Name()))
		}
	}
}

// MARK: running the command

// batchUnsafe: characters cmd.exe interprets when it runs a .bat or .cmd, which Windows does behind the scenes.
const batchUnsafe = "%^&|<>\"()!\r\n"

func (Platform) CommandLine(argv []string) (string, error) {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return "", fmt.Errorf("%s: not found (touchenv doesn't run programs from the current folder unless named as .\\%s)", argv[0], argv[0])
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".bat" || ext == ".cmd" {
		for _, a := range argv[1:] {
			if strings.ContainsAny(a, batchUnsafe) {
				return "", fmt.Errorf("%s is a batch file and its arguments have characters cmd.exe would act on, so the prompt "+
					"couldn't show exactly what runs. Run it as: touchenv run ... -- cmd /c \"...\"", argv[0])
			}
		}
	}
	return windows.ComposeCommandLine(append([]string{path}, argv[1:]...)), nil
}

func (Platform) Run(argv []string, env []string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Ctrl-C reaches the command through the console; touchenv keeps waiting so it can still clean up.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	err := cmd.Wait()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return 0, err
	}
	return cmd.ProcessState.ExitCode(), nil
}
