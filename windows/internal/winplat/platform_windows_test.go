package winplat

// Runs on Windows (CI: windows-latest, windows-11-arm). Nothing here needs Windows Hello.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func useTempAppData(t *testing.T) string {
	dir := t.TempDir()
	t.Setenv("LocalAppData", dir) // os.UserCacheDir reads it: keeps tests out of the real %LOCALAPPDATA%
	return dir
}

func sddl(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// only is the DACL that grants sid alone, written the way Windows prints it: it
// abbreviates well-known accounts (the built-in Administrator on CI runners is "LA").
func only(t *testing.T, flags, sid string) string {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// The store folder, the store file and :file folders grant the user alone, with inheritance cut.
func TestPrivateACLs(t *testing.T) {
	base := useTempAppData(t)
	sid, _ := userSID()
	p := New()
	dir, err := p.DataDir()
	if err != nil || dir != filepath.Join(base, "touchenv") {
		t.Fatalf("%q %v", dir, err)
	}
	if got := sddl(t, dir); got != only(t, "OICI", sid) {
		t.Fatalf("folder DACL %s", got)
	}
	file := filepath.Join(dir, "store.json")
	if err := p.WriteFilePrivate(file, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteFilePrivate(file, []byte("two")); err != nil { // replace in place
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(file); string(data) != "two" {
		t.Fatalf("%q", data)
	}
	if got := sddl(t, file); got != only(t, "", sid) {
		t.Fatalf("file DACL %s", got)
	}
	leftovers, _ := filepath.Glob(file + ".new-*")
	if len(leftovers) != 0 {
		t.Fatal(leftovers)
	}
	unlock, err := p.Lock(file + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

func TestRunDirCleanupAndSweep(t *testing.T) {
	useTempAppData(t)
	p := New()
	dir, cleanup, err := p.NewRunDir()
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := userSID()
	if got := sddl(t, dir); got != only(t, "OICI", sid) {
		t.Fatalf("run folder DACL %s", got)
	}
	if err := p.WriteFilePrivate(filepath.Join(dir, "KEY"), []byte("secret")); err != nil {
		t.Fatal(err)
	}
	// A folder from a touchenv that is gone (no such pid) and one from this live process.
	base := filepath.Dir(dir)
	stale := filepath.Join(base, "4294967290-1-dead")
	os.Mkdir(stale, 0o700)
	p.SweepRunDirs()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale folder kept")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("live folder swept")
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("not removed")
	}
}

func TestCommandLineAndRun(t *testing.T) {
	p := New()
	line, err := p.CommandLine([]string{"cmd", "/c", "exit 3"})
	if err != nil || !strings.HasSuffix(strings.ToLower(line), `cmd.exe /c "exit 3"`) {
		t.Fatalf("%q %v", line, err)
	}
	code, err := p.Run([]string{"cmd", "/c", "exit 3"}, os.Environ())
	if err != nil || code != 3 {
		t.Fatalf("exit %d %v", code, err)
	}
	if _, err := p.CommandLine([]string{"no-such-program-touchenv"}); err == nil {
		t.Fatal("found a missing program")
	}
	bat := filepath.Join(t.TempDir(), "x.cmd")
	os.WriteFile(bat, []byte("@echo %1\r\n"), 0o600)
	if _, err := p.CommandLine([]string{bat, "a&calc"}); err == nil || !strings.Contains(err.Error(), "batch file") {
		t.Fatalf("batch with & accepted: %v", err)
	}
	if _, err := p.CommandLine([]string{bat, "plain"}); err != nil {
		t.Fatal(err)
	}
}

func TestEnvReachesCommand(t *testing.T) {
	p := New()
	code, err := p.Run([]string{"cmd", "/c", "exit", "%TOUCHENV_TEST%"}, append(os.Environ(), "TOUCHENV_TEST=4"))
	if err != nil || code != 4 {
		t.Fatalf("exit %d %v", code, err)
	}
}

func TestAncestorsSeesParent(t *testing.T) {
	chain := New().Ancestors()
	if len(chain) == 0 || chain[0].Name == "" {
		t.Fatalf("%v", chain)
	}
}
