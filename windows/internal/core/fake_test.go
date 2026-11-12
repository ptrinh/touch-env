package core

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHello stands in for the Windows Hello key: a software RSA key, a prompt log, and a yes/no answer.
type fakeHello struct {
	key      *rsa.PrivateKey
	created  bool
	deny     bool
	notReady error
	prompts  []string
	onPrompt func() // run once, at the next Decrypt (something else happening while Hello asks)
}

var sharedKeys struct {
	sync.Mutex
	keys []*rsa.PrivateKey
}

// testKey hands out RSA keys made once per test binary (2048-bit generation is slow).
func testKey(i int) *rsa.PrivateKey {
	sharedKeys.Lock()
	defer sharedKeys.Unlock()
	for len(sharedKeys.keys) <= i {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		sharedKeys.keys = append(sharedKeys.keys, k)
	}
	return sharedKeys.keys[i]
}

func (h *fakeHello) Ready() error { return h.notReady }

func (h *fakeHello) PublicKey(create bool) (*rsa.PublicKey, error) {
	if !h.created && !create {
		return nil, ErrNoKey
	}
	h.created = true
	return &h.key.PublicKey, nil
}

func (h *fakeHello) Decrypt(message string, ciphertext []byte) ([]byte, error) {
	h.prompts = append(h.prompts, message)
	if f := h.onPrompt; f != nil {
		h.onPrompt = nil
		f()
	}
	if h.deny {
		return nil, ErrCancelled
	}
	return rsa.DecryptPKCS1v15(nil, h.key, ciphertext)
}

func (h *fakeHello) Sign(message string, digest []byte) ([]byte, error) {
	h.prompts = append(h.prompts, message)
	if h.deny {
		return nil, ErrCancelled
	}
	return rsa.SignPKCS1v15(nil, h.key, crypto.SHA256, digest)
}

type ranCommand struct {
	argv  []string
	env   []string
	files map[string][]byte // :file contents as the command saw them
}

type fakePlatform struct {
	t         *testing.T
	dir       string
	ancestors []Process
	terminal  bool
	exitCode  int
	ran       []ranCommand
	runDirs   []string
	snapshots int // Ancestors calls
}

func (p *fakePlatform) Ancestors() []Process { p.snapshots++; return p.ancestors }
func (p *fakePlatform) DataDir() (string, error) {
	return p.dir, os.MkdirAll(p.dir, 0o700)
}
func (p *fakePlatform) WriteFilePrivate(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RewriteFile keeps the file's permissions, as the real one keeps its ACL.
func (p *fakePlatform) RewriteFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		p.t.Errorf("RewriteFile given a link: %s", path)
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func (p *fakePlatform) Lock(string) (func(), error) { return func() {}, nil }
func (p *fakePlatform) ReadSecret(stdin io.Reader, _ io.Writer) ([]byte, error) {
	return io.ReadAll(stdin)
}
func (p *fakePlatform) StdoutIsTerminal() bool { return p.terminal }
func (p *fakePlatform) Hostname() string       { return "test-pc" }
func (p *fakePlatform) NewRunDir() (string, func() error, error) {
	dir, err := os.MkdirTemp(p.t.TempDir(), "run-")
	if err != nil {
		return "", nil, err
	}
	p.runDirs = append(p.runDirs, dir)
	return dir, func() error { return os.RemoveAll(dir) }, nil
}
func (p *fakePlatform) SweepRunDirs() {}
func (p *fakePlatform) CommandLine(argv []string) (string, error) {
	if argv[0] == "unshowable.cmd" {
		return "", errors.New("unshowable.cmd: can't show this command faithfully")
	}
	return strings.Join(argv, " "), nil
}
func (p *fakePlatform) Run(argv []string, env []string) (int, error) {
	r := ranCommand{argv: argv, env: env, files: map[string][]byte{}}
	for _, kv := range env {
		if i := strings.Index(kv, "="); i > 0 {
			for _, dir := range p.runDirs {
				if strings.HasPrefix(kv[i+1:], dir) {
					data, err := os.ReadFile(kv[i+1:])
					if err != nil {
						p.t.Errorf("%s: %v", kv[:i], err)
					}
					r.files[kv[:i]] = data
				}
			}
		}
	}
	p.ran = append(p.ran, r)
	return p.exitCode, nil
}
func (p *fakePlatform) Environ() []string { return []string{"PATH=C:\\Windows", "Api_Key=old"} }

// machine is one PC: its store folder, its Hello key, and who runs touchenv.
type machine struct {
	t     *testing.T
	p     *fakePlatform
	h     *fakeHello
	now   time.Time
	stdin string
	svc   *fakeService // nil: no touchenv service
	ssh   *fakeSSHHost // nil: no SSH agent support
}

func newMachine(t *testing.T, keyIndex int) *machine {
	return &machine{t: t, p: &fakePlatform{t: t, dir: filepath.Join(t.TempDir(), "touchenv"),
		ancestors: []Process{{"bash.exe"}, {"WindowsTerminal.exe"}}},
		h: &fakeHello{key: testKey(keyIndex)}, now: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
}

func (m *machine) asAgent() *machine {
	m.p.ancestors = []Process{{"bash.exe"}, {"claude.exe"}, {"WindowsTerminal.exe"}}
	return m
}

type result struct {
	code           int
	stdout, stderr string
	raw            []byte
}

func (m *machine) run(args ...string) result {
	var out, errOut bytes.Buffer
	env := Env{Stdin: strings.NewReader(m.stdin), Stdout: &out, Stderr: &errOut, Platform: m.p,
		Hello: m.h, Now: func() time.Time { return m.now }}
	if m.svc != nil {
		env.Service = m.svc
	}
	if m.ssh != nil {
		env.SSH = m.ssh
	}
	code := Main(args, env)
	m.stdin = ""
	return result{code, out.String(), errOut.String(), out.Bytes()}
}

func (m *machine) must(args ...string) result {
	m.t.Helper()
	r := m.run(args...)
	if r.code != 0 {
		m.t.Fatalf("touchenv %v: exit %d, stderr %q", args, r.code, r.stderr)
	}
	return r
}

func (m *machine) set(name, value string) {
	m.t.Helper()
	m.stdin = value
	m.must("set", name)
}
