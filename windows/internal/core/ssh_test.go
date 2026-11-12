package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type fakeSSHHost struct {
	home      string
	installed bool
	running   bool
	other     string
	procs     ProcTable
	m         *machine
	helpers   int // sign helpers run
}

func (h *fakeSSHHost) HomeDir() (string, error)   { return h.home, nil }
func (h *fakeSSHHost) AgentPipe() (string, error) { return `\\.\pipe\touchenv-ssh-test`, nil }
func (h *fakeSSHHost) InstallAgent() error        { h.installed, h.running = true, true; return nil }
func (h *fakeSSHHost) UninstallAgent() error      { h.installed, h.running = false, false; return nil }
func (h *fakeSSHHost) AgentState() AgentState {
	return AgentState{AtLogon: h.installed, Running: h.running, Other: h.other}
}
func (h *fakeSSHHost) Serve(func(io.ReadWriteCloser, uint32)) error {
	return nil
}
func (h *fakeSSHHost) Procs() ProcTable { return h.procs }

// SignHelper runs touchenv ssh agent sign as the real one does, in-process: same store and Hello, no SSH host.
func (h *fakeSSHHost) SignHelper(request []byte) ([]byte, error) {
	h.helpers++
	r := h.m.runHelper(request)
	return []byte(r.stdout), nil
}

func (m *machine) runHelper(request []byte) result {
	var out, errOut bytes.Buffer
	code := Main([]string{"ssh", "agent", "sign"}, Env{Stdin: bytes.NewReader(request), Stdout: &out, Stderr: &errOut,
		Platform: m.p, Hello: m.h, Now: func() time.Time { return m.now }})
	return result{code, out.String(), errOut.String(), out.Bytes()}
}

// Process 100 is ssh.exe, run by git.exe (101), run by bash (102) under claude.exe (103).
func newSSHMachine(t *testing.T, keyIndex int) *machine {
	m := newMachine(t, keyIndex)
	m.ssh = &fakeSSHHost{home: t.TempDir(), m: m, procs: ProcTable{
		100: {Parent: 101, Start: 40, Name: "ssh.exe"},
		101: {Parent: 102, Start: 30, Name: "git.exe"},
		102: {Parent: 103, Start: 20, Name: "bash.exe"},
		103: {Parent: 104, Start: 10, Name: "claude.exe"},
		104: {Parent: 0, Start: 5, Name: "WindowsTerminal.exe"},
	}}
	return m
}

func writeKey(t *testing.T, key any, passphrase string) string {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(key, "me@laptop")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "me@laptop", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// agentClient serves one connection from process pid with a fresh agent, as the pipe would.
func (m *machine) agentClient(pid uint32) agent.ExtendedAgent {
	return m.agentClientConn(pid, func(c net.Conn) io.ReadWriteCloser { return c })
}

// goneConn is a connection whose client has gone, as winplat's pipe reports it.
type goneConn struct {
	net.Conn
	gone *bool
}

func (g goneConn) ClientGone() bool { return *g.gone }

func (m *machine) agentClientConn(pid uint32, wrap func(net.Conn) io.ReadWriteCloser) agent.ExtendedAgent {
	env := Env{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard, Platform: m.p, Hello: m.h,
		SSH: m.ssh, Now: func() time.Time { return m.now }}
	c := &cmd{env: &env, p: m.p, h: m.h, ssh: m.ssh}
	a := &sshAgent{c: c}
	server, client := net.Pipe()
	go a.serve(wrap(server), pid)
	m.t.Cleanup(func() { client.Close() })
	return agent.NewClient(client)
}

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// loginData is what ssh asks the agent to sign for a publickey login (RFC 4252 section 7).
func loginData(session []byte, user string, key ssh.PublicKey) []byte {
	var d []byte
	d = append(d, sshString(session)...)
	d = append(d, 50)
	d = append(d, sshString([]byte(user))...)
	d = append(d, sshString([]byte("ssh-connection"))...)
	d = append(d, sshString([]byte("publickey"))...)
	d = append(d, 1)
	d = append(d, sshString([]byte(key.Type()))...)
	d = append(d, sshString(key.Marshal())...)
	return d
}

// bind sends session-bind@openssh.com as ssh does after accepting host's key for session.
func bind(t *testing.T, c agent.ExtendedAgent, host ssh.Signer, session []byte) {
	t.Helper()
	sig, err := host.Sign(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	var p []byte
	p = append(p, sshString(host.PublicKey().Marshal())...)
	p = append(p, sshString(session)...)
	p = append(p, sshString(ssh.Marshal(sig))...)
	p = append(p, 0)
	if _, err := c.Extension("session-bind@openssh.com", p); err != nil {
		t.Fatalf("session-bind: %v", err)
	}
}

func TestSSHName(t *testing.T) {
	for in, want := range map[string]string{`C:\Users\me\.ssh\id_ed25519`: "SSH_ID_ED25519", "work.pem": "SSH_WORK",
		"ssh_deploy-key.KEY": "SSH_DEPLOY_KEY", "/x/my key": "SSH_MY_KEY"} {
		if got := sshName(in); got != want {
			t.Errorf("sshName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSSHAddListSignRemove(t *testing.T) {
	m := newSSHMachine(t, 0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := writeKey(t, priv, "")
	pub, _ := ssh.NewPublicKey(priv.Public())

	out := m.must("ssh", "add", path).stdout
	for _, want := range []string{"stored SSH_ID_ED25519: ED25519 256 " + ssh.FingerprintSHA256(pub) + ", on this PC only",
		"touchenv ssh agent install --config", "del \"" + path + "\""} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q lacks %q", out, want)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("ssh add must leave the key file alone")
	}
	pubFile, _ := os.ReadFile(filepath.Join(m.p.dir, "ssh", "SSH_ID_ED25519.pub"))
	if !strings.HasPrefix(string(pubFile), "ssh-ed25519 ") || !strings.Contains(string(pubFile), " SSH_ID_ED25519") {
		t.Fatalf(".pub = %q", pubFile)
	}
	prompts := len(m.h.prompts) // setting up the store
	if r := m.run("ssh", "add", path); r.code != 1 || !strings.Contains(r.stderr, "already a secret named SSH_ID_ED25519") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if ls := m.must("ssh", "ls").stdout; !strings.Contains(ls, "SSH_ID_ED25519  ED25519 256  "+ssh.FingerprintSHA256(pub)) {
		t.Fatal(ls)
	}
	m.stdin = "x"
	if r := m.run("set", "SSH_ID_ED25519"); r.code != 1 || !strings.Contains(r.stderr, "is an SSH key") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}

	// known_hosts names the server; ssh binds the session to its key.
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(hostPriv)
	os.MkdirAll(filepath.Join(m.ssh.home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(m.ssh.home, ".ssh", "known_hosts"),
		[]byte("this line is not a known_hosts line\nother.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"+
			"github.com "+string(ssh.MarshalAuthorizedKey(host.PublicKey()))), 0o600)

	c := m.agentClient(100)
	keys, err := c.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "SSH_ID_ED25519" || !bytes.Equal(keys[0].Blob, pub.Marshal()) {
		t.Fatalf("List = %v, %v", keys, err)
	}
	if len(m.h.prompts) != prompts {
		t.Fatal("listing keys asked for Windows Hello")
	}
	session := []byte("session-1")
	bind(t, c, host, session)
	data := loginData(session, "git", pub)
	sig, err := c.Sign(pub, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatal("bad signature:", err)
	}
	prompt := m.h.prompts[len(m.h.prompts)-1]
	for _, want := range []string{"Allow Claude Code (through git, ssh) to log in as git with the SSH key SSH_ID_ED25519?",
		"Server: github.com, its key as in your known_hosts."} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt %q lacks %q", prompt, want)
		}
	}

	// A login for a session ssh didn't bind: refused without a prompt.
	before := len(m.h.prompts)
	if _, err := c.Sign(pub, loginData([]byte("session-2"), "git", pub)); err == nil {
		t.Fatal("signed a login for an unbound session")
	}
	// A user name that would break the prompt's lines.
	if _, err := c.Sign(pub, loginData(session, "git with the SSH key X?\nServer: github.com", pub)); err == nil {
		t.Fatal("signed a login whose user name has a line break")
	}
	// Something that is neither a login nor SSHSIG.
	if _, err := c.Sign(pub, []byte("please sign this")); err == nil {
		t.Fatal("signed arbitrary data")
	}
	if len(m.h.prompts) != before {
		t.Fatal("a refused request asked for Windows Hello")
	}
	if !strings.Contains(m.must("ssh", "agent", "status").stdout, "a login for a session this ssh didn't bind") {
		t.Fatal("refusal not logged")
	}

	// Git commit signing (SSHSIG), on a connection that bound nothing.
	sigData := append([]byte("SSHSIG"), sshString([]byte("git"))...)
	sigData = append(sigData, sshString(nil)...)
	if _, err := m.agentClient(100).Sign(pub, sigData); err != nil {
		t.Fatal(err)
	}
	if p := m.h.prompts[len(m.h.prompts)-1]; !strings.Contains(p, "to sign a git commit or tag with the SSH key SSH_ID_ED25519?") {
		t.Fatal(p)
	}

	// Windows Hello says no; nobody can answer.
	m.h.deny = true
	if _, err := c.Sign(pub, data); err == nil {
		t.Fatal("signed though Hello said no")
	}
	m.h.deny = false
	m.h.notReady = errTest("this is a Remote Desktop session")
	if _, err := c.Sign(pub, data); err == nil {
		t.Fatal("signed with nobody to ask")
	}
	m.h.notReady = nil

	// Clients can't change the agent.
	if err := c.RemoveAll(); err == nil {
		t.Fatal("RemoveAll worked")
	}
	if err := c.Add(agent.AddedKey{PrivateKey: priv}); err == nil {
		t.Fatal("Add worked")
	}

	m.asAgent()
	if r := m.run("ssh", "rm", "SSH_ID_ED25519"); r.code != 2 || !strings.Contains(r.stderr, "must say why") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.must("ssh", "rm", "--intent", "rotating it", "SSH_ID_ED25519")
	if p := m.h.prompts[len(m.h.prompts)-1]; !strings.Contains(p, "delete the SSH key SSH_ID_ED25519?") || !strings.Contains(p, "Intent: rotating it") {
		t.Fatal(p)
	}
	if _, err := os.Stat(filepath.Join(m.p.dir, "ssh", "SSH_ID_ED25519.pub")); err == nil {
		t.Fatal(".pub left behind")
	}
	if keys, _ := c.List(); len(keys) != 0 {
		t.Fatal("removed key still listed")
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

func TestSSHRSAAndPassphrase(t *testing.T) {
	m := newSSHMachine(t, 0)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := writeKey(t, priv, "correct horse")
	m.stdin = "wrong"
	if r := m.run("ssh", "add", "WORK", path); r.code != 1 || !strings.Contains(r.stderr, "wrong passphrase") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.stdin = "correct horse"
	if out := m.must("ssh", "add", "WORK", path).stdout; !strings.Contains(out, "stored WORK: RSA 2048") {
		t.Fatal(out)
	}
	pub, _ := ssh.NewPublicKey(&priv.PublicKey)
	c := m.agentClient(100)
	data := loginData([]byte("s"), "deploy", pub)
	if _, err := c.SignWithFlags(pub, data, 0); err == nil {
		t.Fatal("made an ssh-rsa (SHA-1) signature")
	}
	sig, err := c.SignWithFlags(pub, data, agent.SignatureFlagRsaSha256)
	if err != nil || sig.Format != ssh.KeyAlgoRSASHA256 || pub.Verify(data, sig) != nil {
		t.Fatalf("%v %v", sig, err)
	}
	if p := m.h.prompts[len(m.h.prompts)-1]; !strings.Contains(p, "Server: unknown") {
		t.Fatal(p)
	}
}

func TestSSHAddRefusals(t *testing.T) {
	m := newSSHMachine(t, 0)
	dir := t.TempDir()
	pubOnly := filepath.Join(dir, "id.pub")
	os.WriteFile(pubOnly, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me\n"), 0o600)
	garbage := filepath.Join(dir, "notakey")
	os.WriteFile(garbage, []byte("hello"), 0o600)
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"ssh", "add", pubOnly}, 1, "that is a public key"},
		{[]string{"ssh", "add", garbage}, 1, "not a private key ssh can use"},
		{[]string{"ssh", "add", dir}, 1, "can't read"},
		{[]string{"ssh", "add", "bad-name", pubOnly}, 2, "usage: touchenv ssh add [NAME] KEYFILE"},
		{[]string{"ssh", "rm", "NOPE"}, 1, "no SSH key named NOPE"},
	} {
		if r := m.run(c.args...); r.code != c.code || !strings.Contains(r.stderr, c.want) {
			t.Errorf("touchenv %v: %d %q, want %d %q", c.args, r.code, r.stderr, c.code, c.want)
		}
	}
	m.set("PLAIN", "x")
	if r := m.run("ssh", "rm", "PLAIN"); r.code != 1 || !strings.Contains(r.stderr, "isn't an SSH key from touchenv ssh add") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestSSHAgentConfig(t *testing.T) {
	m := newSSHMachine(t, 0)
	cfg := filepath.Join(m.ssh.home, ".ssh", "config")
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	original := "Host work\n    User me"
	os.WriteFile(cfg, []byte(original), 0o600)

	out := m.must("ssh", "agent", "install").stdout
	if !strings.Contains(out, "add these lines") || !strings.Contains(out, `IdentityAgent "//./pipe/touchenv-ssh-test"`) {
		t.Fatal(out)
	}
	if data, _ := os.ReadFile(cfg); string(data) != original {
		t.Fatal("install without --config changed the config")
	}
	m.must("ssh", "agent", "install", "--config")
	data, _ := os.ReadFile(cfg)
	want := original + "\n\n" + sshConfigBlock(`\\.\pipe\touchenv-ssh-test`)
	if string(data) != want {
		t.Fatalf("config =\n%s\nwant\n%s", data, want)
	}
	if backup, _ := os.ReadFile(cfg + ".touchenv-backup"); string(backup) != original {
		t.Fatalf("backup = %q", backup)
	}
	if out := m.must("ssh", "agent", "--config", "install").stdout; !strings.Contains(out, "already uses it") {
		t.Fatal(out)
	}
	status := m.must("ssh", "agent", "status").stdout
	if !strings.Contains(status, "running on") || !strings.Contains(status, cfg+" uses it") {
		t.Fatal(status)
	}
	if out := m.must("ssh", "agent", "uninstall").stdout; !strings.Contains(out, "still points ssh at it") {
		t.Fatal(out)
	}
	m.must("ssh", "agent", "uninstall", "--config")
	if data, _ := os.ReadFile(cfg); string(data) != original+"\n" {
		t.Fatalf("after uninstall: %q", data)
	}
}

func TestSSHKeyMovesWithExport(t *testing.T) {
	old := newSSHMachine(t, 0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	old.must("ssh", "add", "DEPLOY", writeKey(t, priv, ""))
	fresh := newSSHMachine(t, 1)
	fresh.set("OTHER", "x")
	line := ""
	for _, l := range strings.Split(fresh.must("import", "--begin").stdout, "\n") {
		if strings.Contains(l, "touchenv export --to") {
			line = strings.Fields(l)[3]
		}
	}
	file := filepath.Join(t.TempDir(), "keys.tenv")
	os.WriteFile(file, old.must("export", "--to", line).raw, 0o600)
	fresh.must("import", file)
	pub, _ := ssh.NewPublicKey(priv.Public())
	if ls := fresh.must("ssh", "ls").stdout; !strings.Contains(ls, "DEPLOY  ED25519 256  "+ssh.FingerprintSHA256(pub)) {
		t.Fatal(ls)
	}
}

// ssh -A: the connection is first bound to the host the agent is forwarded to; a login that host then asks for is
// labelled as coming from it.
func TestSSHForwardedRequestSaysSo(t *testing.T) {
	m := newSSHMachine(t, 0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m.must("ssh", "add", writeKey(t, priv, ""))
	pub, _ := ssh.NewPublicKey(priv.Public())
	_, hopPriv, _ := ed25519.GenerateKey(rand.Reader)
	hop, _ := ssh.NewSignerFromKey(hopPriv)
	_, targetPriv, _ := ed25519.GenerateKey(rand.Reader)
	target, _ := ssh.NewSignerFromKey(targetPriv)
	os.MkdirAll(filepath.Join(m.ssh.home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(m.ssh.home, ".ssh", "known_hosts"), []byte("bastion.example "+
		string(ssh.MarshalAuthorizedKey(hop.PublicKey()))+"github.com "+string(ssh.MarshalAuthorizedKey(target.PublicKey()))), 0o600)

	c := m.agentClient(100)
	sig, _ := hop.Sign(rand.Reader, []byte("hop-session"))
	var p []byte
	p = append(p, sshString(hop.PublicKey().Marshal())...)
	p = append(p, sshString([]byte("hop-session"))...)
	p = append(p, sshString(ssh.Marshal(sig))...)
	p = append(p, 1) // forwarding
	if _, err := c.Extension("session-bind@openssh.com", p); err != nil {
		t.Fatal(err)
	}
	bind(t, c, target, []byte("remote-session"))
	if _, err := c.Sign(pub, loginData([]byte("remote-session"), "git", pub)); err != nil {
		t.Fatal(err)
	}
	prompt := m.h.prompts[len(m.h.prompts)-1]
	for _, want := range []string{"Server: github.com, its key as in your known_hosts.",
		"Asked through agent forwarding (ssh -A) by bastion.example, its key as in your known_hosts, not by a program on this PC."} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt %q lacks %q", prompt, want)
		}
	}
}

func TestSSHConfigEdgeCases(t *testing.T) {
	m := newSSHMachine(t, 0)
	cfg := filepath.Join(m.ssh.home, ".ssh", "config")
	os.MkdirAll(filepath.Dir(cfg), 0o700)

	// Windows line endings are kept, and the first backup is never overwritten.
	original := "Host work\r\n    User me\r\n"
	os.WriteFile(cfg, []byte(original), 0o600)
	m.must("ssh", "agent", "install", "--config")
	data, _ := os.ReadFile(cfg)
	if strings.Contains(strings.ReplaceAll(string(data), "\r\n", ""), "\n") || !strings.Contains(string(data), "IdentityAgent \"//./pipe/touchenv-ssh-test\"\r\n") {
		t.Fatalf("config = %q", data)
	}
	if !strings.Contains(m.must("ssh", "agent", "status").stdout, cfg+" uses it") {
		t.Fatal("status doesn't see a CRLF block")
	}
	m.must("ssh", "agent", "uninstall", "--config")
	if data, _ := os.ReadFile(cfg); string(data) != original {
		t.Fatalf("after uninstall: %q", data)
	}
	m.must("ssh", "agent", "install", "--config")
	if backup, _ := os.ReadFile(cfg + ".touchenv-backup"); string(backup) != original {
		t.Fatalf("backup = %q", backup)
	}

	// A begin marker with no end marker: nothing is changed.
	broken := "Host a\n" + sshConfigBegin + "\nHost *\n    User keepme\n"
	os.WriteFile(cfg, []byte(broken), 0o600)
	for _, args := range [][]string{{"ssh", "agent", "install", "--config"}, {"ssh", "agent", "uninstall", "--config"}} {
		if r := m.run(args...); r.code != 1 || !strings.Contains(r.stderr, "no end marker") {
			t.Fatalf("%v: %d %q", args, r.code, r.stderr)
		}
		if data, _ := os.ReadFile(cfg); string(data) != broken {
			t.Fatalf("%v changed a config it couldn't read safely: %q", args, data)
		}
	}
}
