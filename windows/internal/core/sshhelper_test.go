package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The agent never opens the store itself: each signature is one run of the sign helper, and the helper, which any
// program running as you can start, refuses on its own what the agent would refuse.
func TestSSHSignHelper(t *testing.T) {
	m := newSSHMachine(t, 0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m.must("ssh", "add", "DEPLOY", writeKey(t, priv, ""))
	pub, _ := ssh.NewPublicKey(priv.Public())
	sigData := append([]byte("SSHSIG"), sshString([]byte("git"))...)
	sigData = append(sigData, sshString(nil)...)

	// Through the agent: one helper run, one prompt. A requester whose name would break the prompt is shown with "?".
	m.ssh.procs[103] = ProcInfo{Parent: 104, Start: 10, Name: "evil\u202eexe.txt\nServer: github.com.exe"}
	prompts := len(m.h.prompts)
	sig, err := m.agentClient(100).Sign(pub, sigData)
	if err != nil || pub.Verify(sigData, sig) != nil {
		t.Fatal(err)
	}
	if m.ssh.helpers != 1 || len(m.h.prompts) != prompts+1 {
		t.Fatalf("helpers %d, prompts %d", m.ssh.helpers, len(m.h.prompts)-prompts)
	}
	if p := m.h.prompts[len(m.h.prompts)-1]; strings.Contains(p, "\n") || !strings.Contains(p, "evil?exe.txt?Server") {
		t.Fatalf("prompt %q", p)
	}

	if r := m.runHelper(nil); r.code != 1 || !strings.Contains(r.stderr, "started by touchenv's SSH agent") {
		t.Fatalf("empty request: %d %q", r.code, r.stderr)
	}
	good := sshSignRequest{Key: "DEPLOY", PublicKey: pub.Marshal(), Algorithm: ssh.KeyAlgoED25519, Data: sigData,
		Prompt: "touchenv: Allow a script to sign a git commit or tag with the SSH key DEPLOY?"}
	ask := func(req sshSignRequest) (sshSignReply, result) {
		t.Helper()
		data, _ := json.Marshal(req)
		r := m.runHelper(data)
		var reply sshSignReply
		if err := json.Unmarshal(r.raw, &reply); err != nil {
			t.Fatalf("no reply: %d %q %q", r.code, r.stdout, r.stderr)
		}
		return reply, r
	}
	if reply, r := ask(good); r.code != 0 || pub.Verify(sigData, &ssh.Signature{Format: reply.Format, Blob: reply.Blob}) != nil {
		t.Fatalf("%d %+v", r.code, reply)
	}

	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewPublicKey(otherPriv.Public())
	prompts = len(m.h.prompts)
	for what, c := range map[string]struct {
		change func(*sshSignRequest)
		want   string
	}{
		"arbitrary data": {func(r *sshSignRequest) { r.Data = []byte("please sign this") }, "neither an ssh login nor an SSHSIG"},
		"SHA-1":          {func(r *sshSignRequest) { r.Algorithm = ssh.KeyAlgoRSA }, "signatures are refused"},
		"another key":    {func(r *sshSignRequest) { r.PublicKey = other.Marshal() }, "DEPLOY isn't that key"},
		"no such key":    {func(r *sshSignRequest) { r.Key = "NOPE" }, "no SSH key named NOPE"},
		"bad name":       {func(r *sshSignRequest) { r.Key = "../x" }, "not a key name"},
		"other purpose": {func(r *sshSignRequest) {
			r.Prompt = "touchenv: Allow a script to log in as root with the SSH key DEPLOY?"
		}, "prompt isn't one"},
		"other key named": {func(r *sshSignRequest) { r.Prompt = strings.Replace(r.Prompt, "DEPLOY?", "WORK?", 1) }, "prompt isn't one"},
		"not touchenv's": {func(r *sshSignRequest) {
			r.Prompt = "Windows Update: Allow it to sign a git commit or tag with the SSH key DEPLOY?"
		}, "prompt isn't one"},
		"hidden characters": {func(r *sshSignRequest) { r.Prompt = strings.Replace(r.Prompt, "a script", "a\u202escript", 1) }, "prompt isn't one"},
		"empty line":        {func(r *sshSignRequest) { r.Prompt += "\n\nmore" }, "prompt isn't one"},
		"too many lines":    {func(r *sshSignRequest) { r.Prompt += strings.Repeat("\nmore", 4) }, "prompt isn't one"},
		"too long":          {func(r *sshSignRequest) { r.Prompt += "\n" + strings.Repeat("x", sshMaxPrompt) }, "prompt isn't one"},
	} {
		req := good
		c.change(&req)
		if reply, r := ask(req); r.code != 1 || !strings.Contains(reply.Error, c.want) {
			t.Errorf("%s: %d %q, want %q", what, r.code, reply.Error, c.want)
		}
	}
	if len(m.h.prompts) != prompts {
		t.Fatal("a refused request asked for Windows Hello")
	}

	m.h.deny = true
	if reply, r := ask(good); r.code != 1 || reply.Error != "not approved" {
		t.Fatalf("%d %+v", r.code, reply)
	}
}

// A request whose ssh went away while it waited its turn is dropped without a prompt.
func TestSSHClientGoneNotAsked(t *testing.T) {
	m := newSSHMachine(t, 0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m.must("ssh", "add", writeKey(t, priv, ""))
	pub, _ := ssh.NewPublicKey(priv.Public())
	sigData := append([]byte("SSHSIG"), sshString([]byte("file"))...)
	gone := true
	c := m.agentClientConn(100, func(c net.Conn) io.ReadWriteCloser { return goneConn{c, &gone} })
	prompts := len(m.h.prompts)
	if _, err := c.Sign(pub, sigData); err == nil {
		t.Fatal("signed for a client that had gone")
	}
	if len(m.h.prompts) != prompts || m.ssh.helpers != 0 {
		t.Fatal("asked for a client that had gone")
	}
	if !strings.Contains(m.must("ssh", "agent", "status").stdout, "ssh went away while the request waited its turn") {
		t.Fatal("not logged")
	}
	gone = false
	if _, err := c.Sign(pub, sigData); err != nil {
		t.Fatal(err)
	}
}

// run without --intent reads the process list once.
func TestWhoReadOncePerCommand(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "x")
	m.p.snapshots = 0
	m.must("run", "A", "--", "cmd")
	if m.p.snapshots != 1 {
		t.Fatalf("%d process snapshots", m.p.snapshots)
	}
}

// import decides skip or replace on the store as it is when it writes, not as it was before Windows Hello asked; and
// --replace of an SSH key by a plain secret removes the key's .pub.
func TestImportRecheckAndStalePub(t *testing.T) {
	old := newMachine(t, 0)
	old.set("NEW", "theirs")
	old.set("KEY", "plain now")
	fresh := newSSHMachine(t, 1)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	fresh.must("ssh", "add", "KEY", writeKey(t, priv, ""))
	pubFile := filepath.Join(fresh.p.dir, "ssh", "KEY.pub")
	exportTo := func() string {
		line := strings.Fields(strings.Split(fresh.must("import", "--begin").stdout, "\n")[2])[3]
		file := filepath.Join(t.TempDir(), "keys.tenv")
		os.WriteFile(file, old.must("export", "--to", line, "NEW", "KEY").raw, 0o600)
		return file
	}

	file := exportTo()
	fresh.h.onPrompt = func() { fresh.set("NEW", "mine, saved while Hello asked") }
	out := fresh.must("import", file).stdout
	if !strings.Contains(out, "skipped NEW: already here") || !strings.Contains(out, "skipped KEY") || !strings.Contains(out, "0 secrets") {
		t.Fatal(out)
	}
	if got := fresh.must("get", "NEW").stdout; got != "mine, saved while Hello asked" {
		t.Fatalf("NEW = %q", got)
	}

	fresh.must("import", "--replace", exportTo())
	if got := fresh.must("get", "KEY").stdout; got != "plain now" {
		t.Fatal(got)
	}
	if _, err := os.Stat(pubFile); err == nil {
		t.Fatal("the replaced SSH key's .pub was left behind")
	}
	if ls := fresh.must("ssh", "ls").stdout; strings.Contains(ls, "KEY") {
		t.Fatal(ls)
	}
}

// A .ssh\config that is a link stays one, and the file it points to keeps its permissions.
func TestSSHConfigLink(t *testing.T) {
	m := newSSHMachine(t, 0)
	cfg := filepath.Join(m.ssh.home, ".ssh", "config")
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	target := filepath.Join(t.TempDir(), "dotfiles-ssh-config")
	os.WriteFile(target, []byte("Host work\n"), 0o644)
	if err := os.Symlink(target, cfg); err != nil {
		t.Skip(err)
	}
	m.must("ssh", "agent", "install", "--config")
	if info, err := os.Lstat(cfg); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the link was replaced by a file")
	}
	data, _ := os.ReadFile(target)
	if !strings.Contains(string(data), "IdentityAgent") {
		t.Fatalf("target = %q", data)
	}
	if info, _ := os.Stat(target); runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 { // Windows has ACLs instead
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	m.must("ssh", "agent", "uninstall", "--config")
	if data, _ := os.ReadFile(target); string(data) != "Host work\n" {
		t.Fatalf("after uninstall: %q", data)
	}
}

func TestSSHAgentSomethingElseOnThePipe(t *testing.T) {
	m := newSSHMachine(t, 0)
	m.ssh.installed, m.ssh.other = true, `C:\Users\me\evil.exe (pid 42)`
	out := m.must("ssh", "agent", "status").stdout
	if !strings.Contains(out, `not touchenv's agent on \\.\pipe\touchenv-ssh-test: C:\Users\me\evil.exe (pid 42)`) {
		t.Fatal(out)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	out = m.must("ssh", "add", writeKey(t, priv, "")).stdout
	if !strings.Contains(out, `JetBrains IDEs, apps built on libgit2): setx SSH_AUTH_SOCK \\.\pipe\touchenv-ssh-test`) {
		t.Fatal(out)
	}
}
