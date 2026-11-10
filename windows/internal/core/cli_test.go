package core

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetGetOnePromptEach(t *testing.T) {
	m := newMachine(t, 0)
	m.set("API_KEY", "sk-test-1")
	if len(m.h.prompts) != 1 || !strings.Contains(m.h.prompts[0], "set up") {
		t.Fatalf("first set should ask once, to set up the store: %q", m.h.prompts)
	}
	m.set("OTHER", "two") // a new name: sealed to the public key, no prompt
	if len(m.h.prompts) != 1 {
		t.Fatalf("storing a new name asked for Hello: %q", m.h.prompts)
	}
	r := m.must("get", "API_KEY")
	if string(r.raw) != "sk-test-1" {
		t.Fatalf("get = %q", r.raw)
	}
	if len(m.h.prompts) != 2 || !strings.Contains(m.h.prompts[1], "Show Windows Terminal API_KEY in full?") {
		t.Fatalf("prompts %q", m.h.prompts)
	}
}

func TestStoredFileHoldsNoPlaintext(t *testing.T) {
	m := newMachine(t, 0)
	m.set("API_KEY", "plaintext-marker-123")
	data, err := os.ReadFile(filepath.Join(m.p.dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "plaintext-marker-123") {
		t.Fatal("secret stored in the clear")
	}
	info, _ := os.Stat(filepath.Join(m.p.dir, "store.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("store mode %v", info.Mode())
	}
}

func TestReplaceAsksAndCancelKeepsValue(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "one")
	m.h.deny = true
	m.stdin = "two"
	r := m.run("set", "A")
	if r.code != 1 || r.stderr != "touchenv: not approved\n" {
		t.Fatalf("got %d %q", r.code, r.stderr)
	}
	if !strings.Contains(m.h.prompts[len(m.h.prompts)-1], "Allow Windows Terminal to replace A?") {
		t.Fatalf("prompt %q", m.h.prompts)
	}
	m.h.deny = false
	if got := m.must("get", "A").stdout; got != "one" {
		t.Fatalf("value changed to %q", got)
	}
	m.set("A", "two")
	if got := m.must("get", "A").stdout; got != "two" {
		t.Fatalf("replace gave %q", got)
	}
}

func TestEmptyAndSyncAndBadNames(t *testing.T) {
	m := newMachine(t, 0)
	if r := m.run("set", "A"); r.code != 1 || r.stderr != "touchenv: empty secret, nothing stored\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if r := m.run("set", "--sync", "A"); r.code != 2 || !strings.Contains(r.stderr, "--sync isn't available on Windows") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if r := m.run("get", "MISSING"); r.code != 1 || r.stderr != "touchenv: no secret named MISSING\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if len(m.h.prompts) != 0 {
		t.Fatalf("asked for nothing: %q", m.h.prompts)
	}
}

func TestAgentsMustGiveIntent(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "v")
	m.asAgent()
	before := len(m.h.prompts)
	for _, args := range [][]string{{"get", "A"}, {"rm", "A"}, {"ls"}, {"run", "A", "--", "x"},
		{"import", "f.tenv"}} {
		r := m.run(args...)
		if r.code != 2 || !strings.HasPrefix(r.stderr, "touchenv: Claude Code must say why, in a few words: touchenv "+args[0]+" --intent \"<why>\"") {
			t.Fatalf("%v: %d %q", args, r.code, r.stderr)
		}
	}
	if len(m.h.prompts) != before {
		t.Fatal("asked before refusing")
	}
	r := m.must("get", "--intent", "  check\nthe key  ", "A")
	if r.stdout != "v" {
		t.Fatal(r.stdout)
	}
	last := m.h.prompts[len(m.h.prompts)-1]
	if !strings.Contains(last, "Show Claude Code A in full?") || !strings.Contains(last, "Intent: check the key") {
		t.Fatalf("prompt %q", last)
	}
	// Replacing needs a reason; storing a new name does not ask, so does not.
	m.stdin = "w"
	if r := m.run("set", "A"); r.code != 2 {
		t.Fatalf("replace without intent: %d %q", r.code, r.stderr)
	}
	m.set("B", "new")
}

func TestIntentTrimmedAndCut(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "v")
	m.must("get", "--intent", strings.Repeat("é", 300), "A")
	last := m.h.prompts[len(m.h.prompts)-1]
	if !strings.Contains(last, "Intent: "+strings.Repeat("é", 199)+"…\n") && !strings.HasSuffix(last, strings.Repeat("é", 199)+"…") {
		t.Fatalf("intent not cut at 200: %q", last)
	}
	if r := m.run("get", "--intent", "   ", "A"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	if strings.Contains(m.h.prompts[len(m.h.prompts)-1], "Intent:") {
		t.Fatal("blank intent shown")
	}
}

func TestRunOnePromptForAllSecrets(t *testing.T) {
	m := newMachine(t, 0)
	m.set("API_KEY", "sk-1")
	m.set("CERT", "-----BEGIN-----\x00binary")
	before := len(m.h.prompts)
	m.p.exitCode = 7
	r := m.run("run", "api_key", "--", "x") // names are case-sensitive, as on macOS
	if r.code != 1 || r.stderr != "touchenv: no secret named api_key\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	r = m.run("run", "API_KEY", "CERT:file", "--", "python", "report.py", "--out", "a b")
	if r.code != 7 {
		t.Fatalf("exit %d, want the command's 7; stderr %q", r.code, r.stderr)
	}
	if len(m.h.prompts) != before+1 {
		t.Fatalf("want one prompt, got %q", m.h.prompts[before:])
	}
	prompt := m.h.prompts[before]
	for _, want := range []string{"Allow Windows Terminal to read API_KEY, CERT?", "No reason given. Check the command:",
		"python report.py --out a b"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt %q lacks %q", prompt, want)
		}
	}
	ran := m.p.ran[0]
	env := strings.Join(ran.env, "\n")
	if !strings.Contains(env, "API_KEY=sk-1") || strings.Contains(env, "Api_Key=old") {
		t.Fatalf("env %q", ran.env)
	}
	if string(ran.files["CERT"]) != "-----BEGIN-----\x00binary" {
		t.Fatalf("file %q", ran.files)
	}
	for _, dir := range m.p.runDirs {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", dir)
		}
	}
}

func TestRunRefusals(t *testing.T) {
	m := newMachine(t, 0)
	m.set("BIN", "a\x00b")
	if r := m.run("run", "BIN", "--", "x"); r.code != 1 || r.stderr != "touchenv: BIN is not text; use BIN:file\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	before := len(m.h.prompts)
	if r := m.run("run", "BIN:file", "--", "unshowable.cmd"); r.code != 1 || !strings.Contains(r.stderr, "faithfully") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if len(m.h.prompts) != before {
		t.Fatal("asked for a command it can't show")
	}
	m.h.deny = true
	if r := m.run("run", "BIN:file", "--", "x"); r.code != 1 || r.stderr != "touchenv: not approved\n" || len(m.p.ran) != 0 {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestSwiftSplitQuirks(t *testing.T) {
	cases := map[string][]string{"A": {"A"}, "A:file": {"A", "file"}, "A:": {"A"}, ":file": {"file"},
		"A::file": {"A", ":file"}, "::": nil, "A:fil": {"A", "fil"}}
	for in, want := range cases {
		got := swiftSplit(in)
		if strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestLsAndRm(t *testing.T) {
	m := newMachine(t, 0)
	if r := m.must("ls"); r.stdout != "" {
		t.Fatal(r.stdout)
	}
	m.set("ZED", "1")
	m.set("ALPHA", "2")
	before := len(m.h.prompts)
	if r := m.must("ls"); r.stdout != "ALPHA\nZED\n" {
		t.Fatalf("%q", r.stdout)
	}
	if len(m.h.prompts) != before {
		t.Fatal("ls asked")
	}
	if r := m.must("rm", "ZED"); r.stdout != "deleted ZED\n" {
		t.Fatal(r.stdout)
	}
	if !strings.Contains(m.h.prompts[len(m.h.prompts)-1], "Allow Windows Terminal to delete ZED?") {
		t.Fatal(m.h.prompts)
	}
	if r := m.must("ls"); r.stdout != "ALPHA\n" {
		t.Fatalf("%q", r.stdout)
	}
	if r := m.run("lock"); r.stdout != "nothing to lock\n" {
		t.Fatal(r.stdout)
	}
}

func TestNotReadyFailsClosed(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "v")
	m.h.notReady = errNotReady("Windows Hello can't ask in a Remote Desktop session")
	r := m.run("get", "A")
	if r.code != 1 || r.stderr != "touchenv: Windows Hello can't ask in a Remote Desktop session\n" || r.stdout != "" {
		t.Fatalf("%d %q %q", r.code, r.stderr, r.stdout)
	}
	fresh := newMachine(t, 1)
	fresh.h.notReady = m.h.notReady
	fresh.stdin = "v"
	if r := fresh.run("set", "A"); r.code != 1 {
		t.Fatalf("set up without Hello: %d", r.code)
	}
}

type errNotReady string

func (e errNotReady) Error() string { return string(e) }

// A program running as the user swaps in a store key of its own, wrapped to the real Hello key, to read what is
// saved next. Without a Hello signature, touchenv refuses to seal anything to it.
func TestSwappedStoreKeyRefused(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "v")
	path := filepath.Join(m.p.dir, "store.json")
	var s storeFile
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &s)
	attacker, _ := p256().GenerateKey(rand.Reader)
	s.StoreKey = attacker.PublicKey().Bytes()
	s.Wrapped, _ = rsa.EncryptPKCS1v15(rand.Reader, &m.h.key.PublicKey, attacker.Bytes())
	data, _ = json.Marshal(s)
	os.WriteFile(path, data, 0o600)
	m.stdin = "next-secret"
	r := m.run("set", "B")
	if r.code != 1 || !strings.Contains(r.stderr, "was changed outside touchenv") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), `"B"`) {
		t.Fatal("sealed to the swapped key")
	}
}

func TestHelloKeyGoneOrReplaced(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "v")
	m.h.created = false
	if r := m.run("get", "A"); r.code != 1 || !strings.Contains(r.stderr, "Windows Hello key touchenv made is gone") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.h = &fakeHello{key: testKey(1), created: true}
	if r := m.run("get", "A"); r.code != 1 || !strings.Contains(r.stderr, "changed outside touchenv") || len(m.h.prompts) != 0 {
		t.Fatalf("%d %q %q", r.code, r.stderr, m.h.prompts)
	}
}

func TestExportImportBetweenPCs(t *testing.T) {
	old := newMachine(t, 0)
	old.set("A", "alpha")
	old.set("B", "beta")
	fresh := newMachine(t, 1)
	fresh.set("B", "mine")
	begin := fresh.must("import", "--begin").stdout
	line := ""
	for _, l := range strings.Split(begin, "\n") {
		if strings.Contains(l, "touchenv export --to") {
			line = strings.Fields(l)[3]
		}
	}
	recipient, err := ParseRecipient(line)
	if err != nil {
		t.Fatalf("%q: %v", begin, err)
	}
	code := CheckCode(recipient)
	if !strings.Contains(begin, "Approve there only if its prompt shows "+code+".") {
		t.Fatal(begin)
	}

	old.p.terminal = true
	if r := old.run("export", "--to", line); r.code != 2 || !strings.Contains(r.stderr, "send it to a file") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	old.p.terminal = false
	r := old.must("export", "--to", line)
	if !strings.Contains(old.h.prompts[len(old.h.prompts)-1], "to the machine showing "+code+"?") {
		t.Fatal(old.h.prompts)
	}
	if !strings.Contains(r.stderr, "exported 2 secrets (A, B) for the machine showing "+code) {
		t.Fatal(r.stderr)
	}
	file := filepath.Join(t.TempDir(), "keys.tenv")
	os.WriteFile(file, r.raw, 0o600)

	before := len(fresh.h.prompts)
	out := fresh.must("import", file).stdout
	if len(fresh.h.prompts) != before+1 {
		t.Fatalf("import should ask once: %q", fresh.h.prompts[before:])
	}
	for _, want := range []string{"stored A (5 bytes)", "skipped B: already here", "deleted " + file,
		"1 secret from test-pc."} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q lacks %q", out, want)
		}
	}
	if got := fresh.must("get", "A").stdout; got != "alpha" {
		t.Fatal(got)
	}
	if got := fresh.must("get", "B").stdout; got != "mine" {
		t.Fatal(got)
	}
	// The receiving key is spent.
	os.WriteFile(file, r.raw, 0o600)
	if r := fresh.run("import", file); r.code != 1 || !strings.Contains(r.stderr, "no import is waiting on this PC") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestImportReplaceWrongCodeAndExpiry(t *testing.T) {
	old := newMachine(t, 0)
	old.set("B", "theirs")
	fresh := newMachine(t, 1)
	fresh.set("B", "mine")
	exportTo := func(m *machine) string {
		line := strings.Fields(strings.Split(m.must("import", "--begin").stdout, "\n")[2])[3]
		r := old.must("export", "--to", line, "B")
		file := filepath.Join(t.TempDir(), "keys.tenv")
		os.WriteFile(file, r.raw, 0o600)
		return file
	}
	file := exportTo(fresh)
	fresh.must("import", "--begin") // a newer receiving key replaces the one the file was made for
	if r := fresh.run("import", file); r.code != 1 || !strings.Contains(r.stderr, "was made for the code") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	file = exportTo(fresh)
	fresh.now = fresh.now.Add(61 * time.Minute)
	if r := fresh.run("import", file); r.code != 1 || !strings.Contains(r.stderr, "expired (an hour)") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	file = exportTo(fresh)
	fresh.must("import", "--replace", file)
	if got := fresh.must("get", "B").stdout; got != "theirs" {
		t.Fatal(got)
	}
	if r := fresh.run("import", filepath.Join(t.TempDir(), "none")); r.code != 1 || !strings.Contains(r.stderr, "can't read") {
		t.Fatal(r.stderr)
	}
	junk := filepath.Join(t.TempDir(), "junk")
	os.WriteFile(junk, []byte("hello"), 0o600)
	if r := fresh.run("import", junk); r.code != 1 || !strings.Contains(r.stderr, "is not a file from touchenv export") {
		t.Fatal(r.stderr)
	}
}

func TestRequesterChain(t *testing.T) {
	cases := []struct {
		chain []string
		want  Requester
	}{
		{[]string{"bash.exe", "claude.exe", "WindowsTerminal.exe"}, Requester{"Claude Code", true}},
		{[]string{"pwsh.exe", "Code.exe"}, Requester{"VS Code", false}},
		{[]string{"cmd.exe", "conhost.exe", "codex.EXE"}, Requester{"Codex", true}},
		{[]string{"-bash"}, Requester{"a process", false}},
		{[]string{"python.exe", "claude.exe"}, Requester{"python", false}},
		{nil, Requester{"a process", false}},
	}
	for _, c := range cases {
		var chain []Process
		for _, n := range c.chain {
			chain = append(chain, Process{n})
		}
		if got := ClassifyChain(chain); got != c.want {
			t.Errorf("%v: got %+v want %+v", c.chain, got, c.want)
		}
	}
}
