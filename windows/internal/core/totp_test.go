package core

import (
	"bytes"
	"crypto/x509"
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestTOTPArithmetic(t *testing.T) {
	secret := []byte("12345678901234567890")
	if got := Base32Encode(secret); got != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Error(got)
	}
	// RFC 6238's SHA-1 vectors, their last six digits.
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924",
		2000000000: "279037", 20000000000: "353130"} {
		if got := TOTPCode(secret, TOTPStep(time.Unix(unix, 0))); got != want {
			t.Errorf("at %d: %s, want %s", unix, got, want)
		}
	}
	want := "otpauth://totp/touchenv%3Aan@My%20PC?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=touchenv&algorithm=SHA1&digits=6&period=30"
	if got := TOTPURI(secret, "an@My PC"); got != want {
		t.Error(got)
	}
}

// codes is a machine with the service, two secrets and codes set up; seed is the key behind them.
type codes struct {
	*machine
	seed []byte
}

// keyFrom reads the key out of the window text of touchenv totp setup.
func keyFrom(t *testing.T, text string) []byte {
	t.Helper()
	i := strings.Index(text, "Key:")
	if i < 0 {
		t.Fatalf("no key in %q", text)
	}
	line := strings.SplitN(text[i+4:], "\n", 2)[0]
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.Join(strings.Fields(line), ""))
	if err != nil || len(seed) != 20 {
		t.Fatalf("key %q: %v", line, err)
	}
	return seed
}

// lateCode is stdin that answers with the code for the key the window showed.
type lateCode struct {
	c    *codes
	wrap func(code string) string
	r    *strings.Reader
}

func (l *lateCode) Read(p []byte) (int, error) {
	if l.r == nil {
		code := TOTPCode(l.c.seed, TOTPStep(l.c.now))
		if l.wrap != nil {
			code = l.wrap(code)
		}
		l.r = strings.NewReader(code + "\n")
	}
	return l.r.Read(p)
}

func (c *codes) setup(args ...string) result {
	c.svc.onShow = func(text string) { c.seed = keyFrom(c.t, text) }
	c.stdinLate = &lateCode{c: c}
	return c.run(append([]string{"totp"}, args...)...)
}

func newCodes(t *testing.T) *codes {
	t.Helper()
	c := &codes{machine: newMachine(t, 0)}
	c.withService(false)
	c.set("A", "sk-a")
	c.set("B", "sk-b")
	c.set("LOCAL", "sk-local")
	if r := c.setup("--max-for", "8h", "--max-uses", "20", "setup"); r.code != 0 {
		t.Fatalf("setup: %d %q", r.code, r.stderr)
	}
	c.must("totp", "allow", "A", "B")
	c.now = c.now.Add(time.Minute) // past the step of the code typed at setup
	return c
}

func (c *codes) code() string { return TOTPCode(c.seed, TOTPStep(c.now)) }

// afar: Claude Code asks, and Windows Hello can't be answered (Remote Desktop, a locked PC).
func (c *codes) afar() *codes {
	c.claude()
	c.svc.restart("bash.exe") // a new shell, started by Claude Code
	c.h.notReady = errTest("Windows Hello can't ask here")
	return c
}

func (c *codes) grant(code string, rest ...string) result {
	return c.run(append([]string{"grant", "--intent", "deploy", "--totp", code}, rest...)...)
}

func TestTOTPSetupShowsTheKeyInAWindowOnly(t *testing.T) {
	c := newCodes(t)
	if len(c.svc.shown) != 1 || !strings.Contains(c.svc.shown[0], "at most 8 hours and 20 times") {
		t.Fatalf("%q", c.svc.shown)
	}
	key := Base32Encode(c.seed)
	// Never on the terminal, in the Windows Hello prompt or in the store folder.
	r := c.setup("setup")
	if r.code != 0 || strings.Contains(r.stdout+r.stderr, Base32Encode(c.seed)) || strings.Contains(r.stdout+r.stderr, groupKey(Base32Encode(c.seed))) {
		t.Fatalf("%d %q %q", r.code, r.stdout, r.stderr)
	}
	if Base32Encode(c.seed) == key {
		t.Error("setup again kept the old key")
	}
	for _, p := range c.h.prompts {
		if strings.Contains(p, groupKey(Base32Encode(c.seed))) {
			t.Errorf("key in a Hello prompt: %q", p)
		}
	}
	if !strings.Contains(c.lastPrompt(), "The key set up before stops working") {
		t.Errorf("%q", c.lastPrompt())
	}
	// Setup again keeps what was allowed, and its defaults are 12 hours and 100 uses.
	st := c.must("totp", "status").stdout
	if !strings.Contains(st, "allowed from afar: A, B") || !strings.Contains(st, "at most 12 hours and 100 times") || !strings.Contains(st, "last used: never") {
		t.Errorf("%q", st)
	}
}

func TestTOTPSetupRefusals(t *testing.T) {
	m := newMachine(t, 0)
	c := &codes{machine: m}
	if r := m.run("totp", "setup"); r.code != 1 || !strings.Contains(r.stderr, "touchenv service install") {
		t.Fatalf("no service: %d %q", r.code, r.stderr)
	}
	m.withService(false)
	if r := c.setup("setup"); r.code != 1 || !strings.Contains(r.stderr, "save a secret first") {
		t.Fatalf("no Hello key: %d %q", r.code, r.stderr)
	}
	m.set("A", "sk-a")
	// An AI assistant can't run setup: refused before the key exists.
	m.asAgent()
	if r := c.setup("--intent", "x", "setup"); r.code != 1 || !strings.Contains(r.stderr, "Claude Code can't set codes up") || len(m.svc.shown) != 0 {
		t.Fatalf("agent: %d %q", r.code, r.stderr)
	}
	m.p.ancestors = []Process{{"bash.exe"}, {"WindowsTerminal.exe"}}
	before := m.prompts()
	// Cancelled at the window, a wrong code three times, Windows Hello refused: codes stay off.
	m.svc.cancelKey = true
	if r := c.setup("setup"); r.code != 1 || !strings.Contains(r.stderr, "cancelled; codes stay off") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.svc.cancelKey = false
	m.svc.onShow = func(text string) { c.seed = keyFrom(t, text) }
	m.stdin = "000000\n000001\n000002\n"
	if r := m.run("totp", "setup"); r.code != 1 || strings.Count(r.stderr, "That isn't the code") != 3 || !strings.Contains(r.stderr, "codes stay off") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if m.prompts() != before {
		t.Error("Windows Hello asked before a right code was typed")
	}
	m.h.deny = true
	if r := c.setup("setup"); r.code != 1 || !strings.Contains(r.stderr, "not approved; codes stay off") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.h.deny = false
	if st := m.must("totp", "status").stdout; !strings.Contains(st, "codes: off") {
		t.Errorf("%q", st)
	}
	if r := m.run("totp", "allow", "A"); r.code != 1 || !strings.Contains(r.stderr, "First: touchenv totp setup") || m.prompts() != before+1 {
		t.Fatalf("allow before setup: %d %q", r.code, r.stderr)
	}
	// A code typed with spaces, a little early: taken.
	c.svc.onShow = func(text string) { c.seed = keyFrom(t, text) }
	c.stdinLate = &lateCode{c: c, wrap: func(code string) string { return code[:3] + " " + code[3:] }}
	if r := c.run("totp", "setup"); r.code != 0 {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestTOTPGrantFromAfar(t *testing.T) {
	c := newCodes(t).afar()
	before := c.prompts()
	code := c.code()
	r := c.grant(code, "--for", "8h", "--uses", "2", "A", "B")
	if r.code != 0 || !strings.Contains(r.stdout, "Claude Code and what it runs can read A, B") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	// The grant is the ordinary one: run gets the secrets with no Windows Hello, and it counts uses.
	if r := c.run("run", "--intent", "deploy", "A", "B", "--", "deploy.exe"); r.code != 0 || envValue(c.p.ran[len(c.p.ran)-1], "A") != "sk-a" ||
		envValue(c.p.ran[len(c.p.ran)-1], "B") != "sk-b" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if c.prompts() != before {
		t.Errorf("Windows Hello was asked %d times", c.prompts()-before)
	}
	// The same code a second time, also for another grant.
	if r := c.grant(code, "--for", "1h", "--uses", "1", "A"); r.code != 1 || !strings.Contains(r.stderr, "already used") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	// Without the code a grant still needs Windows Hello, which can't ask here.
	if r := c.run("grant", "--intent", "deploy", "--for", "1h", "--uses", "1", "A"); r.code != 1 || !strings.Contains(r.stderr, "can't ask here") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if st := c.must("totp", "status").stdout; !strings.Contains(st, "last used: ") || strings.Contains(st, "never") {
		t.Errorf("%q", st)
	}
	// An agent must say why, as for any grant.
	c.now = c.now.Add(time.Minute)
	if r := c.run("grant", "--totp", c.code(), "--for", "1h", "--uses", "1", "A"); r.code != 2 || !strings.Contains(r.stderr, "must say why") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestTOTPRefusalsDoNotUseTheCodeUp(t *testing.T) {
	c := newCodes(t).afar()
	code := c.code()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--for", "1h", "--uses", "1", "A", "LOCAL"}, "LOCAL isn't: that grant needs Windows Hello"},
		{[]string{"--for", "1h", "--uses", "1", "NOPE"}, "no secret named NOPE"},
		{[]string{"--for", "9h", "--uses", "1", "A"}, "at most 8 hours and 20 times"},
		{[]string{"--for", "1h", "--uses", "21", "A"}, "at most 8 hours and 20 times"},
	} {
		if r := c.grant(code, tc.args...); r.code != 1 || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%v: %d %q", tc.args, r.code, r.stderr)
		}
	}
	if r := c.grant("12345", "--for", "1h", "--uses", "1", "A"); r.code != 1 || !strings.Contains(r.stderr, "six digits") {
		t.Errorf("%d %q", r.code, r.stderr)
	}
	// A codes file that can't be saved: the code can't be marked used, so nothing is approved.
	c.svc.vault.fail = true
	if r := c.grant(code, "--for", "1h", "--uses", "1", "A"); r.code != 1 || !strings.Contains(r.stderr, "nothing approved") {
		t.Errorf("%d %q", r.code, r.stderr)
	}
	c.svc.vault.fail = false
	if r := c.grant(code, "--for", "1h", "--uses", "1", "A"); r.code != 0 {
		t.Fatalf("the code still works after those: %d %q", r.code, r.stderr)
	}
	if st := c.must("totp", "status").stdout; strings.Contains(st, "wrong codes") {
		t.Errorf("%q", st)
	}
}

func TestTOTPWrongCodesLockUntilWindowsHello(t *testing.T) {
	c := newCodes(t).afar()
	wrong := "000000"
	if c.code() == wrong {
		wrong = "111111"
	}
	args := []string{"--for", "1h", "--uses", "1", "A"}
	if r := c.grant(wrong, args...); r.code != 1 || !strings.Contains(r.stderr, "wrong code") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	// The right code must wait too, and waiting uses nothing up.
	if r := c.grant(c.code(), args...); r.code != 1 || !strings.Contains(r.stderr, "too many wrong codes; try again in") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	for i := 2; i <= 5; i++ {
		c.now = c.now.Add(time.Minute)
		r := c.grant(wrong, args...)
		want := "wrong code"
		if i == 5 {
			want = "codes are locked after 5 wrong ones"
		}
		if r.code != 1 || !strings.Contains(r.stderr, want) {
			t.Fatalf("wrong code %d: %d %q", i, r.code, r.stderr)
		}
	}
	c.now = c.now.Add(24 * time.Hour)
	if r := c.grant(c.code(), args...); r.code != 1 || !strings.Contains(r.stderr, "touchenv totp unlock") {
		t.Fatalf("locked a day on: %d %q", r.code, r.stderr)
	}
	// A restart of the service doesn't clear the lock.
	c.svc.restartService()
	if st := c.must("totp", "status").stdout; !strings.Contains(st, "LOCKED after 5 wrong codes") {
		t.Errorf("%q", st)
	}
	// Unlocking needs Windows Hello: not from afar, and not by a program speaking to the service itself.
	if r := c.run("totp", "--intent", "x", "unlock"); r.code != 1 || !strings.Contains(r.stderr, "can't ask here") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	caller := Caller{User: c.svc.user, Session: c.svc.session, PID: touchenvPID}
	if err := c.svc.holder.TOTPUnlock(caller, &Request{At: c.now.Unix(), Sig: bytes.Repeat([]byte{1}, 256)}); err != errSignature {
		t.Fatalf("unsigned unlock: %v", err)
	}
	c.h.notReady = nil
	before := c.prompts()
	if r := c.run("totp", "--intent", "back at the PC", "unlock"); r.code != 0 || c.prompts() != before+1 ||
		!strings.Contains(c.lastPrompt(), "5 wrong codes were tried in a row") {
		t.Fatalf("%d %q %q", r.code, r.stderr, c.lastPrompt())
	}
	if r := c.grant(c.code(), args...); r.code != 0 {
		t.Fatalf("after unlock: %d %q", r.code, r.stderr)
	}
	if r := c.must("totp", "unlock"); !strings.Contains(r.stdout, "codes aren't locked") {
		t.Errorf("%q", r.stdout)
	}
}

func TestTOTPSurvivesARestartAndGrantsDoNot(t *testing.T) {
	c := newCodes(t).afar()
	if r := c.grant(c.code(), "--for", "8h", "--uses", "5", "A"); r.code != 0 {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	c.svc.restartService()
	if st := c.must("status").stdout; !strings.Contains(st, "nothing active") {
		t.Errorf("the grant survived a restart: %q", st)
	}
	// The code used before the restart is still used; the next one grants again, from the copies on disk.
	if r := c.grant(c.code(), "--for", "8h", "--uses", "5", "A"); r.code != 1 || !strings.Contains(r.stderr, "already used") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	c.now = c.now.Add(time.Minute)
	if r := c.grant(c.code(), "--for", "8h", "--uses", "5", "A", "B"); r.code != 0 {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if r := c.run("run", "--intent", "deploy", "B", "--", "deploy.exe"); r.code != 0 || envValue(c.p.ran[len(c.p.ran)-1], "B") != "sk-b" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	// The file holds the secrets (the real one is encrypted to the service's account by the vault).
	if !bytes.Contains(c.svc.vault.data, []byte("sk-a")) {
		t.Error("the copies aren't in the codes file")
	}
	// A damaged file: nothing is approved, and it says so.
	c.svc.vault.data = c.svc.vault.data[:len(c.svc.vault.data)-3]
	c.svc.restartService()
	c.now = c.now.Add(time.Minute)
	if r := c.grant(c.code(), "--for", "1h", "--uses", "1", "A"); r.code != 1 || !strings.Contains(r.stderr, "can't read or save its codes file") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestTOTPAllowDenySetRmOff(t *testing.T) {
	c := newCodes(t)
	if !strings.Contains(c.h.prompts[len(c.h.prompts)-1], "grant A, B from afar") || !strings.Contains(c.lastPrompt(), "outside Windows Hello") {
		t.Errorf("%q", c.lastPrompt())
	}
	// set of an allowed secret updates the copy; of another one it doesn't make one.
	c.stdin = "sk-a2"
	if r := c.must("set", "A"); !strings.Contains(r.stdout, "updated the copy of A") {
		t.Errorf("%q", r.stdout)
	}
	c.stdin = "sk-local2"
	if r := c.must("set", "LOCAL"); strings.Contains(r.stdout, "copy") {
		t.Errorf("%q", r.stdout)
	}
	c.afar()
	if r := c.grant(c.code(), "--for", "1h", "--uses", "3", "A"); r.code != 0 {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if r := c.run("run", "--intent", "deploy", "A", "--", "x.exe"); r.code != 0 || envValue(c.p.ran[len(c.p.ran)-1], "A") != "sk-a2" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	// deny needs no Windows Hello; the copy is gone from the file.
	if r := c.must("totp", "deny", "B", "NOPE"); !strings.Contains(r.stdout, "1 of B, NOPE") {
		t.Errorf("%q", r.stdout)
	}
	if bytes.Contains(c.svc.vault.data, []byte("sk-b")) {
		t.Error("B's copy is still in the codes file")
	}
	c.now = c.now.Add(time.Minute)
	if r := c.grant(c.code(), "--for", "1h", "--uses", "1", "B"); r.code != 1 || !strings.Contains(r.stderr, "B isn't") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	// rm deletes the copy too.
	c.h.notReady = nil
	if r := c.must("rm", "--intent", "x", "A"); !strings.Contains(r.stdout, "deleted the copy of A") {
		t.Errorf("%q", r.stdout)
	}
	if bytes.Contains(c.svc.vault.data, []byte("sk-a2")) {
		t.Error("A's copy is still in the codes file")
	}
	// An SSH key can't be allowed; usage errors.
	for _, args := range [][]string{{"totp"}, {"totp", "bogus"}, {"totp", "allow"}, {"totp", "allow", "bad-name"}, {"totp", "status", "X"},
		{"totp", "--max-for", "1h", "status"}, {"totp", "--max-uses", "3", "allow", "B"}} {
		if r := c.run(args...); r.code != 2 || !strings.Contains(r.stderr, "usage: touchenv totp setup") {
			t.Errorf("%v: %d %q", args, r.code, r.stderr)
		}
	}
	c.must("totp", "--intent", "x", "allow", "B")
	if r := c.must("totp", "off"); !strings.Contains(r.stdout, "codes are off") {
		t.Errorf("%q", r.stdout)
	}
	if len(c.svc.vault.data) != 0 {
		t.Errorf("the codes file still holds %d bytes", len(c.svc.vault.data))
	}
	if r := c.must("totp", "off"); !strings.Contains(r.stdout, "already off") {
		t.Errorf("%q", r.stdout)
	}
	if r := c.grant("123456", "--for", "1h", "--uses", "1", "B"); r.code != 1 || !strings.Contains(r.stderr, "codes aren't set up") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

// A program running as the user that speaks to the service itself can't put its own key behind the codes.
func TestTOTPSetupMustBeSignedByThePinnedHelloKey(t *testing.T) {
	c := newCodes(t)
	h := c.svc.holder
	caller := Caller{User: c.svc.user, Session: c.svc.session, PID: touchenvPID}
	evil := bytes.Repeat([]byte{7}, 20)
	at := c.now.Unix()
	req := func(key int, at int64) *Request {
		k := testKey(key)
		sig, _ := (&fakeHello{key: k}).Sign("", TOTPSignedDigest("setup", at, evil, 3600, 10))
		return &Request{Secrets: map[string][]byte{seedName: evil}, Seconds: 3600, Uses: 10, At: at,
			Pub: x509.MarshalPKCS1PublicKey(&k.PublicKey), Sig: sig}
	}
	if err := h.TOTPSetup(caller, req(1, at)); err != errOtherKey {
		t.Fatalf("another Hello key: %v", err)
	}
	// The pinned key's public half with a signature by another key, or no signature.
	r := req(1, at)
	r.Pub = x509.MarshalPKCS1PublicKey(&testKey(0).PublicKey)
	if err := h.TOTPSetup(caller, r); err != errSignature {
		t.Fatalf("forged: %v", err)
	}
	// Signed by the right key, but long ago, or not newer than the last signed request (a replay).
	if err := h.TOTPSetup(caller, req(0, at-3600)); err != errSignature {
		t.Fatalf("stale: %v", err)
	}
	good := req(0, at)
	if err := h.TOTPSetup(caller, good); err != nil {
		t.Fatalf("signed by the pinned key: %v", err)
	}
	if err := h.TOTPSetup(caller, good); err != errSignature {
		t.Fatalf("replayed: %v", err)
	}
	// Changed limits or key under the same signature.
	c.now = c.now.Add(time.Minute)
	r = req(0, c.now.Unix())
	r.Uses = 500
	if err := h.TOTPSetup(caller, r); err != errSignature {
		t.Fatalf("limits changed: %v", err)
	}
	// Another Windows user has codes of their own, and none of this user's copies.
	other := Caller{User: "S-1-5-21-1-1002", Session: c.svc.session, PID: touchenvPID}
	if st, err := h.TOTPState(other); err != nil || st.On {
		t.Fatalf("%v %v", st, err)
	}
	if _, err := h.TOTPGrant(other, []string{"A"}, time.Hour, 1, c.code()); err != errNoCodes {
		t.Fatalf("%v", err)
	}
	// Not touchenv.exe: refused like every other request.
	if _, err := h.TOTPState(Caller{User: c.svc.user, Session: c.svc.session, PID: 1}); err == nil {
		t.Error("a caller that isn't touchenv.exe was answered")
	}
}

func TestTOTPNoVaultAndOldService(t *testing.T) {
	c := &codes{machine: newMachine(t, 0)}
	c.withService(false)
	c.set("A", "sk-a")
	c.svc.holder.Vault = nil
	if r := c.setup("setup"); r.code != 1 || !strings.Contains(r.stderr, "nowhere to keep codes") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if len(c.svc.shown) != 0 {
		t.Error("the key was shown though it couldn't be kept")
	}
	if r := c.run("grant", "--totp"); r.code != 2 || !strings.Contains(r.stderr, "unknown option --totp") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if r := c.run("grant", "--totp", "123456", "A"); r.code != 2 || !strings.Contains(r.stderr, "usage: touchenv grant") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}
