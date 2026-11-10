package core

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func envValue(r ranCommand, name string) string {
	for _, kv := range r.env {
		if strings.HasPrefix(kv, name+"=") {
			return kv[len(name)+1:]
		}
	}
	return ""
}

func (m *machine) prompts() int { return len(m.h.prompts) }

func (m *machine) lastPrompt() string { return m.h.prompts[len(m.h.prompts)-1] }

// claudeChain: a command Claude Code runs through bash, inside Windows Terminal.
func (m *machine) claude(extra ...string) *machine {
	var chain []Process
	for _, e := range extra {
		chain = append(chain, Process{e})
	}
	m.p.ancestors = append(chain, Process{"bash.exe"}, Process{"claude.exe"}, Process{"WindowsTerminal.exe"})
	return m
}

func TestParseLengthLikeSwift(t *testing.T) {
	good := map[string]time.Duration{"8h": 8 * time.Hour, "30m": 30 * time.Minute, "1h30m": 90 * time.Minute,
		"30m1h": 90 * time.Minute, "0h1m": time.Minute, "24h": 24 * time.Hour, "00001h": time.Hour, "99999m": 99999 * time.Minute}
	for text, want := range good {
		if got, ok := ParseLength(text); !ok || got != want {
			t.Errorf("ParseLength(%q) = %v %v, want %v", text, got, ok, want)
		}
	}
	for _, text := range []string{"", "0h", "0m", "8", "h", "8x", "8H", "1h1h", "8h ", " 8h", "-8h", "+8h", "100000m", "1.5h", "8hm", "٣h"} {
		if got, ok := ParseLength(text); ok {
			t.Errorf("ParseLength(%q) = %v, want refused", text, got)
		}
	}
	if s := SpokenLength(90 * time.Minute); s != "1 hour 30 minutes" {
		t.Error(s)
	}
	if s := SpokenLength(8 * time.Hour); s != "8 hours" {
		t.Error(s)
	}
	if s := SpokenLength(time.Minute); s != "1 minute" {
		t.Error(s)
	}
	if Clock(299) != "4:59" || Clock(28799) != "7:59:59" || Clock(3600) != "1:00:00" {
		t.Error(Clock(299), Clock(28799))
	}
	if Times(1) != "1 time" || Times(20) != "20 times" {
		t.Error("Times")
	}
}

func TestGrantNeedsTheService(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "sk-1")
	before := m.prompts()
	r := m.run("grant", "--for", "8h", "--uses", "3", "A")
	if r.code != 1 || !strings.Contains(r.stderr, "touchenv service install") || !strings.Contains(r.stderr, "Nothing was allowed") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.withService(false).down = true
	if r := m.run("grant", "--for", "8h", "--uses", "3", "A"); r.code != 1 || !strings.Contains(r.stderr, "isn't installed or isn't running") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.svc.down, m.svc.impostor = false, true
	if r := m.run("grant", "--for", "8h", "--uses", "3", "A"); r.code != 1 || !strings.Contains(r.stderr, "something other than the touchenv service") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if m.prompts() != before {
		t.Fatal("asked Windows Hello for a grant that couldn't be kept")
	}
	// Without a service, run asks every time, as before.
	m.svc = nil
	m.must("run", "A", "--", "x")
	m.must("run", "A", "--", "x")
	if m.prompts() != before+2 {
		t.Fatalf("prompts %d", m.prompts()-before)
	}
}

func TestGrantCoversRequesterAndBelowForUses(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "sk-1")
	m.set("B", "sk-2")
	f := m.withService(false)
	m.claude()
	if r := m.run("grant", "--for", "8h", "--uses", "3", "A"); r.code != 2 || !strings.Contains(r.stderr, `touchenv grant --intent "<why>" --for 8h --uses 3 A`) {
		t.Fatalf("agent without intent: %d %q", r.code, r.stderr)
	}
	before := m.prompts()
	r := m.must("grant", "--intent", "nightly deploy", "--for", "8h", "--uses", "3", "A", "A")
	if m.prompts() != before+1 {
		t.Fatal("grant should ask exactly once")
	}
	p := m.lastPrompt()
	for _, want := range []string{"Allow Claude Code and what it runs to read A without asking, for 8 hours, up to 3 times?",
		"stays on while the PC is locked", "any program running as you can get A too", "Intent: nightly deploy"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt lacks %q:\n%s", want, p)
		}
	}
	if !strings.HasPrefix(r.stdout, "Claude Code and what it runs can read A with touchenv run without asking: 3 times, until ") ||
		!strings.Contains(r.stdout, "touchenv lock ends it.") || f.trays != 1 {
		t.Fatalf("%q trays %d", r.stdout, f.trays)
	}
	// A process Claude Code started, and that process's own children: no prompt, one use each.
	before = m.prompts()
	m.claude("python.exe")
	m.must("run", "--intent", "step 1", "A", "--", "deploy")
	m.claude("node.exe", "python.exe")
	m.must("run", "--intent", "step 2", "A:file", "--", "deploy")
	if m.prompts() != before {
		t.Fatalf("a granted run asked: %q", m.h.prompts[before:])
	}
	if got := envValue(m.p.ran[0], "A"); got != "sk-1" {
		t.Fatalf("A = %q", got)
	}
	if got := string(m.p.ran[1].files["A"]); got != "sk-1" {
		t.Fatalf(":file A = %q", got)
	}
	st := m.must("status").stdout
	if !strings.Contains(st, "Claude Code and what it runs can read A without asking: 1 time, 8:00:00 left") ||
		!strings.Contains(st, "python read A (touchenv pid 5000)  Intent: step 1") || !strings.Contains(st, "node read A") {
		t.Fatalf("status:\n%s", st)
	}
	// A secret the grant doesn't cover: asks, and that run doesn't use up the grant.
	m.must("run", "--intent", "x", "A", "B", "--", "deploy")
	if m.prompts() != before+1 {
		t.Fatal("A and B should ask: B isn't granted")
	}
	m.must("run", "--intent", "step 3", "A", "--", "deploy")
	if m.prompts() != before+1 {
		t.Fatal("third use asked")
	}
	m.must("run", "--intent", "step 4", "A", "--", "deploy")
	if m.prompts() != before+2 {
		t.Fatal("a fourth use should ask: 3 were granted")
	}
	if st := m.must("status").stdout; !strings.Contains(st, "nothing active") {
		t.Fatalf("status after the last use:\n%s", st)
	}
}

func TestGrantDoesNotCoverOthers(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "sk-1")
	f := m.withService(false)
	m.claude()
	m.must("grant", "--intent", "i", "--for", "1h", "--uses", "50", "A")
	before := m.prompts()

	m.p.ancestors = []Process{{"pwsh.exe"}, {"Code.exe"}} // another app
	m.must("run", "A", "--", "x")
	m.claude()
	m.must("get", "--intent", "i", "A") // get never uses a grant
	f.user = "S-1-5-21-1-1002"          // another user
	m.must("run", "--intent", "i", "A", "--", "x")
	f.user, f.session = "S-1-5-21-1-1001", 2 // the same user in another session
	m.must("run", "--intent", "i", "A", "--", "x")
	f.session = 1
	if m.prompts() != before+4 {
		t.Fatalf("want 4 prompts, got %d", m.prompts()-before)
	}
	m.must("run", "--intent", "i", "A", "--", "x")
	if m.prompts() != before+4 {
		t.Fatal("the grant itself stopped working")
	}
	// The requester quits and a new Claude Code starts: the grant ended with the old one.
	f.restart("claude.exe")
	m.must("run", "--intent", "i", "A", "--", "x")
	if m.prompts() != before+5 {
		t.Fatal("a grant outlived its requester")
	}
}

func TestGrantExpiresLocksAndLogoff(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "sk-1")
	f := m.withService(false)
	m.claude()
	m.must("grant", "--intent", "i", "--for", "30m", "--uses", "100", "A")
	before := m.prompts()
	m.now = m.now.Add(29 * time.Minute)
	m.must("run", "--intent", "i", "A", "--", "x")
	m.now = m.now.Add(time.Minute)
	m.must("run", "--intent", "i", "A", "--", "x")
	if m.prompts() != before+1 {
		t.Fatalf("expiry: %d prompts", m.prompts()-before)
	}

	m.must("grant", "--intent", "i", "--for", "1h", "--uses", "100", "A")
	f.holder.SessionLocked(1) // screen locked: a grant goes on
	before = m.prompts()
	m.must("run", "--intent", "i", "A", "--", "x")
	if r := m.must("lock"); r.stdout != "locked: every approval and grant ended\n" {
		t.Fatal(r.stdout)
	}
	m.must("run", "--intent", "i", "A", "--", "x")
	if m.prompts() != before+1 {
		t.Fatalf("lock: %d prompts", m.prompts()-before)
	}

	m.must("grant", "--intent", "i", "--for", "1h", "--uses", "100", "A")
	f.holder.SessionEnded(1) // logoff
	before = m.prompts()
	m.must("run", "--intent", "i", "A", "--", "x")
	if m.prompts() != before+1 {
		t.Fatal("a grant outlived logoff")
	}

	m.svc = nil
	if r := m.must("lock"); r.stdout != "nothing to lock\n" {
		t.Fatal(r.stdout)
	}
	if r := m.must("status"); !strings.Contains(r.stdout, "no touchenv service") {
		t.Fatal(r.stdout)
	}
}

func TestGrantRefusals(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "sk-1")
	m.withService(false)
	m.p.ancestors = nil
	if r := m.run("grant", "--for", "1h", "--uses", "1", "A"); r.code != 1 || r.stderr != "touchenv: can't tell which app is asking, so there is nothing to grant to\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.p.ancestors = []Process{{"bash.exe"}, {"WindowsTerminal.exe"}}
	if r := m.run("grant", "--for", "1h", "--uses", "1", "NOPE"); r.code != 1 || r.stderr != "touchenv: no secret named NOPE\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	m.h.deny = true
	if r := m.run("grant", "--for", "1h", "--uses", "1", "A"); r.code != 1 || r.stderr != "touchenv: not approved\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if st := m.must("status").stdout; !strings.Contains(st, "nothing active") {
		t.Fatal("a cancelled grant was kept")
	}
}

func TestFiveMinutesOnlyWhenOfferedAndChosen(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "sk-1")
	f := m.withService(false)
	m.claude()
	m.must("run", "--intent", "i", "A", "--", "x")
	if len(f.asked) != 0 {
		t.Fatal("asked about 5 minutes though the service doesn't offer them")
	}
	if r := m.run("run", "--keep", "A", "--", "x"); r.code != 2 || !strings.Contains(r.stderr, "unknown option --keep") {
		t.Fatal("there must be no flag for it")
	}

	f.holder.OfferKeep = true
	f.keep.keep = false // "No: just this once"
	before := m.prompts()
	m.must("run", "--intent", "build", "A", "--", "x")
	if len(f.asked) != 1 || !strings.Contains(f.asked[0], "Claude Code wants to read A.\nIntent: build") ||
		!strings.Contains(f.asked[0], "and so could any other program running as you") {
		t.Fatalf("question %q", f.asked)
	}
	if strings.Contains(m.lastPrompt(), "5 minutes") {
		t.Fatal("Hello prompt mentions 5 minutes though No was chosen")
	}
	m.must("run", "--intent", "build", "A", "--", "x")
	if m.prompts() != before+2 {
		t.Fatal("No kept an approval")
	}

	f.keep.keep = true
	m.must("run", "--intent", "build", "A", "--", "x")
	if p := m.lastPrompt(); !strings.Contains(p, "Allow Claude Code to read A, and again without asking for the next 5 minutes? "+
		"For those 5 minutes any program running as you can get A too.") {
		t.Fatalf("prompt %q", p)
	}
	before = m.prompts()
	m.claude("cmd.exe") // another shell under the same Claude Code: the same requester
	m.must("run", "--intent", "build", "A", "--", "x")
	if m.prompts() != before {
		t.Fatal("the 5-minute approval wasn't used")
	}
	m.claude("python.exe") // a program Claude Code runs is a requester of its own: not covered (as on a Mac)
	m.must("run", "--intent", "build", "A", "--", "x")
	m.claude()
	m.now = m.now.Add(ApprovalLength)
	m.must("run", "--intent", "build", "A", "--", "x")
	if m.prompts() != before+2 {
		t.Fatalf("prompts %d", m.prompts()-before)
	}

	// Locking the screen ends a 5-minute approval.
	m.must("run", "--intent", "build", "A", "--", "x") // keeps again
	f.holder.SessionLocked(1)
	before = m.prompts()
	m.must("run", "--intent", "build", "A", "--", "x")
	if m.prompts() != before+1 {
		t.Fatal("approval survived the screen lock")
	}

	// Cancel in touchenv's question: nothing runs, Windows Hello isn't asked.
	m.must("lock")
	f.keep.proceed = false
	before, ran := m.prompts(), len(m.p.ran)
	if r := m.run("run", "--intent", "build", "A", "--", "x"); r.code != 1 || r.stderr != "touchenv: not approved\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	if m.prompts() != before || len(m.p.ran) != ran {
		t.Fatal("cancel still asked or ran")
	}

	// Where Hello can't ask (Remote Desktop), the question isn't shown either.
	f.keep.proceed = true
	n := len(f.asked)
	m.h.notReady = errRemoteDesktop
	m.run("run", "--intent", "build", "A", "--", "x")
	if len(f.asked) != n {
		t.Fatal("asked a question nobody could answer")
	}
}

var errRemoteDesktop = HoldError("Windows Hello can't ask in a Remote Desktop session")

func TestServiceCommand(t *testing.T) {
	m := newMachine(t, 0)
	if r := m.run("service", "install"); r.code != 1 || !strings.Contains(r.stderr, "Windows only") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	f := m.withService(false)
	m.must("service", "install")
	m.must("service", "install", "--offer-5-minutes")
	m.must("service", "uninstall")
	if len(f.installs) != 2 || f.installs[0] || !f.installs[1] {
		t.Fatalf("installs %v", f.installs)
	}
	for _, args := range [][]string{{"service"}, {"service", "start"}, {"service", "install", "--other"}, {"service", "uninstall", "x"}} {
		if r := m.run(args...); r.code != 2 || !strings.Contains(r.stderr, "usage: touchenv service install") {
			t.Errorf("%v: %d %q", args, r.code, r.stderr)
		}
	}
}

// MARK: the holder, directly

func newHolder(now *time.Time, t ProcTable) *Holder {
	return &Holder{Now: func() time.Time { return *now }, Procs: func() ProcTable { return t }}
}

var table = ProcTable{
	10: {Parent: 0, Start: 1, Name: "WindowsTerminal.exe", Session: 1},
	11: {Parent: 10, Start: 2, Name: "claude.exe", Session: 1},
	12: {Parent: 11, Start: 3, Name: "bash.exe", Session: 1},
	13: {Parent: 12, Start: 4, Name: "touchenv.exe", Session: 1},
	20: {Parent: 11, Start: 5, Name: "evil.exe", Session: 1},
	30: {Parent: 99, Start: 6, Name: "touchenv.exe", Session: 1}, // its parent is gone
}

func TestHolderChecksCallerAndLimits(t *testing.T) {
	now := time.Unix(1000, 0)
	h := newHolder(&now, table)
	me := Caller{User: "U", Session: 1, PID: 13}
	s := map[string][]byte{"A": []byte("v")}
	if _, err := h.Allow(Caller{User: "U", Session: 1, PID: 20}, s, time.Hour, 1); err != errNotTouchenv {
		t.Fatalf("a program other than touchenv.exe: %v", err)
	}
	if _, err := h.Allow(Caller{User: "U", Session: 2, PID: 13}, s, time.Hour, 1); err != errCallerGone {
		t.Fatalf("session mismatch: %v", err)
	}
	if _, err := h.Allow(Caller{User: "U", Session: 1, PID: 30}, s, time.Hour, 1); err != errNoRequester {
		t.Fatalf("no requester: %v", err)
	}
	for _, bad := range []struct {
		d time.Duration
		u int
	}{{59 * time.Second, 1}, {25 * time.Hour, 1}, {time.Hour, 0}, {time.Hour, 501}} {
		if _, err := h.Allow(me, s, bad.d, bad.u); err != errBadLimits {
			t.Errorf("%v %d: %v", bad.d, bad.u, err)
		}
	}
	if _, err := h.Approve(me, s); err != errKeepOff {
		t.Fatalf("approve while not offered: %v", err)
	}
	if who, err := h.Allow(me, s, time.Hour, 2); err != nil || who != "Claude Code" {
		t.Fatal(who, err)
	}
	// Replacing: same requester and names.
	if _, err := h.Allow(me, map[string][]byte{"A": []byte("w")}, time.Hour, 5); err != nil {
		t.Fatal(err)
	}
	if items := h.Status("U"); len(items) != 1 || items[0].Uses != 5 {
		t.Fatalf("%+v", items)
	}
	if got, _ := h.Get(me, []string{"A"}, ""); string(got["A"]) != "w" {
		t.Fatalf("%q", got)
	}
	if items := h.Status("other"); len(items) != 0 {
		t.Fatal("another user sees the grant")
	}
	if h.Lock("other") != 0 || h.Lock("U") != 1 {
		t.Fatal("lock")
	}
	// Too much for one user.
	big := map[string][]byte{"A": make([]byte, maxHeldPerUser+1)}
	if _, err := h.Allow(me, big, time.Hour, 1); err != errTooMuch {
		t.Fatal(err)
	}
}

func TestHolderWipesAndNotifies(t *testing.T) {
	now := time.Unix(1000, 0)
	h := newHolder(&now, table)
	var freed [][]byte
	h.Free = func(b []byte) { wipe(b); freed = append(freed, b) }
	me := Caller{User: "U", Session: 1, PID: 13}
	events, cancel := h.Watch("U", 1)
	defer cancel()
	if ev := <-events; len(ev.Items) != 0 {
		t.Fatal("first event should be the empty state")
	}
	h.Allow(me, map[string][]byte{"A": []byte("secret")}, time.Hour, 1)
	if ev := <-events; len(ev.Items) != 1 || ev.Notice != nil {
		t.Fatalf("%+v", ev)
	}
	h.Get(me, []string{"A"}, "why")
	ev := <-events
	if ev.Notice == nil || ev.Notice.Title != "Claude Code read A" || ev.Notice.Intent != "why" ||
		ev.Notice.Detail != "No Windows Hello asked: that was the last use granted." || len(ev.Items) != 0 {
		t.Fatalf("%+v %+v", ev, ev.Notice)
	}
	if len(freed) != 1 || !bytes.Equal(freed[0], make([]byte, 6)) {
		t.Fatalf("held secret not wiped: %q", freed)
	}
	h.Allow(me, map[string][]byte{"A": []byte("secret")}, time.Hour, 3)
	<-events
	now = now.Add(time.Hour)
	h.Tick()
	if ev := <-events; len(ev.Items) != 0 || len(freed) != 2 {
		t.Fatal("expiry didn't end and wipe it")
	}
}

// MARK: the protocol

func TestFrameRoundTripKeepsSecretsOutOfJSON(t *testing.T) {
	var buf bytes.Buffer
	in := Request{V: 1, Op: "allow", Seconds: 60, Uses: 2, Secrets: map[string][]byte{"A": []byte("s3cret"), "B": {0, 1, 2}}}
	if err := WriteFrame(&buf, in, in.Secrets); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	jl := binary.LittleEndian.Uint32(raw[4:])
	if bytes.Contains(raw[8:8+jl], []byte("s3cret")) || bytes.Contains(raw[8:8+jl], []byte("czNjcmV0")) {
		t.Fatal("secret inside the JSON part")
	}
	var out Request
	secrets, err := ReadFrame(bytes.NewReader(raw), &out)
	if err != nil || out.Op != "allow" || out.Uses != 2 || string(secrets["A"]) != "s3cret" || !bytes.Equal(secrets["B"], []byte{0, 1, 2}) {
		t.Fatalf("%v %+v %q", err, out, secrets)
	}
}

func frame(js string, tail []byte) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, uint32(4+len(js)+len(tail)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(js)))
	return append(append(b, js...), tail...)
}

func secretBytes(name string, value []byte) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(value)))
	return append(b, value...)
}

func TestReadFrameRefusesMalformed(t *testing.T) {
	huge := binary.LittleEndian.AppendUint32(nil, MaxFrame)
	cases := map[string][]byte{
		"too large":      huge,
		"short":          {1, 0, 0, 0, 0},
		"json past end":  binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, 4), 50),
		"not json":       frame("{", nil),
		"bad name":       frame("{}", secretBytes("A-B", []byte("x"))),
		"empty value":    frame("{}", secretBytes("A", nil)),
		"twice":          frame("{}", append(secretBytes("A", []byte("x")), secretBytes("A", []byte("y"))...)),
		"value past end": frame("{}", secretBytes("A", []byte("x"))[:7]),
		"name past end":  frame("{}", []byte{9, 0, 'A'}),
	}
	for name, raw := range cases {
		var r Request
		if _, err := ReadFrame(bytes.NewReader(raw), &r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestServeRefusesBadRequests(t *testing.T) {
	now := time.Unix(1000, 0)
	h := newHolder(&now, table)
	me := Caller{User: "U", Session: 1, PID: 13}
	ask := func(req Request, version int) Reply {
		var in, out bytes.Buffer
		req.V = version
		WriteFrame(&in, req, req.Secrets)
		conn := &duplex{r: &in, w: &out}
		if err := h.Serve(conn, func() (Caller, error) { return me, nil }, "1.5.0", nil); err != nil {
			t.Fatal(err)
		}
		var reply Reply
		ReadFrame(&out, &reply)
		return reply
	}
	if r := ask(Request{Op: "status"}, 2); r.OK || !strings.Contains(r.Error, "different versions") {
		t.Fatalf("%+v", r)
	}
	for _, req := range []Request{{Op: "frobnicate"}, {Op: "get"}, {Op: "get", Names: []string{"A", "A"}},
		{Op: "get", Names: []string{"bad-name"}}, {Op: "allow", Names: []string{"A"}}, {Op: "lock", Secrets: map[string][]byte{"A": {1}}},
		{Op: "status", Intent: strings.Repeat("x", 201)}} {
		if r := ask(req, 1); r.OK || r.Error != "the touchenv service didn't understand the request" {
			t.Errorf("%+v: %+v", req, r)
		}
	}
	if r := ask(Request{Op: "status"}, 1); !r.OK || r.Version != "1.5.0" {
		t.Fatalf("%+v", r)
	}
}

type duplex struct {
	r *bytes.Buffer
	w *bytes.Buffer
}

func (d *duplex) Read(p []byte) (int, error)  { return d.r.Read(p) }
func (d *duplex) Write(p []byte) (int, error) { return d.w.Write(p) }
