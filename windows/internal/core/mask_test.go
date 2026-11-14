package core

import (
	"bytes"
	"strings"
	"testing"
)

const testToken = "ghp_TESTa1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"

func TestMaskWriterSplitsAndHoldsBack(t *testing.T) {
	needles := maskNeedles([][]byte{[]byte(testToken), []byte("abc")})
	if len(needles) != 1 {
		t.Fatalf("needles %q: a value under 6 bytes is not masked", needles)
	}
	whole := []byte("x " + testToken + " y")
	for cut := 1; cut < len(whole); cut++ {
		var b bytes.Buffer
		m := newMaskWriter(&b, needles)
		m.Write(whole[:cut])
		m.Write(whole[cut:])
		m.Close()
		if b.String() != "x ***REDACTED*** y" {
			t.Fatalf("split at %d: %q", cut, b.String())
		}
	}
	var b bytes.Buffer
	m := newMaskWriter(&b, needles)
	m.Write([]byte("line one\n"))
	if b.String() != "line one\n" {
		t.Errorf("ordinary output held back: %q", b.String())
	}
	m.Write([]byte("almost gh"))
	if b.String() != "line one\nalmost " {
		t.Errorf("the start of a token: %q", b.String())
	}
	m.Write([]byte("x\n"))
	if b.String() != "line one\nalmost ghx\n" {
		t.Errorf("let go: %q", b.String())
	}
}

func TestMaskKeyLines(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\r\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\r\n-----END PRIVATE KEY-----\r\n"
	var b bytes.Buffer
	m := newMaskWriter(&b, maskNeedles([][]byte{[]byte(pem)}))
	m.Write([]byte("key:\r\n" + pem + "part: MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\r\n"))
	m.Close()
	if b.String() != "key:\r\n***REDACTED***part: ***REDACTED***\r\n" {
		t.Errorf("%q", b.String())
	}
}

func TestShouldMask(t *testing.T) {
	for _, c := range []struct {
		terminal, agent bool
		env             []string
		want            bool
	}{
		{false, false, nil, true},
		{true, false, []string{"WT_SESSION=x"}, false},
		{true, true, nil, true},
		{true, false, []string{"ClaudeCode=1"}, true},
		{true, false, []string{"AI_AGENT=x"}, true},
		{true, false, []string{"AI_AGENTS=x"}, false},
	} {
		if got := shouldMask(c.terminal, c.agent, c.env); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

func TestRunMasksOutput(t *testing.T) {
	m := newMachine(t, 0)
	m.set("GH_TOKEN", testToken)
	m.p.printOut = "token env:GH_TOKEN done\n"
	m.p.printErr = "error with env:GH_TOKEN\n"

	// To a program (not a console): masked, on both streams.
	r := m.run("run", "GH_TOKEN", "--", "deploy")
	if r.code != 0 || r.stdout != "token ***REDACTED*** done\n" || !strings.HasSuffix(r.stderr, "error with ***REDACTED***\n") {
		t.Fatalf("pipe: %d %q %q", r.code, r.stdout, r.stderr)
	}
	// A person's console: as it is. --no-mask: as it is.
	m.p.terminal = true
	if r := m.run("run", "GH_TOKEN", "--", "deploy"); !strings.Contains(r.stdout, testToken) {
		t.Errorf("console: %q", r.stdout)
	}
	m.p.terminal = false
	if r := m.run("run", "--no-mask", "GH_TOKEN", "--", "deploy"); !strings.Contains(r.stdout, testToken) {
		t.Errorf("--no-mask: %q", r.stdout)
	}
	// An AI assistant, even in a console of its own.
	m.p.terminal = true
	m.asAgent()
	if r := m.run("run", "--intent", "deploy", "GH_TOKEN", "--", "deploy"); strings.Contains(r.stdout, testToken) {
		t.Errorf("agent: %q", r.stdout)
	}
}

func TestGetEndsALineOnlyOnAConsole(t *testing.T) {
	m := newMachine(t, 0)
	m.set("A", "value-1")
	if got := m.must("get", "A").stdout; got != "value-1" {
		t.Errorf("pipe: %q", got)
	}
	m.p.terminal = true
	if got := m.must("get", "A").stdout; got != "value-1\n" {
		t.Errorf("console: %q", got)
	}
}
