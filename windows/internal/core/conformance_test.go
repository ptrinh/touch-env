package core

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestConformance runs ../../../conformance/cases.txt, the cases the macOS build is checked against too.
func TestConformance(t *testing.T) {
	f, err := os.Open("../../../conformance/cases.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	n := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "@mac " and "@windows " lines are for one build; this core is the Windows build's.
		if strings.HasPrefix(line, "@") {
			tag, rest, _ := strings.Cut(line, " ")
			if tag != "@windows" {
				continue
			}
			line = rest
		}
		parts := strings.SplitN(line, "|", 3)
		want, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		check := strings.TrimSpace(parts[1])
		args := strings.Fields(parts[2])
		m := newMachine(t, 0).asAgent() // as an agent: anything past the contract would be refused, never prompt
		r := m.run(args...)
		stream, text, _ := strings.Cut(check, ":")
		got := r.stderr
		if stream == "out" {
			got = r.stdout
		}
		if r.code != want || (check != "-" && !strings.Contains(got, text)) {
			t.Errorf("touchenv %v: exit %d (want %d), %s %q lacks %q", args, r.code, want, stream, got, text)
		}
		if len(m.h.prompts) != 0 {
			t.Errorf("touchenv %v asked for Hello", args)
		}
		n++
	}
	if n < 30 {
		t.Fatalf("only %d cases", n)
	}
}
