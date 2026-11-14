package core

import (
	"bytes"
	"io"
	"slices"
	"sort"
	"strings"
)

// Masking secrets in a command's output, as touchenv.swift does: touchenv run replaces the secrets' exact values
// with maskText in what the command prints, when the output goes to a program rather than a console or an AI
// assistant runs the command (shouldMask).

// maskText is what a secret is replaced with.
const maskText = "***REDACTED***"

// maskMinLength is the shortest value masked: shorter ones (a PIN, "true") would mask ordinary output.
const maskMinLength = 6

// agentVariables are environment variables AI coding assistants set for the commands they run.
var agentVariables = []string{"CLAUDECODE", "AI_AGENT"}

// shouldMask: the stream does not go to a console (a pipe, a file), or an AI assistant runs the command (agent: the
// requester is one; or one of agentVariables is set in environ).
func shouldMask(isTerminal, agent bool, environ []string) bool {
	if !isTerminal || agent {
		return true
	}
	for _, kv := range environ {
		for _, v := range agentVariables {
			if len(kv) > len(v) && kv[len(v)] == '=' && strings.EqualFold(kv[:len(v)], v) {
				return true
			}
		}
	}
	return false
}

// maskNeedles are the byte strings to hide for these values: each whole and, for a value of several lines (a PEM
// key), each of its lines of 16 bytes or more. Longest first, so a whole value is replaced before one of its lines.
func maskNeedles(values [][]byte) [][]byte {
	var out [][]byte
	add := func(b []byte) {
		if !slices.ContainsFunc(out, func(o []byte) bool { return bytes.Equal(o, b) }) {
			out = append(out, slices.Clone(b))
		}
	}
	for _, v := range values {
		if len(v) < maskMinLength {
			continue
		}
		add(v)
		for _, line := range bytes.Split(v, []byte("\n")) {
			line = bytes.TrimSuffix(line, []byte("\r"))
			if len(line) >= 16 && !bytes.Equal(line, v) {
				add(line)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// maskWriter replaces the needles in what is written to it before passing it on. A secret split across two writes
// is still found: the end of a write that could be the start of one is held back until the next write or Close.
// Nothing else is held back, so output keeps flowing.
type maskWriter struct {
	w       io.Writer
	needles [][]byte
	pending []byte
}

func newMaskWriter(w io.Writer, needles [][]byte) *maskWriter {
	return &maskWriter{w: w, needles: needles}
}

func (m *maskWriter) Write(p []byte) (int, error) {
	m.pending = append(m.pending, p...)
	out := m.replace(m.pending)
	hold := m.heldBack(out)
	if _, err := m.w.Write(out[:len(out)-hold]); err != nil {
		return 0, err
	}
	m.pending = append(m.pending[:0], out[len(out)-hold:]...)
	return len(p), nil
}

// Close writes what was held back.
func (m *maskWriter) Close() error {
	out := m.replace(m.pending)
	m.pending = nil
	_, err := m.w.Write(out)
	return err
}

func (m *maskWriter) replace(data []byte) []byte {
	var out []byte
	at := 0
scan:
	for at < len(data) {
		for _, n := range m.needles {
			if bytes.HasPrefix(data[at:], n) {
				out = append(out, maskText...)
				at += len(n)
				continue scan
			}
		}
		// Up to the next byte that starts a needle, at once.
		next := len(data)
		for _, n := range m.needles {
			if i := bytes.IndexByte(data[at+1:], n[0]); i >= 0 && at+1+i < next {
				next = at + 1 + i
			}
		}
		out = append(out, data[at:next]...)
		at = next
	}
	return out
}

// heldBack is how many bytes at the end of data could be the start of a needle.
func (m *maskWriter) heldBack(data []byte) int {
	hold := 0
	for _, n := range m.needles {
		for start := max(0, len(data)-len(n)+1); start < len(data); start++ {
			k := len(data) - start
			if k <= hold {
				break
			}
			if data[start] == n[0] && bytes.HasPrefix(n, data[start:]) {
				hold = k
				break
			}
		}
	}
	return hold
}
