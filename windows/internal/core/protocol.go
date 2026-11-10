package core

// The protocol between touchenv.exe and the touchenv service, over \\.\pipe\touchenv: one request and one reply per
// connection (a tray's "watch" gets a reply per change until it hangs up).
//
// Frame: total length (uint32 LE, at most MaxFrame) | JSON length (uint32 LE) | JSON | secrets, each
// name length (uint16 LE) | name | value length (uint32 LE) | value. Secrets stay out of the JSON so they never pass
// through encoding/json's pooled buffers, which touchenv can't wipe; the frame buffers are wiped after use.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode/utf8"
)

const (
	ProtocolVersion = 1
	MaxFrame        = 4 << 20
	maxSecretSize   = 1 << 20
	maxNames        = 64
)

// Request is what the client asks. Ops: get, approve, allow, lock, status, watch.
type Request struct {
	V       int               `json:"v"`
	Op      string            `json:"op"`
	Names   []string          `json:"names,omitempty"`
	Seconds int               `json:"seconds,omitempty"`
	Uses    int               `json:"uses,omitempty"`
	Intent  string            `json:"intent,omitempty"`
	Secrets map[string][]byte `json:"-"`
}

// Reply is the service's answer.
type Reply struct {
	V         int               `json:"v"`
	OK        bool              `json:"ok"`
	Error     string            `json:"error,omitempty"`
	Who       string            `json:"who,omitempty"`
	OfferKeep bool              `json:"offer_keep,omitempty"`
	Version   string            `json:"version,omitempty"`
	Ended     int               `json:"ended,omitempty"`
	Items     []Item            `json:"items,omitempty"`
	Event     *Event            `json:"event,omitempty"`
	Secrets   map[string][]byte `json:"-"`
}

var errFrame = errors.New("bad message")

// WriteFrame writes header (as JSON) and secrets as one frame, then wipes the frame.
func WriteFrame(w io.Writer, header any, secrets map[string][]byte) error {
	js, err := json.Marshal(header)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(secrets))
	n := 8 + len(js)
	for name, v := range secrets {
		names = append(names, name)
		n += 2 + len(name) + 4 + len(v)
	}
	if n > MaxFrame {
		return fmt.Errorf("message too large")
	}
	sort.Strings(names)
	buf := make([]byte, 0, n)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(n-4))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(js)))
	buf = append(buf, js...)
	for _, name := range names {
		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(name)))
		buf = append(buf, name...)
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(secrets[name])))
		buf = append(buf, secrets[name]...)
	}
	_, err = w.Write(buf)
	wipe(buf)
	return err
}

// ReadFrame reads one frame into header and returns its secrets, each checked (a valid name, once, 1 byte to
// 1 MiB). The frame buffer is wiped; the caller wipes the secrets.
func ReadFrame(r io.Reader, header any) (map[string][]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	total := binary.LittleEndian.Uint32(head[:])
	if total < 4 || total > MaxFrame-4 {
		return nil, errFrame
	}
	buf := make([]byte, total)
	defer wipe(buf)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	jl := binary.LittleEndian.Uint32(buf)
	if uint64(jl) > uint64(len(buf)-4) {
		return nil, errFrame
	}
	if err := json.Unmarshal(buf[4:4+jl], header); err != nil {
		return nil, errFrame
	}
	rest := buf[4+jl:]
	var secrets map[string][]byte
	fail := func() (map[string][]byte, error) {
		wipeAll(secrets)
		return nil, errFrame
	}
	for len(rest) > 0 {
		if len(rest) < 2 {
			return fail()
		}
		nl := int(binary.LittleEndian.Uint16(rest))
		if len(rest) < 2+nl+4 {
			return fail()
		}
		name := string(rest[2 : 2+nl])
		vl := binary.LittleEndian.Uint32(rest[2+nl:])
		rest = rest[2+nl+4:]
		if !validName(name) || vl == 0 || vl > maxSecretSize || uint64(vl) > uint64(len(rest)) || len(secrets) >= maxNames {
			return fail()
		}
		if secrets == nil {
			secrets = map[string][]byte{}
		}
		if secrets[name] != nil {
			return fail()
		}
		secrets[name] = append([]byte(nil), rest[:vl]...)
		rest = rest[vl:]
	}
	return secrets, nil
}

func wipeAll(m map[string][]byte) {
	for _, v := range m {
		wipe(v)
	}
}

// validate checks a request beyond its framing.
func (req *Request) validate() error {
	if len(req.Names) > maxNames {
		return errFrame
	}
	seen := map[string]bool{}
	for _, n := range req.Names {
		if !validName(n) || seen[n] {
			return errFrame
		}
		seen[n] = true
	}
	if !utf8.ValidString(req.Intent) || utf8.RuneCountInString(req.Intent) > 200 {
		return errFrame
	}
	switch req.Op {
	case "get":
		if len(req.Names) == 0 || len(req.Secrets) != 0 {
			return errFrame
		}
	case "approve", "allow":
		if len(req.Secrets) == 0 || len(req.Names) != 0 {
			return errFrame
		}
	case "lock", "status", "watch":
		if len(req.Secrets) != 0 || len(req.Names) != 0 {
			return errFrame
		}
	default:
		return errFrame
	}
	return nil
}

// Serve answers one connection. identify says who the client is; it is called after the request is read (Windows
// lets a pipe server look at its client's token only once it has read from the pipe). version is the service's
// touchenv version; done ends a watch.
func (h *Holder) Serve(conn io.ReadWriter, identify func() (Caller, error), version string, done <-chan struct{}) error {
	var req Request
	secrets, err := ReadFrame(conn, &req)
	defer wipeAll(secrets)
	if err != nil {
		return err
	}
	req.Secrets = secrets
	reply := Reply{V: ProtocolVersion, Version: version, OfferKeep: h.OfferKeep}
	c, err := identify()
	if err != nil {
		reply.Error = "the touchenv service can't tell who is asking: " + err.Error()
		return WriteFrame(conn, reply, nil)
	}
	if req.V != ProtocolVersion {
		reply.Error = "this touchenv.exe and the touchenv service are different versions: run touchenv service install again with this touchenv.exe"
		return WriteFrame(conn, reply, nil)
	}
	if err := req.validate(); err != nil {
		reply.Error = "the touchenv service didn't understand the request"
		return WriteFrame(conn, reply, nil)
	}
	var out map[string][]byte
	switch req.Op {
	case "get":
		out, err = h.Get(c, req.Names, req.Intent)
		reply.OK = out != nil
	case "approve":
		reply.Who, err = h.Approve(c, secrets)
		reply.OK = err == nil
	case "allow":
		reply.Who, err = h.Allow(c, secrets, time.Duration(req.Seconds)*time.Second, req.Uses)
		reply.OK = err == nil
	case "lock":
		reply.Ended = h.Lock(c.User)
		reply.OK = true
	case "status":
		reply.Items = h.Status(c.User)
		reply.OK = true
	case "watch":
		return h.serveWatch(conn, c, reply, done)
	}
	defer wipeAll(out)
	if err != nil {
		reply.Error = err.Error()
	}
	return WriteFrame(conn, reply, out)
}

func (h *Holder) serveWatch(conn io.ReadWriter, c Caller, reply Reply, done <-chan struct{}) error {
	events, cancel := h.Watch(c.User, c.Session)
	defer cancel()
	reply.OK = true
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			reply.Event = &ev
			if err := WriteFrame(conn, reply, nil); err != nil {
				return err
			}
		case <-done:
			return nil
		}
	}
}

// Ask sends req over conn and reads the reply (the client side). The caller wipes reply.Secrets.
func Ask(conn io.ReadWriter, req Request) (Reply, error) {
	req.V = ProtocolVersion
	var reply Reply
	if err := WriteFrame(conn, req, req.Secrets); err != nil {
		return reply, err
	}
	secrets, err := ReadFrame(conn, &reply)
	if err != nil {
		return reply, err
	}
	reply.Secrets = secrets
	return reply, nil
}
