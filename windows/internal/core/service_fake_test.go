package core

import (
	"io"
	"net"
	"strings"
	"time"
)

// fakeService runs a real Holder behind an in-memory pipe, and tells it who the caller is the way the Windows
// service would (from the "kernel": here, the machine's ancestor chain turned into a process table).
type fakeService struct {
	m        *machine
	holder   *Holder
	user     string
	session  uint32
	down     bool
	impostor bool
	keep     struct{ proceed, keep bool }
	asked    []string
	trays    int
	installs []bool

	pids  map[string]uint32 // process name -> pid, so the same app keeps its pid across runs
	start map[uint32]uint64
	next  uint64
	table ProcTable
}

const touchenvPID = 5000

func (m *machine) withService(offerKeep bool) *fakeService {
	f := &fakeService{m: m, user: "S-1-5-21-1-1001", session: 1, pids: map[string]uint32{}, start: map[uint32]uint64{}, next: 100}
	f.keep.proceed = true
	f.holder = &Holder{Now: func() time.Time { return m.now }, Procs: f.procs, OfferKeep: offerKeep}
	m.svc = f
	return f
}

// procs: every app seen so far, with touchenv.exe under the machine's current ancestor chain. Each app keeps its
// pid and start time until restart(name); a parent always started before its child.
func (f *fakeService) procs() ProcTable {
	if f.table == nil {
		f.table = ProcTable{}
	}
	chain := f.m.p.ancestors
	var parent uint32
	for i := len(chain) - 1; i >= 0; i-- {
		name := chain[i].Name
		pid, ok := f.pids[strings.ToLower(name)]
		if !ok {
			f.next += 10
			pid = uint32(f.next)
			f.pids[strings.ToLower(name)] = pid
		}
		start := f.table[pid].Start
		if !ok {
			start = f.next
		}
		f.table[pid] = ProcInfo{Parent: parent, Start: start, Name: name, Session: f.session}
		parent = pid
	}
	f.table[touchenvPID] = ProcInfo{Parent: parent, Start: 1 << 40, Name: "touchenv.exe", Session: f.session}
	out := ProcTable{}
	for k, v := range f.table {
		out[k] = v
	}
	return out
}

// restart makes name a new process (new pid and start time), as when the app quits and is opened again.
func (f *fakeService) restart(name string) {
	delete(f.table, f.pids[strings.ToLower(name)])
	delete(f.pids, strings.ToLower(name))
}

func (f *fakeService) Dial() (io.ReadWriteCloser, error) {
	if f.down {
		return nil, ErrNoService
	}
	if f.impostor {
		return nil, ErrNotService
	}
	client, server := net.Pipe()
	caller := Caller{User: f.user, Session: f.session, PID: touchenvPID}
	go func() {
		f.holder.Serve(server, func() (Caller, error) { return caller, nil }, "test", nil)
		server.Close()
	}()
	return client, nil
}

func (f *fakeService) AskKeep(text string) (bool, bool, error) {
	f.asked = append(f.asked, text)
	return f.keep.proceed, f.keep.keep, nil
}

func (f *fakeService) StartTray() { f.trays++ }

func (f *fakeService) Install(offer bool, out io.Writer) error {
	f.installs = append(f.installs, offer)
	io.WriteString(out, "installed\n")
	return nil
}

func (f *fakeService) Uninstall(out io.Writer) error {
	io.WriteString(out, "uninstalled\n")
	return nil
}
