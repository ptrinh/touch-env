package core

// The holder: what the touchenv service keeps in memory, 5-minute approvals and grants, per Windows user and
// session, and nothing on disk. Portable, so it is tested on any OS; internal/winplat runs it inside the service and
// tells it who each caller is from what Windows itself reports (the pipe client's token and pid, the system's process
// list), never from anything the caller says about itself.
//
// What it can and can't promise on Windows is in docs/windows.md ("Grants on Windows"). In short: the time limit, the
// number of uses and touchenv lock are enforced here, in a process the user's programs can't read or change without
// administrator rights. Which process gets the secrets is not: a program running as the user can start a process
// under the requester, or inject into it, so the requester checks below stop accidents, not attacks.

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxEntriesPerUser = 32
	maxHeldPerUser    = 4 << 20
	maxUsesLogged     = 20
)

// ProcInfo is one process as the system lists it.
type ProcInfo struct {
	Parent  uint32
	Start   uint64 // creation time; with the pid it names one process even after the pid is reused
	Name    string // image file name, e.g. "claude.exe"
	Session uint32
}

// ProcTable is every process on the PC by pid.
type ProcTable map[uint32]ProcInfo

// ProcRef names one process.
type ProcRef struct {
	PID   uint32
	Start uint64
}

// Lineage is pid and every process above it, nearest first. Windows keeps a parent's pid after it exits and
// reuses pids, so the walk stops at a "parent" that started after its child.
func (t ProcTable) Lineage(pid uint32) []ProcRef {
	var out []ProcRef
	for i := 0; i < 64 && pid != 0 && pid != 4; i++ {
		p, ok := t[pid]
		if !ok {
			break
		}
		if n := len(out); n > 0 && p.Start != 0 && out[n-1].Start != 0 && p.Start > out[n-1].Start {
			break
		}
		out = append(out, ProcRef{pid, p.Start})
		if p.Parent == pid {
			break
		}
		pid = p.Parent
	}
	return out
}

// RequesterOf is the nearest process above pid that is not a shell or a wrapper, as the CLI names it in prompts.
func (t ProcTable) RequesterOf(pid uint32) (ProcRef, Requester) {
	above := t.Lineage(pid)
	if len(above) > 0 {
		above = above[1:]
	}
	chain := make([]Process, len(above))
	for i, ref := range above {
		chain[i] = Process{Name: t[ref.PID].Name}
	}
	r, i := classify(chain)
	if i < 0 {
		return ProcRef{}, r
	}
	return above[i], r
}

// Caller is the client of one request, as Windows reports it.
type Caller struct {
	User    string // SID of the client's token
	Session uint32 // the client's Windows session
	PID     uint32 // the client process
}

// Use is one read through an approval or a grant, kept for touchenv status.
type Use struct {
	At     time.Time `json:"at"`
	Names  []string  `json:"names"`
	By     string    `json:"by"`  // who asked (the nearest non-shell process above the touchenv that read)
	PID    uint32    `json:"pid"` // that touchenv
	Intent string    `json:"intent,omitempty"`
}

// Item is one approval or grant as status and the tray show it.
type Item struct {
	Grant   bool     `json:"grant"`
	Who     string   `json:"who"`
	Names   []string `json:"names"`
	Left    int      `json:"left"` // seconds
	Uses    int      `json:"uses"` // grants: uses left
	Session uint32   `json:"session"`
	Used    []Use    `json:"used,omitempty"`
}

// Notice is shown each time an approval or grant is used, so it never happens unseen.
type Notice struct {
	Title  string `json:"title"`
	Intent string `json:"intent,omitempty"`
	Detail string `json:"detail"`
}

// Event goes to the user's tray: the current state, and a notice when something was read.
type Event struct {
	Items  []Item  `json:"items"`
	Notice *Notice `json:"notice,omitempty"`
}

// HoldError is a refusal the client shows as is (after "touchenv: ").
type HoldError string

func (e HoldError) Error() string { return string(e) }

var (
	errNotTouchenv = HoldError("only touchenv.exe may ask the touchenv service")
	errCallerGone  = HoldError("the asking process is gone")
	errNoRequester = HoldError("can't tell which app is asking, so there is nothing to grant to")
	errKeepOff     = HoldError("5-minute approvals are off on this PC (an administrator turns them on with touchenv service install --offer-5-minutes)")
	errTooMuch     = HoldError("too many grants and approvals are held for you: touchenv lock, or wait for some to end")
	errBadLimits   = HoldError("a grant needs a length from 1 minute to 24 hours and from 1 to 500 uses")
)

type entry struct {
	grant     bool
	user      string
	session   uint32
	requester ProcRef
	who       string
	secrets   map[string][]byte // in memory from Alloc, wiped and freed when the entry ends
	expires   time.Time
	uses      int
	used      []Use
}

func (e *entry) names() []string {
	out := make([]string, 0, len(e.secrets))
	for n := range e.secrets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (e *entry) covers(names []string) bool {
	for _, n := range names {
		if e.secrets[n] == nil {
			return false
		}
	}
	return true
}

type watcher struct {
	user    string
	session uint32
	ch      chan Event
}

// Holder keeps approvals and grants. Set the function fields before use; it is safe for concurrent use.
type Holder struct {
	Now       func() time.Time
	Procs     func() ProcTable
	Alloc     func(n int) []byte // memory for a held secret (the service locks it so it isn't paged out)
	Free      func(b []byte)     // wipes and releases what Alloc gave
	OfferKeep bool               // installed with --offer-5-minutes

	mu       sync.Mutex
	entries  []*entry
	watchers map[*watcher]bool
}

func (h *Holder) alloc(n int) []byte {
	if h.Alloc != nil {
		return h.Alloc(n)
	}
	return make([]byte, n)
}

func (h *Holder) release(e *entry) {
	for name, v := range e.secrets {
		if h.Free != nil {
			h.Free(v)
		} else {
			wipe(v)
		}
		delete(e.secrets, name)
	}
}

// checkCaller: the client must be touchenv.exe in the session its token says. A program running as the user can run
// touchenv.exe itself or inject into it, so this keeps out other programs speaking the protocol by mistake, no more.
func checkCaller(c Caller, t ProcTable) error {
	p, ok := t[c.PID]
	if !ok {
		return errCallerGone
	}
	if !strings.EqualFold(p.Name, "touchenv.exe") {
		return errNotTouchenv
	}
	if p.Session != c.Session {
		return errCallerGone
	}
	return nil
}

func (h *Holder) heldBy(user string) (count, size int) {
	for _, e := range h.entries {
		if e.user == user {
			count++
			for _, v := range e.secrets {
				size += len(v)
			}
		}
	}
	return
}

func (h *Holder) keep(secrets map[string][]byte, dst map[string][]byte) {
	for name, v := range secrets {
		if old := dst[name]; old != nil {
			if h.Free != nil {
				h.Free(old)
			} else {
				wipe(old)
			}
		}
		b := h.alloc(len(v))
		copy(b, v)
		dst[name] = b
	}
}

func size(secrets map[string][]byte) int {
	n := 0
	for _, v := range secrets {
		n += len(v)
	}
	return n
}

// Approve keeps secrets for 5 minutes for the caller's requester (the "Don't ask again for 5 minutes" choice).
// The caller has just read them with Windows Hello. Returns who it covers.
func (h *Holder) Approve(c Caller, secrets map[string][]byte) (string, error) {
	if !h.OfferKeep {
		return "", errKeepOff
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.Procs()
	if err := checkCaller(c, t); err != nil {
		return "", err
	}
	ref, who := t.RequesterOf(c.PID)
	if !who.Found || t[ref.PID].Session != c.Session {
		return "", errNoRequester
	}
	h.prune(t)
	var e *entry
	for _, x := range h.entries {
		if !x.grant && x.user == c.User && x.session == c.Session && x.requester == ref {
			e = x
		}
	}
	count, held := h.heldBy(c.User)
	if (e == nil && count >= maxEntriesPerUser) || held+size(secrets) > maxHeldPerUser {
		return "", errTooMuch
	}
	if e == nil {
		e = &entry{user: c.User, session: c.Session, requester: ref, who: who.Name, secrets: map[string][]byte{}}
		h.entries = append(h.entries, e)
	}
	h.keep(secrets, e.secrets)
	e.expires = h.Now().Add(ApprovalLength)
	h.broadcast(c.User, nil)
	return who.Name, nil
}

// Allow starts a grant: the caller's requester and every process below it read these secrets without asking, for
// length and uses. A new grant to the same requester for the same names replaces the old one.
func (h *Holder) Allow(c Caller, secrets map[string][]byte, length time.Duration, uses int) (string, error) {
	if length < MinGrantLength || length > MaxGrantLength || uses < 1 || uses > MaxGrantUses || len(secrets) == 0 {
		return "", errBadLimits
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.Procs()
	if err := checkCaller(c, t); err != nil {
		return "", err
	}
	ref, who := t.RequesterOf(c.PID)
	if !who.Found || t[ref.PID].Session != c.Session {
		return "", errNoRequester
	}
	h.prune(t)
	e := &entry{grant: true, user: c.User, session: c.Session, requester: ref, who: who.Name,
		secrets: map[string][]byte{}, expires: h.Now().Add(length), uses: uses}
	for _, n := range sortedNames(secrets) {
		e.secrets[n] = nil
	}
	kept := h.entries[:0]
	for _, x := range h.entries {
		if x.grant && x.user == c.User && x.session == c.Session && x.requester == ref && sameNames(x.names(), e.names()) {
			h.release(x)
			continue
		}
		kept = append(kept, x)
	}
	h.entries = kept
	count, held := h.heldBy(c.User)
	if count >= maxEntriesPerUser || held+size(secrets) > maxHeldPerUser {
		return "", errTooMuch
	}
	h.keep(secrets, e.secrets)
	h.entries = append(h.entries, e)
	h.broadcast(c.User, nil)
	return who.Name, nil
}

func sortedNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Get hands out copies of names if a 5-minute approval for the caller's requester, or a grant to a process above
// the caller, covers them all; nil when none does (the client then asks Windows Hello). A grant use counts one.
func (h *Holder) Get(c Caller, names []string, intent string) (map[string][]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.Procs()
	if err := checkCaller(c, t); err != nil {
		return nil, err
	}
	h.prune(t)
	now := h.Now()
	ref, who := t.RequesterOf(c.PID)
	use := Use{At: now, Names: names, By: who.Name, PID: c.PID, Intent: intent}
	for _, e := range h.entries {
		if !e.grant && who.Found && e.user == c.User && e.session == c.Session && e.requester == ref && e.covers(names) {
			e.used = appendUse(e.used, use)
			h.broadcast(c.User, &Notice{Title: who.Name + " read " + strings.Join(names, ", "), Intent: intent,
				Detail: "No Windows Hello asked: approved for " + Clock(secondsLeft(e.expires, now)) + " more. touchenv lock ends it."})
			return copySecrets(e.secrets, names), nil
		}
	}
	above := t.Lineage(c.PID)
	for i, e := range h.entries {
		if !e.grant || e.user != c.User || e.session != c.Session || e.uses < 1 || !e.covers(names) || !contains(above, e.requester) {
			continue
		}
		out := copySecrets(e.secrets, names)
		e.uses--
		e.used = appendUse(e.used, use)
		detail := "No Windows Hello asked: granted for " + Clock(secondsLeft(e.expires, now)) + " more, " + Times(e.uses) + " left."
		if e.uses == 0 {
			detail = "No Windows Hello asked: that was the last use granted."
			h.release(e)
			h.entries = append(h.entries[:i], h.entries[i+1:]...)
		}
		h.broadcast(c.User, &Notice{Title: who.Name + " read " + strings.Join(names, ", "), Intent: intent, Detail: detail})
		return out, nil
	}
	return nil, nil
}

func appendUse(log []Use, u Use) []Use {
	log = append(log, u)
	if len(log) > maxUsesLogged {
		log = log[len(log)-maxUsesLogged:]
	}
	return log
}

func contains(refs []ProcRef, r ProcRef) bool {
	for _, x := range refs {
		if x == r {
			return true
		}
	}
	return false
}

func copySecrets(from map[string][]byte, names []string) map[string][]byte {
	out := map[string][]byte{}
	for _, n := range names {
		out[n] = append([]byte(nil), from[n]...)
	}
	return out
}

// Lock ends every approval and grant of user, in every session. Returns how many ended.
func (h *Holder) Lock(user string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.drop(func(e *entry) bool { return e.user == user })
}

// LockAll ends everything (the service is stopping).
func (h *Holder) LockAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drop(func(*entry) bool { return true })
}

// SessionEnded: logoff ends everything in that session.
func (h *Holder) SessionEnded(session uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drop(func(e *entry) bool { return e.session == session })
}

// SessionLocked: locking the screen ends 5-minute approvals (they are for while you're at the PC); grants go on,
// which is what they are for.
func (h *Holder) SessionLocked(session uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drop(func(e *entry) bool { return e.session == session && !e.grant })
}

// drop ends the entries matching and tells their users' trays. Called with mu held.
func (h *Holder) drop(match func(*entry) bool) int {
	kept := h.entries[:0]
	users := map[string]bool{}
	n := 0
	for _, e := range h.entries {
		if match(e) {
			h.release(e)
			users[e.user] = true
			n++
			continue
		}
		kept = append(kept, e)
	}
	for i := len(kept); i < len(h.entries); i++ {
		h.entries[i] = nil
	}
	h.entries = kept
	for u := range users {
		h.broadcast(u, nil)
	}
	return n
}

// prune drops what expired, ran out, or whose requester is gone. Called with mu held.
func (h *Holder) prune(t ProcTable) {
	now := h.Now()
	h.drop(func(e *entry) bool {
		p, alive := t[e.requester.PID]
		return !e.expires.After(now) || (e.grant && e.uses < 1) || !alive || p.Start != e.requester.Start
	})
}

// Tick prunes; the service calls it every second or two.
func (h *Holder) Tick() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.entries) == 0 {
		return
	}
	h.prune(h.Procs())
}

// Status lists user's approvals and grants, in every session.
func (h *Holder) Status(user string) []Item {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.items(user)
}

func (h *Holder) items(user string) []Item {
	now := h.Now()
	var out []Item
	for _, e := range h.entries {
		if e.user != user {
			continue
		}
		out = append(out, Item{Grant: e.grant, Who: e.who, Names: e.names(), Left: secondsLeft(e.expires, now),
			Uses: e.uses, Session: e.session, Used: append([]Use(nil), e.used...)})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Who < out[j].Who })
	return out
}

// Watch registers a tray for user in session: it gets the state now and on every change. cancel stops it.
func (h *Holder) Watch(user string, session uint32) (<-chan Event, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.watchers == nil {
		h.watchers = map[*watcher]bool{}
	}
	w := &watcher{user: user, session: session, ch: make(chan Event, 16)}
	n := 0
	for x := range h.watchers {
		if x.user == user {
			n++
		}
	}
	if n >= 4 { // a few trays per user at most; the oldest are dropped
		for x := range h.watchers {
			if x.user == user {
				delete(h.watchers, x)
				close(x.ch)
				break
			}
		}
	}
	h.watchers[w] = true
	w.ch <- Event{Items: h.items(user)}
	return w.ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.watchers[w] {
			delete(h.watchers, w)
			close(w.ch)
		}
	}
}

// broadcast sends user's state (and a notice) to their trays without blocking. Called with mu held.
func (h *Holder) broadcast(user string, n *Notice) {
	var items []Item
	for w := range h.watchers {
		if w.user != user {
			continue
		}
		if items == nil {
			items = h.items(user)
		}
		select {
		case w.ch <- Event{Items: items, Notice: n}:
		default: // a tray that doesn't read misses updates; it never holds the service up
		}
	}
}

// IsHoldError says whether err is a refusal meant for the user.
func IsHoldError(err error) bool {
	var h HoldError
	return errors.As(err, &h)
}
