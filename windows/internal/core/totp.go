package core

// Codes from an authenticator app (touchenv grant --totp): the service's side.
//
// A six-digit code (RFC 6238: HMAC-SHA1, 30 seconds) approves a timed grant instead of Windows Hello, for someone
// driving an agent from afar. Windows Hello can't be answered from afar and every secret in the store is sealed to it,
// so the service keeps, per Windows user, the key behind the codes and a copy of each secret that user allowed from
// afar (touchenv totp allow, with Windows Hello, at the PC). It checks the code itself and makes the grant from
// those copies: nothing a program running as the user says is taken on trust, and such a program can't read the key or
// the copies.
//
// Unlike grants, this is kept on disk (the Vault: a file only the service's account can read, encrypted to that
// account), so it is still there after a restart. An administrator can read it; see docs/windows.md.
//
// Setting codes up and unlocking them after wrong codes must be signed by the user's Windows Hello key, which asks
// for Hello on every use: the first setup pins that key, and later ones must be signed by the same key. So a
// program running as the user can't swap in a key of its own behind the codes without a Hello prompt.

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	totpPeriod        = 30
	totpDigits        = 6
	totpTries         = 5
	totpSeedSize      = 20
	TOTPDefaultLength = 12 * time.Hour
	TOTPDefaultUses   = 100
	maxRemoteNames    = 32
	maxRemoteSize     = 1 << 20
	signedWindow      = 5 * time.Minute
	seedName          = "SEED"
)

// Base32Encode is RFC 4648 base32 without padding, as authenticator apps take it.
func Base32Encode(b []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// TOTPCode is the code for one 30-second step (RFC 4226 truncation of HMAC-SHA1 over the step, big-endian).
func TOTPCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	number := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", number%1000000)
}

// TOTPStep is the 30-second step t is in.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// TOTPURI is what an authenticator app scans.
func TOTPURI(secret []byte, account string) string {
	escape := func(s string) string {
		var b strings.Builder
		for _, c := range []byte(s) {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~@", c) >= 0 {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
		return b.String()
	}
	return "otpauth://totp/" + escape("touchenv:"+account) + "?secret=" + Base32Encode(secret) +
		"&issuer=touchenv&algorithm=SHA1&digits=6&period=30"
}

// TOTPSignedDigest is what the user's Windows Hello key signs to set codes up ("setup") or unlock them ("unlock").
func TOTPSignedDigest(op string, at int64, seed []byte, maxSeconds, maxUses int) []byte {
	seedHash := sha256.Sum256(seed)
	d := sha256.Sum256([]byte(fmt.Sprintf("touchenv totp v1\n%s\n%d\n%x\n%d\n%d", op, at, seedHash, maxSeconds, maxUses)))
	return d[:]
}

// Vault keeps the service's codes file. Load gives nil when nothing was saved yet.
type Vault interface {
	Load() ([]byte, error)
	Save(data []byte) error
}

// remoteState is what the service keeps for one Windows user. The exported fields are the file's header.
type remoteState struct {
	User       string `json:"user"`
	Pub        []byte `json:"pub"` // the user's Windows Hello public key (PKCS #1), pinned at the first setup
	Created    int64  `json:"created"`
	MaxSeconds int    `json:"max_seconds"` // the longest grant a code may approve
	MaxUses    int    `json:"max_uses"`
	LastStep   int64  `json:"last_step"` // the step of the last code accepted: nothing at or before it passes again
	Failures   int    `json:"failures"`  // wrong codes in a row
	NotBefore  int64  `json:"not_before"`
	LastSigned int64  `json:"last_signed"` // the time in the last signed request accepted: none at or before it passes
	LastUsed   int64  `json:"last_used"`

	seed   []byte
	copies map[string][]byte // the secrets allowed from afar
}

// TOTPStatus is what touchenv totp status shows.
type TOTPStatus struct {
	On         bool     `json:"on"`
	Created    int64    `json:"created,omitempty"`
	MaxSeconds int      `json:"max_seconds,omitempty"`
	MaxUses    int      `json:"max_uses,omitempty"`
	LastUsed   int64    `json:"last_used,omitempty"`
	Failures   int      `json:"failures,omitempty"`
	Locked     bool     `json:"locked,omitempty"`
	Wait       int      `json:"wait,omitempty"` // seconds before the next code is looked at
	Names      []string `json:"names,omitempty"`
}

var (
	errNoVault   = HoldError("this touchenv service has nowhere to keep codes: run touchenv service install again")
	errVault     = HoldError("the touchenv service can't read or save its codes file; nothing approved")
	errNoCodes   = HoldError("codes aren't set up on this PC. At the PC, in a terminal: touchenv totp setup")
	errBadSetup  = HoldError("the touchenv service didn't accept that setup")
	errOtherKey  = HoldError("codes were set up with another Windows Hello key. An administrator starts over with touchenv service uninstall, then touchenv service install")
	errSignature = HoldError("that wasn't approved with your Windows Hello key just now; try again")
	errRemoteMax = HoldError(fmt.Sprintf("at most %d secrets and 1 MiB can be allowed from afar", maxRemoteNames))
)

type codeCheck int

const (
	codeOK codeCheck = iota
	codeWrong
	codeUsed
	codeLocked
	codeWait
	codeMalformed
)

// throttleDelay: the wait after n wrong codes in a row: 1, 2, 4, 8 seconds.
func throttleDelay(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Second << min(n-1, 12)
}

// checkCode checks code against the step now is in and the one before, and records the outcome in st (to be saved
// by the caller before anything is allowed). A code that isn't six digits isn't counted as a wrong one. wait is
// the seconds left for codeWait.
func checkCode(code string, st *remoteState, now time.Time) (result codeCheck, wait int) {
	if len(code) != totpDigits || strings.Trim(code, "0123456789") != "" {
		return codeMalformed, 0
	}
	if st.Failures >= totpTries {
		return codeLocked, 0
	}
	if left := time.Unix(st.NotBefore, 0).Sub(now); left > 0 {
		return codeWait, int((left + time.Second - 1) / time.Second)
	}
	current := TOTPStep(now)
	matched := int64(-1)
	for _, step := range []int64{current - 1, current} {
		if subtle.ConstantTimeCompare([]byte(TOTPCode(st.seed, step)), []byte(code)) == 1 {
			matched = step
		}
	}
	if matched < 0 {
		st.Failures++
		st.NotBefore = now.Add(throttleDelay(st.Failures)).Unix() + 1
		if st.Failures >= totpTries {
			return codeLocked, 0
		}
		return codeWrong, 0
	}
	if matched <= st.LastStep {
		return codeUsed, 0
	}
	st.LastStep = matched
	st.Failures = 0
	st.NotBefore = 0
	st.LastUsed = now.Unix()
	return codeOK, 0
}

// loadRemote reads the codes file once. Called with mu held.
func (h *Holder) loadRemote() error {
	if h.remoteLoaded {
		return h.remoteErr
	}
	h.remoteLoaded = true
	h.remote = map[string]*remoteState{}
	if h.Vault == nil {
		h.remoteErr = errNoVault
		return h.remoteErr
	}
	data, err := h.Vault.Load()
	defer wipe(data)
	if err != nil {
		h.remoteErr = errVault
		return h.remoteErr
	}
	r := bytes.NewReader(data)
	for r.Len() > 0 {
		st := &remoteState{copies: map[string][]byte{}}
		seed, err := ReadFrame(r, st)
		if err == nil && (len(seed) != 1 || len(seed[seedName]) != totpSeedSize || st.User == "" || h.remote[st.User] != nil) {
			err = errFrame
		}
		var copies map[string][]byte
		if err == nil {
			copies, err = ReadFrame(r, &struct{}{})
		}
		if err != nil {
			wipeAll(seed)
			for _, x := range h.remote {
				h.releaseRemote(x)
			}
			h.remote = map[string]*remoteState{}
			h.remoteErr = errVault
			return h.remoteErr
		}
		st.seed = h.held(seed[seedName])
		for name, v := range copies {
			st.copies[name] = h.held(v)
		}
		wipeAll(seed)
		wipeAll(copies)
		h.remote[st.User] = st
	}
	return nil
}

// held copies b into the memory the service keeps secrets in.
func (h *Holder) held(b []byte) []byte {
	out := h.alloc(len(b))
	copy(out, b)
	return out
}

func (h *Holder) free(b []byte) {
	if h.Free != nil {
		h.Free(b)
	} else {
		wipe(b)
	}
}

func (h *Holder) releaseRemote(st *remoteState) {
	h.free(st.seed)
	for name, v := range st.copies {
		h.free(v)
		delete(st.copies, name)
	}
}

// saveRemote writes every user's state. Called with mu held.
func (h *Holder) saveRemote() error {
	users := make([]string, 0, len(h.remote))
	for u := range h.remote {
		users = append(users, u)
	}
	sort.Strings(users)
	var buf bytes.Buffer
	defer func() { wipe(buf.Bytes()) }()
	for _, u := range users {
		st := h.remote[u]
		if err := WriteFrame(&buf, st, map[string][]byte{seedName: st.seed}); err != nil {
			return errVault
		}
		if err := WriteFrame(&buf, struct{}{}, st.copies); err != nil {
			return errVault
		}
	}
	if err := h.Vault.Save(buf.Bytes()); err != nil {
		return errVault
	}
	return nil
}

// commitRemote puts next in user's place (nil: nothing) and saves; if it can't be saved, the old state stays.
// Called with mu held. The caller frees what only the losing state holds.
func (h *Holder) commitRemote(user string, next *remoteState) error {
	old := h.remote[user]
	if next == nil {
		delete(h.remote, user)
	} else {
		h.remote[user] = next
	}
	if err := h.saveRemote(); err != nil {
		if old == nil {
			delete(h.remote, user)
		} else {
			h.remote[user] = old
		}
		return err
	}
	return nil
}

// remoteFor is the caller's state after the usual checks; nil with no error when codes aren't set up.
func (h *Holder) remoteFor(c Caller) (*remoteState, ProcTable, error) {
	t := h.Procs()
	if err := checkCaller(c, t); err != nil {
		return nil, nil, err
	}
	if err := h.loadRemote(); err != nil {
		return nil, nil, err
	}
	return h.remote[c.User], t, nil
}

// signedBy checks a request signed by the Windows Hello key pub: made within the last few minutes, and newer than
// the last one accepted.
func signedBy(pub []byte, lastSigned int64, now time.Time, at int64, digest, sig []byte) bool {
	key, err := x509.ParsePKCS1PublicKey(pub)
	if err != nil || key.N.BitLen() < 2048 {
		return false
	}
	if d := now.Sub(time.Unix(at, 0)); d < -signedWindow || d > signedWindow || at <= lastSigned {
		return false
	}
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sig) == nil
}

// TOTPSetup turns codes on for the caller's user, or replaces the key behind them. The secrets already allowed
// from afar stay allowed.
func (h *Holder) TOTPSetup(c Caller, req *Request) error {
	seed := req.Secrets[seedName]
	if len(seed) != totpSeedSize || len(req.Secrets) != 1 || req.Seconds < int(MinGrantLength/time.Second) ||
		req.Seconds > int(MaxGrantLength/time.Second) || req.Uses < 1 || req.Uses > MaxGrantUses {
		return errBadSetup
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	old, _, err := h.remoteFor(c)
	if err != nil {
		return err
	}
	now := h.Now()
	last := int64(0)
	if old != nil {
		if !bytes.Equal(old.Pub, req.Pub) {
			return errOtherKey
		}
		last = old.LastSigned
	}
	if !signedBy(req.Pub, last, now, req.At, TOTPSignedDigest("setup", req.At, seed, req.Seconds, req.Uses), req.Sig) {
		return errSignature
	}
	// Codes shown up to now are used up: the one typed to confirm approves nothing more.
	next := &remoteState{User: c.User, Pub: append([]byte(nil), req.Pub...), Created: now.Unix(), MaxSeconds: req.Seconds,
		MaxUses: req.Uses, LastStep: TOTPStep(now), LastSigned: req.At, seed: h.held(seed), copies: map[string][]byte{}}
	if old != nil {
		next.copies = old.copies
	}
	if err := h.commitRemote(c.User, next); err != nil {
		h.free(next.seed)
		return err
	}
	if old != nil {
		h.free(old.seed)
	}
	return nil
}

// TOTPUnlock takes codes again after wrong ones locked them.
func (h *Holder) TOTPUnlock(c Caller, req *Request) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, _, err := h.remoteFor(c)
	if err != nil {
		return err
	}
	if st == nil {
		return errNoCodes
	}
	if !signedBy(st.Pub, st.LastSigned, h.Now(), req.At, TOTPSignedDigest("unlock", req.At, nil, 0, 0), req.Sig) {
		return errSignature
	}
	next := *st
	next.Failures, next.NotBefore, next.LastSigned = 0, 0, req.At
	return h.commitRemote(c.User, &next)
}

// TOTPAllow keeps copies of secrets for grants from afar. The client has just read them with Windows Hello (the
// service can't check that; a program without Hello can only put in values it already has). With update, only
// names already allowed are replaced (touchenv set of such a secret). Returns how many it keeps now for those names.
func (h *Holder) TOTPAllow(c Caller, secrets map[string][]byte, update bool) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, _, err := h.remoteFor(c)
	if err != nil {
		return 0, err
	}
	if st == nil {
		if update {
			return 0, nil
		}
		return 0, errNoCodes
	}
	next := *st
	next.copies = map[string][]byte{}
	total := 0
	for name, v := range st.copies {
		next.copies[name] = v
		total += len(v)
	}
	var added, replaced [][]byte
	n := 0
	for name, v := range secrets {
		old := st.copies[name]
		if update && old == nil {
			continue
		}
		total += len(v) - len(old)
		b := h.held(v)
		added = append(added, b)
		if old != nil {
			replaced = append(replaced, old)
		}
		next.copies[name] = b
		n++
	}
	if n == 0 {
		return 0, nil
	}
	if len(next.copies) > maxRemoteNames || total > maxRemoteSize {
		err = errRemoteMax
	} else {
		err = h.commitRemote(c.User, &next)
	}
	if err != nil {
		for _, b := range added {
			h.free(b)
		}
		return 0, err
	}
	for _, b := range replaced {
		h.free(b)
	}
	return n, nil
}

// TOTPDeny forgets the copies of names. Returns how many it held. No Windows Hello: it only takes a way in away.
func (h *Holder) TOTPDeny(c Caller, names []string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, _, err := h.remoteFor(c)
	if err != nil || st == nil {
		return 0, err
	}
	next := *st
	next.copies = map[string][]byte{}
	for name, v := range st.copies {
		next.copies[name] = v
	}
	var gone [][]byte
	for _, name := range names {
		if v := next.copies[name]; v != nil {
			gone = append(gone, v)
			delete(next.copies, name)
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}
	if err := h.commitRemote(c.User, &next); err != nil {
		return 0, err
	}
	for _, b := range gone {
		h.free(b)
	}
	return len(gone), nil
}

// TOTPOff forgets the key behind the codes and every copy. Says whether codes were on.
func (h *Holder) TOTPOff(c Caller) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, _, err := h.remoteFor(c)
	if err != nil || st == nil {
		return false, err
	}
	if err := h.commitRemote(c.User, nil); err != nil {
		return false, err
	}
	h.releaseRemote(st)
	return true, nil
}

// TOTPState is what touchenv totp status shows for the caller's user.
func (h *Holder) TOTPState(c Caller) (*TOTPStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, _, err := h.remoteFor(c)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return &TOTPStatus{}, nil
	}
	out := &TOTPStatus{On: true, Created: st.Created, MaxSeconds: st.MaxSeconds, MaxUses: st.MaxUses, LastUsed: st.LastUsed,
		Failures: st.Failures, Locked: st.Failures >= totpTries, Names: sortedNames(st.copies)}
	if left := time.Unix(st.NotBefore, 0).Sub(h.Now()); left > 0 && !out.Locked {
		out.Wait = int((left + time.Second - 1) / time.Second)
	}
	return out, nil
}

// TOTPGrant starts a grant of names to the caller's requester, approved by code. Refused before the code is
// looked at when a name isn't allowed from afar or the grant asks for more than setup allows: a refusal of that
// kind doesn't use the code up.
func (h *Holder) TOTPGrant(c Caller, names []string, length time.Duration, uses int, code string) (string, error) {
	if length < MinGrantLength || length > MaxGrantLength || uses < 1 || uses > MaxGrantUses || len(names) == 0 {
		return "", errBadLimits
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st, t, err := h.remoteFor(c)
	if err != nil {
		return "", err
	}
	if st == nil {
		return "", errNoCodes
	}
	var missing []string
	for _, n := range names {
		if st.copies[n] == nil {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		list := strings.Join(missing, ", ")
		verb := "isn't"
		if len(missing) > 1 {
			verb = "aren't"
		}
		return "", HoldError(fmt.Sprintf("--totp is for secrets allowed from afar only. %s %s: that grant needs Windows Hello "+
			"at the PC (or, there, touchenv totp allow %s)", list, verb, strings.Join(missing, " ")))
	}
	if int(length/time.Second) > st.MaxSeconds || uses > st.MaxUses {
		return "", HoldError(fmt.Sprintf("a code approves at most %s and %s (chosen at touchenv totp setup); ask for less, "+
			"or use Windows Hello at the PC", SpokenLength(time.Duration(st.MaxSeconds)*time.Second), Times(st.MaxUses)))
	}
	if ref, who := t.RequesterOf(c.PID); !who.Found || t[ref.PID].Session != c.Session {
		return "", errNoRequester
	}
	next := *st
	result, wait := checkCode(code, &next, h.Now())
	// Saved before anything is allowed: a code that can't be marked used approves nothing.
	if next.LastStep != st.LastStep || next.Failures != st.Failures || next.NotBefore != st.NotBefore {
		if err := h.commitRemote(c.User, &next); err != nil {
			return "", err
		}
	}
	switch result {
	case codeOK:
	case codeMalformed:
		return "", HoldError("--totp takes the six digits your authenticator app shows")
	case codeWrong:
		return "", HoldError("wrong code; not approved. Ask for the code the app shows now (check this PC's clock too)")
	case codeUsed:
		return "", HoldError("that code was already used; wait for the app to show the next one")
	case codeWait:
		return "", HoldError(fmt.Sprintf("too many wrong codes; try again in %d s", wait))
	default:
		return "", HoldError(fmt.Sprintf("codes are locked after %d wrong ones in a row. At the PC: touchenv totp unlock (Windows Hello)", totpTries))
	}
	secrets := map[string][]byte{}
	for _, n := range names {
		secrets[n] = st.copies[n]
	}
	return h.allowLocked(c, t, secrets, length, uses)
}
