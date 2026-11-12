package core

// The SSH agent: answers ssh, git and scp on a named pipe (winplat) with the ssh-agent protocol. It lists the
// public halves from the store without asking; every signature asks Windows Hello, naming who asks (and through
// which ssh tools), which key, and the server: ssh tells the agent which server key it accepted, signed for that
// session (session-bind@openssh.com), and touchenv checks that signature and looks the key up in known_hosts.
// Clients can't add, remove or lock keys, and never get one. No grants or 5-minute approvals cover signatures on
// Windows (docs/windows.md): each one is a Windows Hello prompt.
//
// The agent runs for as long as you're logged on, so it never unlocks the store itself: once it has checked a request
// and written the prompt, it starts "touchenv ssh agent sign" (SSHHost.SignHelper), a process that asks Windows
// Hello, opens that one key, signs and exits, taking the store's key and the private key with it. Any program
// running as you can start that helper too, so it checks the request again on its own (signHelper below).

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The programs between the requester and the agent: named as "through" in the prompt, not as who asks.
var sshTools = map[string]bool{"ssh": true, "scp": true, "sftp": true, "rsync": true, "git": true, "ssh-keygen": true,
	"ssh-add": true, "git-remote-https": true, "git-remote-ssh": true}

const (
	sshMaxWaiting = 4  // requests waiting behind the one prompt shown at a time; more are refused at once
	sshMaxName    = 64 // runes of a user name or SSHSIG namespace shown in the prompt
	sshLogMax     = 256 << 10
	// The prompt the agent hands the sign helper: at most this many lines and runes; lines after the first (the
	// server, forwarding) are cut to sshMaxLine runes.
	sshMaxPromptLines = 4
	sshMaxPrompt      = 1500
	sshMaxLine        = 300
	sshMaxRequest     = 1 << 20 // bytes of a request to the sign helper
)

var errRefused = errors.New("refused")

type sshAgent struct {
	c       *cmd
	prompt  sync.Mutex // one Windows Hello prompt at a time
	mu      sync.Mutex
	waiting int
}

var sshLogMu sync.Mutex

// sshBinding is one session-bind@openssh.com: the server key ssh accepted for a session, verified.
type sshBinding struct {
	hostKey    ssh.PublicKey
	sessionID  []byte
	forwarding bool
}

// sshSession is one client connection (one ssh process, usually).
type sshSession struct {
	a     *sshAgent
	conn  io.ReadWriteCloser
	pid   uint32
	binds []sshBinding
}

func (a *sshAgent) serve(conn io.ReadWriteCloser, pid uint32) {
	defer conn.Close()
	agent.ServeAgent(&sshSession{a: a, conn: conn, pid: pid}, conn)
}

// gone: the client closed its end while its request waited (ssh stopped with Ctrl-C, a git fetch cancelled).
func (s *sshSession) gone() bool {
	g, ok := s.conn.(ClientGone)
	return ok && g.ClientGone()
}

// MARK: who asks

// requester names who asks for a signature: the nearest process above the client that is neither a shell nor an
// ssh tool, and the ssh tools in between (nearest last: "git, ssh"). The name is made fit for the prompt.
func (a *sshAgent) requester(pid uint32) (Requester, []string) {
	t := a.c.ssh.Procs()
	var chain []Process
	var via []string
	for _, ref := range t.Lineage(pid) {
		name := t[ref.PID].Name
		base := strings.ToLower(strings.TrimSuffix(strings.ToLower(name), ".exe"))
		if sshTools[base] {
			if !slices.Contains(via, base) {
				via = append([]string{base}, via...)
			}
			continue
		}
		chain = append(chain, Process{Name: name})
	}
	r, _ := classify(chain)
	r.Name = cut(promptClean(r.Name), sshMaxName)
	return r, via
}

// MARK: the prompt's text

// promptClean: s with every character that isn't printable (control and formatting characters, line breaks,
// spaces other than the plain one) shown as "?", so a name can't break the prompt's lines or hide what follows.
func promptClean(s string) string {
	return strings.Map(func(r rune) rune {
		if r != utf8.RuneError && unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}

func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// sshPromptText joins the prompt's lines, each made printable, the later ones cut to sshMaxLine runes.
func sshPromptText(lines []string) string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = promptClean(l)
		if i > 0 {
			out[i] = cut(out[i], sshMaxLine)
		}
	}
	return strings.Join(out, "\n")
}

// sshPromptOK: whether text is a prompt the sign helper shows: printable lines only, no more than the agent writes,
// and a first line that says what is signed with which key, as the agent writes it (firstEnd).
func sshPromptOK(text, firstEnd string) bool {
	lines := strings.Split(text, "\n")
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > sshMaxPrompt || len(lines) > sshMaxPromptLines {
		return false
	}
	for _, l := range lines {
		if l == "" || promptClean(l) != l {
			return false
		}
	}
	return strings.HasPrefix(lines[0], "touchenv: Allow ") && strings.HasSuffix(lines[0], firstEnd)
}

// sshFirstEnd: how the prompt's first line ends for a signature of purpose with the key name.
func sshFirstEnd(p sshPurpose, name string) string {
	return " to " + p.what() + " with the SSH key " + name + "?"
}

// MARK: what is signed

type sshPurpose struct {
	login     bool
	sessionID []byte
	user      string
	hostKey   ssh.PublicKey // publickey-hostbound-v00@openssh.com carries the server key too
	namespace string        // SSHSIG
}

// what: the purpose as the prompt says it ("log in as git", "sign a git commit or tag").
func (p sshPurpose) what() string {
	if p.login {
		return "log in as " + p.user
	}
	switch p.namespace {
	case "git":
		return "sign a git commit or tag"
	case "file":
		return "sign a file"
	}
	return "make an SSH signature (" + p.namespace + ")"
}

// sshAlgorithm: the signature algorithm for key and the client's flags; "" for ssh-rsa (SHA-1), which is refused.
func sshAlgorithm(key ssh.PublicKey, flags agent.SignatureFlags) string {
	if key.Type() != ssh.KeyAlgoRSA {
		return key.Type()
	}
	switch {
	case flags&agent.SignatureFlagRsaSha512 != 0:
		return ssh.KeyAlgoRSASHA512
	case flags&agent.SignatureFlagRsaSha256 != 0:
		return ssh.KeyAlgoRSASHA256
	}
	return ""
}

// sshAlgorithmOK: algorithm is one touchenv signs with for key (never ssh-rsa, SHA-1).
func sshAlgorithmOK(key ssh.PublicKey, algorithm string) bool {
	if key.Type() == ssh.KeyAlgoRSA {
		return algorithm == ssh.KeyAlgoRSASHA256 || algorithm == ssh.KeyAlgoRSASHA512
	}
	return algorithm == key.Type()
}

type sshReader struct{ b []byte }

func (r *sshReader) bytes() ([]byte, bool) {
	if len(r.b) < 4 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		return nil, false
	}
	out := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return out, true
}

func (r *sshReader) byte() (byte, bool) {
	if len(r.b) < 1 {
		return 0, false
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v, true
}

// showable: text from the client that may go into the prompt as is: short, and nothing that could break the line
// or hide what follows (spaces, control and formatting characters).
func showable(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) || utf8.RuneCount(b) > sshMaxName {
		return false
	}
	for _, r := range string(b) {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// parsePurpose reads what ssh wants signed: an ssh login (SSH_MSG_USERAUTH_REQUEST, RFC 4252 section 7) or an
// SSHSIG signature (ssh-keygen -Y sign; git commit signing uses namespace "git"). Anything else is refused.
func parsePurpose(data []byte) (sshPurpose, bool) {
	if bytes.HasPrefix(data, []byte("SSHSIG")) {
		r := sshReader{data[6:]}
		ns, ok := r.bytes()
		if !ok || !showable(ns) {
			return sshPurpose{}, false
		}
		return sshPurpose{namespace: string(ns)}, true
	}
	r := sshReader{data}
	session, ok1 := r.bytes()
	kind, ok2 := r.byte()
	user, ok3 := r.bytes()
	service, ok4 := r.bytes()
	method, ok5 := r.bytes()
	if !(ok1 && ok2 && ok3 && ok4 && ok5) || kind != 50 || string(service) != "ssh-connection" || !showable(user) {
		return sshPurpose{}, false
	}
	p := sshPurpose{login: true, sessionID: session, user: string(user)}
	switch string(method) {
	case "publickey":
	case "publickey-hostbound-v00@openssh.com":
		hasSig, ok := r.byte()
		_, okA := r.bytes() // algorithm
		_, okK := r.bytes() // the user's key
		blob, okH := r.bytes()
		if !ok || hasSig != 1 || !okA || !okK || !okH {
			return sshPurpose{}, false
		}
		key, err := ssh.ParsePublicKey(blob)
		if err != nil {
			return sshPurpose{}, false
		}
		p.hostKey = key
	default:
		return sshPurpose{}, false
	}
	return p, true
}

// MARK: the server

// knownHostNames: the names your known_hosts gives key (hashed entries count as "a hashed name").
func (a *sshAgent) knownHostNames(key ssh.PublicKey) []string {
	home, err := a.c.ssh.HomeDir()
	if err != nil {
		return nil
	}
	var names []string
	for _, file := range []string{"known_hosts", "known_hosts2"} {
		data, err := os.ReadFile(filepath.Join(home, ".ssh", file))
		if err != nil {
			continue
		}
		for len(data) > 0 {
			marker, hosts, pub, _, rest, err := ssh.ParseKnownHosts(data)
			if err != nil { // a line it can't read: skip it, not the rest of the file
				if err == io.EOF || len(rest) >= len(data) {
					break
				}
				data = rest
				continue
			}
			data = rest
			if marker != "" || !bytes.Equal(pub.Marshal(), key.Marshal()) {
				continue
			}
			for _, h := range hosts {
				if strings.HasPrefix(h, "|1|") {
					h = "a hashed name"
				}
				if !slices.Contains(names, h) {
					names = append(names, h)
				}
			}
		}
	}
	return names
}

// serverLine says which server the signature is for, from what ssh bound this session to.
func (a *sshAgent) serverLine(b *sshBinding) string {
	if b == nil {
		return "Server: unknown (this ssh didn't tell the agent which server it reached)."
	}
	return "Server: " + a.hostText(b.hostKey) + "."
}

func (a *sshAgent) hostText(key ssh.PublicKey) string {
	if names := a.knownHostNames(key); len(names) > 0 {
		return strings.Join(names, ", ") + ", its key as in your known_hosts"
	}
	return "not in your known_hosts (key " + ssh.FingerprintSHA256(key) + ")"
}

// MARK: agent.ExtendedAgent

func (s *sshSession) List() ([]*agent.Key, error) {
	st, err := loadStore(s.a.c.p)
	if err != nil || st == nil {
		return nil, nil
	}
	var out []*agent.Key
	for _, id := range st.sshIdentities() {
		out = append(out, &agent.Key{Format: id.pub.Type(), Blob: id.pub.Marshal(), Comment: id.name})
	}
	return out, nil
}

func (s *sshSession) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.SignWithFlags(key, data, 0)
}

func (s *sshSession) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	sig, err := s.sign(key, data, flags)
	if err != nil {
		s.a.c.sshLog("refused: %v", err)
		return nil, errRefused
	}
	return sig, nil
}

func (s *sshSession) Extension(kind string, contents []byte) ([]byte, error) {
	if kind != "session-bind@openssh.com" {
		return nil, agent.ErrExtensionUnsupported
	}
	r := sshReader{contents}
	keyBlob, ok1 := r.bytes()
	session, ok2 := r.bytes()
	sigBlob, ok3 := r.bytes()
	forwarding, ok4 := r.byte()
	if !(ok1 && ok2 && ok3 && ok4) || len(r.b) != 0 || len(s.binds) >= 16 {
		return nil, errRefused
	}
	hostKey, err := ssh.ParsePublicKey(keyBlob)
	if err != nil {
		return nil, errRefused
	}
	sr := sshReader{sigBlob}
	format, okF := sr.bytes()
	blob, okB := sr.bytes()
	if !okF || !okB || hostKey.Verify(session, &ssh.Signature{Format: string(format), Blob: blob}) != nil {
		s.a.c.sshLog("refused a session-bind whose signature doesn't check")
		return nil, errRefused
	}
	s.binds = append(s.binds, sshBinding{hostKey: hostKey, sessionID: slices.Clone(session), forwarding: forwarding != 0})
	return nil, nil
}

func (s *sshSession) Add(agent.AddedKey) error       { return errRefused }
func (s *sshSession) Remove(ssh.PublicKey) error     { return errRefused }
func (s *sshSession) RemoveAll() error               { return errRefused }
func (s *sshSession) Lock([]byte) error              { return errRefused }
func (s *sshSession) Unlock([]byte) error            { return errRefused }
func (s *sshSession) Signers() ([]ssh.Signer, error) { return nil, errRefused }

// sign checks the request, writes the prompt, and has the sign helper ask Windows Hello and sign.
func (s *sshSession) sign(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a := s.a
	st, err := loadStore(a.c.p)
	if err != nil || st == nil {
		return nil, errors.New("no store")
	}
	var name string
	for _, id := range st.sshIdentities() {
		if bytes.Equal(id.pub.Marshal(), key.Marshal()) {
			name = id.name
		}
	}
	if name == "" {
		return nil, fmt.Errorf("a key touchenv doesn't have (%s)", ssh.FingerprintSHA256(key))
	}
	algorithm := sshAlgorithm(key, flags)
	if algorithm == "" {
		return nil, errors.New("ssh-rsa (SHA-1) signatures are refused; the server needs rsa-sha2-256 or -512")
	}
	purpose, ok := parsePurpose(data)
	if !ok {
		return nil, fmt.Errorf("%s: neither an ssh login nor an SSHSIG signature", name)
	}
	who, via := a.requester(s.pid)
	what := purpose.what()
	var binding, forwardedBy *sshBinding
	if purpose.login && len(s.binds) > 0 {
		for i := range s.binds {
			if bytes.Equal(s.binds[i].sessionID, purpose.sessionID) {
				binding = &s.binds[i]
				break
			}
			// ssh -A binds the connection to the host it forwards the agent to first: what follows on this
			// connection is asked by that host, not by a program on this PC.
			if s.binds[i].forwarding && forwardedBy == nil {
				forwardedBy = &s.binds[i]
			}
		}
		if binding == nil {
			return nil, fmt.Errorf("%s: a login for a session this ssh didn't bind", name)
		}
		if purpose.hostKey != nil && !bytes.Equal(purpose.hostKey.Marshal(), binding.hostKey.Marshal()) {
			return nil, fmt.Errorf("%s: the login names another server than the session", name)
		}
	}
	through := ""
	if len(via) > 0 {
		through = " (through " + strings.Join(via, ", ") + ")"
	}
	lines := []string{fmt.Sprintf("touchenv: Allow %s%s to %s with the SSH key %s?", who.Name, through, what, name)}
	if purpose.login {
		lines = append(lines, a.serverLine(binding))
	}
	if forwardedBy != nil || (binding != nil && binding.forwarding) {
		from := binding
		if forwardedBy != nil {
			from = forwardedBy
		}
		lines = append(lines, "Asked through agent forwarding (ssh -A) by "+a.hostText(from.hostKey)+", not by a program on this PC.")
	}
	text := sshPromptText(lines)

	if err := a.c.h.Ready(); err != nil {
		return nil, fmt.Errorf("%s for %s: nobody can answer Windows Hello here (%v)", name, who.Name, err)
	}
	a.mu.Lock()
	if a.waiting > sshMaxWaiting { // the one being asked, and sshMaxWaiting behind it
		a.mu.Unlock()
		return nil, fmt.Errorf("%s for %s: too many requests waiting", name, who.Name)
	}
	a.waiting++
	a.mu.Unlock()
	a.prompt.Lock()
	defer func() {
		a.prompt.Unlock()
		a.mu.Lock()
		a.waiting--
		a.mu.Unlock()
	}()
	// While it waited its turn, ssh may have been stopped, or the screen locked.
	if s.gone() {
		return nil, fmt.Errorf("%s for %s: ssh went away while the request waited its turn; not asked", name, who.Name)
	}
	if err := a.c.h.Ready(); err != nil {
		return nil, fmt.Errorf("%s for %s: nobody can answer Windows Hello here (%v)", name, who.Name, err)
	}

	request, err := json.Marshal(sshSignRequest{Key: name, PublicKey: key.Marshal(), Algorithm: algorithm, Data: data, Prompt: text})
	if err != nil {
		return nil, err
	}
	out, err := a.c.ssh.SignHelper(request)
	if err != nil {
		return nil, fmt.Errorf("%s for %s: %v", name, who.Name, err)
	}
	var reply sshSignReply
	if err := json.Unmarshal(out, &reply); err != nil {
		return nil, fmt.Errorf("%s for %s: the sign helper gave no answer", name, who.Name)
	}
	if reply.Error != "" {
		return nil, fmt.Errorf("%s for %s: %s", name, who.Name, cut(promptClean(reply.Error), sshMaxLine))
	}
	sig := &ssh.Signature{Format: reply.Format, Blob: reply.Blob}
	if sig.Format != algorithm || key.Verify(data, sig) != nil {
		return nil, fmt.Errorf("%s for %s: the sign helper's signature doesn't check", name, who.Name)
	}
	a.c.sshLog("signed: %s%s, %s with %s", who.Name, through, what, name)
	return sig, nil
}

// MARK: the sign helper (touchenv ssh agent sign)

// sshSignRequest is what the agent sends the sign helper on its stdin, as JSON.
type sshSignRequest struct {
	Key       string `json:"key"`        // the key's name in the store
	PublicKey []byte `json:"public_key"` // its public half, as ssh sent it
	Algorithm string `json:"algorithm"`
	Data      []byte `json:"data"` // what to sign: an ssh login or an SSHSIG
	Prompt    string `json:"prompt"`
}

// sshSignReply is the helper's answer on its stdout: the signature, or why not.
type sshSignReply struct {
	Format string `json:"format,omitempty"`
	Blob   []byte `json:"blob,omitempty"`
	Error  string `json:"error,omitempty"`
}

// sshAgentSign is the sign helper: one request in, one reply out. Any program running as you can start it, so it
// checks everything again: the key is an SSH key in the store with that public half, the data is an ssh login or
// an SSHSIG signature, the algorithm isn't SHA-1, and the prompt is printable, short, and its first line says what is
// signed with which key as the agent says it. What it can't check (who asks, the server) is what any program running
// as you could put in a Windows Hello prompt of its own anyway (docs/windows.md, "Weaker than on a Mac").
func (c *cmd) sshAgentSign() error {
	data, err := io.ReadAll(io.LimitReader(c.env.Stdin, sshMaxRequest+1))
	var req sshSignRequest
	if err != nil || len(data) == 0 || len(data) > sshMaxRequest || json.Unmarshal(data, &req) != nil {
		return die(1, "touchenv: ssh agent sign is started by touchenv's SSH agent, with a request on its stdin")
	}
	defer wipe(data)
	defer wipe(req.Data)
	var reply sshSignReply
	sig, err := c.signHelper(req)
	if err != nil {
		msg := err.Error()
		var f fail
		if errors.As(err, &f) {
			msg = f.msg
		}
		reply.Error = strings.TrimPrefix(msg, "touchenv: ")
	} else {
		reply.Format, reply.Blob = sig.Format, sig.Blob
	}
	if json.NewEncoder(c.env.Stdout).Encode(reply) != nil || err != nil {
		return exitCode(1)
	}
	return nil
}

func (c *cmd) signHelper(req sshSignRequest) (*ssh.Signature, error) {
	name := req.Key
	if !validName(name) {
		return nil, errors.New("not a key name")
	}
	key, err := ssh.ParsePublicKey(req.PublicKey)
	if err != nil {
		return nil, errors.New("not a public key")
	}
	st, err := loadStore(c.p)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Secrets[name] == nil || st.SSHKeys[name] == "" {
		return nil, fmt.Errorf("no SSH key named %s", name)
	}
	stored, err := parsePublicLine(st.SSHKeys[name])
	if err != nil || !bytes.Equal(stored.Marshal(), key.Marshal()) {
		return nil, fmt.Errorf("%s isn't that key", name)
	}
	if !sshAlgorithmOK(key, req.Algorithm) {
		return nil, fmt.Errorf("%s: %q signatures are refused", name, req.Algorithm)
	}
	purpose, ok := parsePurpose(req.Data)
	if !ok {
		return nil, fmt.Errorf("%s: neither an ssh login nor an SSHSIG signature", name)
	}
	if !sshPromptOK(req.Prompt, sshFirstEnd(purpose, name)) {
		return nil, fmt.Errorf("%s: the prompt isn't one touchenv's agent writes", name)
	}
	storeKey, err := st.unlock(c.h, req.Prompt)
	if err != nil {
		return nil, err
	}
	secret, err := OpenSecret(storeKey, name, st.Secrets[name])
	if err != nil {
		return nil, fmt.Errorf("%s can't be opened: the store was changed outside touchenv", name)
	}
	defer wipe(secret)
	signer, err := sshSigner(secret)
	if err != nil {
		return nil, fmt.Errorf("%s isn't a key touchenv can sign with: %v", name, err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), key.Marshal()) {
		return nil, fmt.Errorf("%s doesn't match its public key in the store", name)
	}
	algSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("%s can't sign with %s", name, req.Algorithm)
	}
	sig, err := algSigner.SignWithAlgorithm(rand.Reader, req.Data, req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	return sig, nil
}

// MARK: log (refusals, so touchenv ssh agent status can say why ssh said "agent refused operation")

func (c *cmd) sshLogPath() (string, error) {
	dir, err := c.p.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ssh-agent.log"), nil
}

func (c *cmd) sshLog(format string, a ...any) {
	sshLogMu.Lock()
	defer sshLogMu.Unlock()
	path, err := c.sshLogPath()
	if err != nil {
		return
	}
	if info, err := os.Stat(path); err == nil && info.Size() > sshLogMax {
		os.Remove(path + ".old")
		os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", c.env.Now().Format("2006-01-02 15:04:05"), strings.ReplaceAll(fmt.Sprintf(format, a...), "\n", " "))
}

func (c *cmd) sshLogTail(n int) []string {
	path, err := c.sshLogPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}
