package core

// The SSH agent: answers ssh, git and scp on a named pipe (winplat) with the ssh-agent protocol. It lists the
// public halves from the store without asking; every signature asks Windows Hello, naming who asks (and through
// which ssh tools), which key, and the server: ssh tells the agent which server key it accepted, signed for that
// session (session-bind@openssh.com), and touchenv checks that signature and looks the key up in known_hosts.
// Clients can't add, remove or lock keys, and never get one. No grants or 5-minute approvals cover signatures on
// Windows (docs/windows.md): each one is a Windows Hello prompt.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The programs between the requester and the agent: named as "through" in the prompt, not as who asks.
var sshTools = map[string]bool{"ssh": true, "scp": true, "sftp": true, "rsync": true, "git": true, "ssh-keygen": true,
	"ssh-add": true, "git-remote-https": true, "git-remote-ssh": true}

const (
	sshMaxWaiting = 4 // requests waiting for the one prompt shown at a time; more are refused at once
	sshLogMax     = 256 << 10
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
	pid   uint32
	binds []sshBinding
}

func (a *sshAgent) serve(conn io.ReadWriteCloser, pid uint32) {
	defer conn.Close()
	agent.ServeAgent(&sshSession{a: a, pid: pid}, conn)
}

// MARK: who asks

// requester names who asks for a signature: the nearest process above the client that is neither a shell nor an
// ssh tool, and the ssh tools in between (nearest last: "git, ssh").
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
	return r, via
}

// MARK: what is signed

type sshPurpose struct {
	login     bool
	sessionID []byte
	user      string
	hostKey   ssh.PublicKey // publickey-hostbound-v00@openssh.com carries the server key too
	namespace string        // SSHSIG
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

// parsePurpose reads what ssh wants signed: an ssh login (SSH_MSG_USERAUTH_REQUEST, RFC 4252 section 7) or an
// SSHSIG signature (ssh-keygen -Y sign; git commit signing uses namespace "git"). Anything else is refused.
func parsePurpose(data []byte) (sshPurpose, bool) {
	if bytes.HasPrefix(data, []byte("SSHSIG")) {
		r := sshReader{data[6:]}
		ns, ok := r.bytes()
		if !ok || len(ns) == 0 || len(ns) > 64 {
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
	if !(ok1 && ok2 && ok3 && ok4 && ok5) || kind != 50 || string(service) != "ssh-connection" || len(user) > 256 {
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
			if err != nil {
				break
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
	forwarded := ""
	if b.forwarding {
		forwarded = " Through agent forwarding (ssh -A)."
	}
	if names := a.knownHostNames(b.hostKey); len(names) > 0 {
		return fmt.Sprintf("Server: %s, its key as in your known_hosts.%s", strings.Join(names, ", "), forwarded)
	}
	return fmt.Sprintf("Server: not in your known_hosts (key %s).%s", ssh.FingerprintSHA256(b.hostKey), forwarded)
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

// sign checks the request, asks Windows Hello, and signs.
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
	algorithm := key.Type()
	if algorithm == ssh.KeyAlgoRSA {
		switch {
		case flags&agent.SignatureFlagRsaSha512 != 0:
			algorithm = ssh.KeyAlgoRSASHA512
		case flags&agent.SignatureFlagRsaSha256 != 0:
			algorithm = ssh.KeyAlgoRSASHA256
		default:
			return nil, errors.New("ssh-rsa (SHA-1) signatures are refused; the server needs rsa-sha2-256 or -512")
		}
	}
	purpose, ok := parsePurpose(data)
	if !ok {
		return nil, fmt.Errorf("%s: neither an ssh login nor an SSHSIG signature", name)
	}
	who, via := a.requester(s.pid)
	var what string
	var binding *sshBinding
	if purpose.login {
		if len(s.binds) > 0 {
			for i := range s.binds {
				if bytes.Equal(s.binds[i].sessionID, purpose.sessionID) {
					binding = &s.binds[i]
				}
			}
			if binding == nil {
				return nil, fmt.Errorf("%s: a login for a session this ssh didn't bind", name)
			}
			if purpose.hostKey != nil && !bytes.Equal(purpose.hostKey.Marshal(), binding.hostKey.Marshal()) {
				return nil, fmt.Errorf("%s: the login names another server than the session", name)
			}
		}
		what = fmt.Sprintf("log in as %s", purpose.user)
	} else {
		switch purpose.namespace {
		case "git":
			what = "sign a git commit or tag"
		case "file":
			what = "sign a file"
		default:
			what = fmt.Sprintf("make an SSH signature (%s)", purpose.namespace)
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
	text := strings.Join(lines, "\n")

	if err := a.c.h.Ready(); err != nil {
		return nil, fmt.Errorf("%s for %s: nobody can answer Windows Hello here (%v)", name, who.Name, err)
	}
	a.mu.Lock()
	if a.waiting >= sshMaxWaiting {
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

	storeKey, err := st.unlock(a.c.h, text)
	if err != nil {
		var f fail
		if errors.As(err, &f) {
			err = errors.New(strings.TrimPrefix(f.msg, "touchenv: "))
		}
		return nil, fmt.Errorf("%s for %s: %v", name, who.Name, err)
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
		return nil, fmt.Errorf("%s can't sign with %s", name, algorithm)
	}
	sig, err := algSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	a.c.sshLog("signed: %s%s, %s with %s", who.Name, through, what, name)
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
