package core

// touchenv ssh on Windows: SSH private keys kept as ordinary secrets in the store (sealed like any other, read only
// after Windows Hello), with their public key line in the store's ssh_keys, and an SSH agent (sshagent.go) on a
// named pipe that signs with them, asking Windows Hello for every signature. Same commands and messages as
// touchenv.swift where they exist on both; differences are listed in docs/windows.md.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

const sshUsage = `usage: touchenv ssh add [NAME] KEYFILE · touchenv ssh ls · touchenv ssh rm NAME
       touchenv ssh agent install [--config] · touchenv ssh agent uninstall [--config] · touchenv ssh agent status`

const (
	sshAddUsage   = "usage: touchenv ssh add [NAME] KEYFILE  (NAME = env var style; from the file's name if left out)"
	sshAgentUsage = "usage: touchenv ssh agent install [--config] · touchenv ssh agent uninstall [--config] · touchenv ssh agent status"
	sshMaxKeyFile = 65536
)

// sshName: "SSH_ID_ED25519" from "C:\Users\me\.ssh\id_ed25519", as touchenv.swift's sshName(fromPath:).
func sshName(path string) string {
	base := filepath.Base(strings.ReplaceAll(path, "\\", "/"))
	for _, ext := range []string{".pem", ".key"} {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			base = base[:len(base)-len(ext)]
		}
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(base) {
		if r < 128 && (r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	upper := b.String()
	if strings.HasPrefix(upper, "SSH_") {
		return upper
	}
	return "SSH_" + upper
}

// sshKeyLabel: "ED25519 256", "ECDSA 384", "RSA 3072".
func sshKeyLabel(pub ssh.PublicKey) string {
	switch k := pub.(ssh.CryptoPublicKey).CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		return "ED25519 256"
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %d", k.Curve.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	}
	return pub.Type()
}

func sshPublicLine(pub ssh.PublicKey, name string) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + name
}

// parsePublicLine reads a line from the store's ssh_keys.
func parsePublicLine(line string) (ssh.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return pub, err
}

// sshSigner parses a stored OpenSSH private key (as ssh add stores it) into a signer.
func sshSigner(data []byte) (ssh.Signer, error) {
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

// sshLineOf: the public key line when data is an unencrypted OpenSSH private key (as touchenv ssh add stores
// them, on either system), else "".
func sshLineOf(name string, data []byte) string {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		return ""
	}
	signer, err := sshSigner(data)
	if err != nil {
		return ""
	}
	return sshPublicLine(signer.PublicKey(), name)
}

// sshKeyOf parses a key file's contents, asking for the passphrase if it has one. It returns the key in OpenSSH's
// own format without a passphrase (what touchenv stores) and its public half.
func (c *cmd) sshKeyOf(path string, data []byte) (stored []byte, pub ssh.PublicKey, err error) {
	text := string(data)
	switch {
	case strings.Contains(text, "BEGIN DSA PRIVATE KEY"):
		return nil, nil, fmt.Errorf("a DSA key, which OpenSSH no longer accepts")
	case strings.HasPrefix(strings.TrimSpace(text), "ssh-") || strings.HasPrefix(strings.TrimSpace(text), "ecdsa-"):
		return nil, nil, fmt.Errorf("that is a public key (.pub); give the private key file")
	case strings.Contains(text, "PuTTY-User-Key-File"):
		return nil, nil, fmt.Errorf("not an OpenSSH key file: convert it with ssh-keygen or PuTTYgen first")
	}
	key, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		fmt.Fprintf(c.env.Stderr, "%s is protected by a passphrase: type it once (touchenv keeps the key without one, behind Windows Hello)\n", path)
		passphrase, perr := c.p.ReadSecret(c.env.Stdin, c.env.Stderr)
		if perr != nil || len(passphrase) == 0 {
			return nil, nil, fmt.Errorf("no passphrase")
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
		wipe(passphrase)
		if err != nil {
			return nil, nil, fmt.Errorf("wrong passphrase, or a key touchenv can't read (%v)", err)
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "sk-") {
			return nil, nil, fmt.Errorf("security-key (sk-) keys can't be stored: the key never leaves the security key anyway")
		}
		return nil, nil, fmt.Errorf("not a private key ssh can use (%v)", err)
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ed25519.PrivateKey:
	default:
		return nil, nil, fmt.Errorf("a %T key, which touchenv can't sign with (Ed25519, ECDSA and RSA only)", key)
	}
	if p, ok := key.(*ed25519.PrivateKey); ok {
		key = *p
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, nil, err
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, nil, err
	}
	stored = pem.EncodeToMemory(block)
	wipe(block.Bytes)
	return stored, signer.PublicKey(), nil
}

func (c *cmd) sshCmd(args []string) error {
	if len(args) == 0 {
		return die(2, "%s", sshUsage)
	}
	sub, rest := args[0], args[1:]
	if sub == "agent" && len(rest) > 0 && !strings.HasPrefix(rest[0], "--") {
		// options may come after the action: move it past them
		action := rest[0]
		rest = append([]string{}, rest[1:]...)
		i := 0
		for i < len(rest) && strings.HasPrefix(rest[i], "--") {
			if rest[i] == "--intent" {
				i++
			}
			i++
		}
		rest = append(rest[:min(i, len(rest))], append([]string{action}, rest[min(i, len(rest)):]...)...)
	}
	config := false
	for len(rest) > 0 && strings.HasPrefix(rest[0], "--") && rest[0] != "--" {
		switch option := rest[0]; {
		case option == "--sync" && sub == "add":
			return die(2, "touchenv: --sync isn't available on Windows: keys stay on this PC")
		case option == "--for" && sub == "load":
			return die(2, "touchenv: ssh load is macOS only for now")
		case option == "--config" && sub == "agent":
			config = true
			rest = rest[1:]
		case option == "--intent" && len(rest) > 1:
			text := strings.ReplaceAll(strings.TrimSpace(rest[1]), "\n", " ")
			if r := []rune(text); len(r) > 200 {
				text = string(r[:199]) + "…"
			}
			c.o.intent, c.o.hasIntent = text, text != ""
			rest = rest[2:]
		default:
			return die(2, "touchenv: unknown option %s", option)
		}
	}
	switch sub {
	case "add":
		return c.sshAdd(rest)
	case "ls":
		if len(rest) != 0 {
			return die(2, "usage: touchenv ssh ls")
		}
		return c.sshLs()
	case "rm":
		if len(rest) != 1 || !validName(rest[0]) {
			return die(2, "usage: touchenv ssh rm NAME")
		}
		return c.sshRm(rest[0])
	case "load", "unload":
		// Loading into the stock ssh-agent exists in the macOS build only: on Windows that agent keeps keys in the
		// registry, readable by any program running as you, so it would undo what touchenv is for.
		return die(2, "touchenv: ssh %s is macOS only for now", sub)
	case "agent":
		if len(rest) != 1 {
			return die(2, "%s", sshAgentUsage)
		}
		switch rest[0] {
		case "install":
			return c.sshAgentInstall(config)
		case "uninstall":
			return c.sshAgentUninstall(config)
		case "status":
			if config {
				return die(2, "%s", sshAgentUsage)
			}
			return c.sshAgentStatus()
		case "serve": // what InstallAgent starts, at logon and now
			return c.sshAgentServe()
		}
		return die(2, "%s", sshAgentUsage)
	}
	return die(2, "%s", sshUsage)
}

func (c *cmd) needSSH() error {
	if c.ssh == nil {
		return die(1, "touchenv: ssh keys aren't available on this system")
	}
	return nil
}

func (c *cmd) sshPubPath(name string) (string, error) {
	dir, err := c.p.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ssh", name+".pub"), nil
}

func (c *cmd) writePub(name, line string) (string, error) {
	path, err := c.sshPubPath(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return path, err
	}
	return path, c.p.WriteFilePrivate(path, []byte(line+"\n"))
}

func (c *cmd) sshAdd(rest []string) error {
	if len(rest) < 1 || len(rest) > 2 || (len(rest) == 2 && !validName(rest[0])) {
		return die(2, "%s", sshAddUsage)
	}
	path := rest[len(rest)-1]
	name := sshName(path)
	if len(rest) == 2 {
		name = rest[0]
	}
	if !validName(name) {
		return die(2, "%s", sshAddUsage)
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return die(1, "touchenv: can't read %s", path)
	}
	if info.Size() > sshMaxKeyFile {
		return die(1, "touchenv: %s is too big to be an SSH private key", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return die(1, "touchenv: can't read %s", path)
	}
	defer wipe(data)
	stored, pub, err := c.sshKeyOf(path, data)
	if err != nil {
		return die(1, "touchenv: %s: %v", path, err)
	}
	defer wipe(stored)
	s, err := openOrCreateStore(c.p, c.h)
	if err != nil {
		return err
	}
	if err := s.verify(c.h); err != nil {
		return err
	}
	if s.Secrets[name] != nil {
		return die(1, "touchenv: there is already a secret named %s: give another name (touchenv ssh add NAME %s)", name, path)
	}
	sealed, err := SealSecret(s.storePublic, name, stored)
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	line := sshPublicLine(pub, name)
	if err := c.modify(s.StoreKey, func(st *storeFile) error {
		if st.Secrets[name] != nil {
			return die(1, "touchenv: there is already a secret named %s: give another name (touchenv ssh add NAME %s)", name, path)
		}
		st.Secrets[name] = sealed
		if st.SSHKeys == nil {
			st.SSHKeys = map[string]string{}
		}
		st.SSHKeys[name] = line
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(c.env.Stdout, "stored %s: %s %s, on this PC only\n", name, sshKeyLabel(pub), ssh.FingerprintSHA256(pub))
	if pubPath, err := c.writePub(name, line); err != nil {
		fmt.Fprintf(c.env.Stdout, "touchenv: couldn't write %s\n", pubPath)
	} else {
		fmt.Fprintf(c.env.Stdout, "public key: %s\n", pubPath)
	}
	c.sshNextSteps(path)
	return nil
}

// sshNextSteps: what's left to do on this PC. touchenv never deletes the key file itself.
func (c *cmd) sshNextSteps(keyPath string) {
	var steps []string
	if c.ssh != nil {
		atLogon, _ := c.ssh.AgentState()
		configured := false
		if text, err := c.readSSHConfig(); err == nil {
			configured = strings.Contains(text, sshConfigBegin)
		}
		switch {
		case !atLogon && !configured:
			steps = append(steps, "touchenv ssh agent install --config     (touchenv becomes ssh's agent; shows the lines first)")
		case !atLogon:
			steps = append(steps, "touchenv ssh agent install")
		case !configured:
			steps = append(steps, "touchenv ssh agent install --config")
		}
	}
	steps = append(steps, "ssh -T git@github.com     (or any server that has this key: Windows Hello asks)",
		"then, once it works, delete the old file yourself: del \""+keyPath+"\"")
	fmt.Fprintln(c.env.Stdout, "next:")
	for i, s := range steps {
		fmt.Fprintf(c.env.Stdout, "  %d. %s\n", i+1, s)
	}
}

type sshIdentity struct {
	name string
	pub  ssh.PublicKey
}

func (s *storeFile) sshIdentities() []sshIdentity {
	var out []sshIdentity
	for name, line := range s.SSHKeys {
		if s.Secrets[name] == nil {
			continue
		}
		if pub, err := parsePublicLine(line); err == nil {
			out = append(out, sshIdentity{name, pub})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (c *cmd) sshLs() error {
	s, err := loadStore(c.p)
	if err != nil {
		return err
	}
	var all []sshIdentity
	if s != nil {
		all = s.sshIdentities()
	}
	if len(all) == 0 {
		io.WriteString(c.env.Stdout, "no SSH keys in touchenv; add one: touchenv ssh add %USERPROFILE%\\.ssh\\id_ed25519\n")
		return nil
	}
	width := 0
	for _, id := range all {
		width = max(width, len(id.name))
	}
	for _, id := range all {
		c.writePub(id.name, s.SSHKeys[id.name]) // imported from another machine: give it its .pub here too
		fmt.Fprintf(c.env.Stdout, "%-*s  %s  %s  this PC\n", width, id.name, sshKeyLabel(id.pub), ssh.FingerprintSHA256(id.pub))
	}
	return nil
}

func (c *cmd) sshRm(name string) error {
	s, err := loadStore(c.p)
	if err != nil {
		return err
	}
	if s == nil || s.Secrets[name] == nil {
		return die(1, "touchenv: no SSH key named %s", name)
	}
	if s.SSHKeys[name] == "" {
		return die(1, "touchenv: %s isn't an SSH key from touchenv ssh add (touchenv rm %s deletes any secret)", name, name)
	}
	if err := c.requireIntent(fmt.Sprintf(`touchenv ssh rm --intent "<why>" %s`, name)); err != nil {
		return err
	}
	if _, err := s.unlock(c.h, c.promptText(fmt.Sprintf("Allow %s to delete the SSH key %s?", c.who().Name, name), "")); err != nil {
		return err
	}
	if err := c.modify(s.StoreKey, func(st *storeFile) error {
		delete(st.Secrets, name)
		delete(st.SSHKeys, name)
		return nil
	}); err != nil {
		return err
	}
	if path, err := c.sshPubPath(name); err == nil {
		os.Remove(path)
	}
	fmt.Fprintf(c.env.Stdout, "deleted %s\n", name)
	return nil
}

// MARK: .ssh\config

const (
	sshConfigBegin = "# touchenv ssh agent: begin (touchenv ssh agent uninstall --config removes this block)"
	sshConfigEnd   = "# touchenv ssh agent: end"
)

func (c *cmd) sshConfigPath() (string, error) {
	home, err := c.ssh.HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

func (c *cmd) readSSHConfig() (string, error) {
	path, err := c.sshConfigPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return string(data), err
}

func sshConfigBlock(pipe string) string {
	return sshConfigBegin + "\nHost *\n    IdentityAgent " + pipe + "\n" + sshConfigEnd + "\n"
}

// withoutBlock removes touchenv's block (the marker lines and what's between them); found says whether there was one.
func withoutBlock(text string) (out string, found bool) {
	lines := strings.SplitAfter(text, "\n")
	var kept []string
	inside := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == sshConfigBegin:
			inside, found = true, true
		case inside && trimmed == sshConfigEnd:
			inside = false
		case !inside:
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, ""), found
}

// writeSSHConfig replaces .ssh\config with text, after copying it to config.touchenv-backup.
func (c *cmd) writeSSHConfig(path, old, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if old != "" {
		if err := c.p.WriteFilePrivate(path+".touchenv-backup", []byte(old)); err != nil {
			return err
		}
	}
	return c.p.WriteFilePrivate(path, []byte(text))
}

func (c *cmd) sshAgentInstall(config bool) error {
	if err := c.needSSH(); err != nil {
		return err
	}
	pipe, err := c.ssh.AgentPipe()
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	if err := c.ssh.InstallAgent(); err != nil {
		return die(1, "touchenv: can't install the agent: %v", err)
	}
	_, running := c.ssh.AgentState()
	if running {
		fmt.Fprintf(c.env.Stdout, "the agent is running on %s, and starts at every logon\n", pipe)
	} else {
		fmt.Fprintf(c.env.Stdout, "installed: the agent starts at every logon; it didn't answer yet on %s (touchenv ssh agent status)\n", pipe)
	}
	path, err := c.sshConfigPath()
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	if !config {
		fmt.Fprintf(c.env.Stdout, "\nTo make ssh use it, add these lines to the end of %s (or run: touchenv ssh agent install --config):\n\n%s", path, sshConfigBlock(pipe))
		return nil
	}
	old, err := c.readSSHConfig()
	if err != nil {
		return die(1, "touchenv: can't read %s: %v", path, err)
	}
	if rest, found := withoutBlock(old); found {
		if strings.Contains(old, sshConfigBlock(pipe)) {
			fmt.Fprintf(c.env.Stdout, "%s already uses it\n", path)
			return nil
		}
		old = rest // an older block: replace it
	}
	text := old
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if text != "" {
		text += "\n"
	}
	text += sshConfigBlock(pipe)
	if err := c.writeSSHConfig(path, old, text); err != nil {
		return die(1, "touchenv: can't write %s: %v", path, err)
	}
	if old != "" {
		fmt.Fprintf(c.env.Stdout, "added to %s (a copy of it before is in config.touchenv-backup):\n\n%s", path, sshConfigBlock(pipe))
	} else {
		fmt.Fprintf(c.env.Stdout, "wrote %s:\n\n%s", path, sshConfigBlock(pipe))
	}
	return nil
}

func (c *cmd) sshAgentUninstall(config bool) error {
	if err := c.needSSH(); err != nil {
		return err
	}
	if err := c.ssh.UninstallAgent(); err != nil {
		return die(1, "touchenv: can't uninstall the agent: %v", err)
	}
	fmt.Fprintln(c.env.Stdout, "the agent is stopped and no longer starts at logon")
	path, err := c.sshConfigPath()
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	old, err := c.readSSHConfig()
	if err != nil {
		return die(1, "touchenv: can't read %s: %v", path, err)
	}
	text, found := withoutBlock(old)
	switch {
	case !found:
		if config {
			fmt.Fprintf(c.env.Stdout, "%s has no touchenv lines\n", path)
		}
	case !config:
		fmt.Fprintf(c.env.Stdout, "%s still points ssh at it: remove touchenv's lines (or run: touchenv ssh agent uninstall --config)\n", path)
	default:
		if err := c.writeSSHConfig(path, old, strings.TrimRight(text, "\n")+"\n"); err != nil {
			return die(1, "touchenv: can't write %s: %v", path, err)
		}
		fmt.Fprintf(c.env.Stdout, "removed touchenv's lines from %s (a copy of it before is in config.touchenv-backup)\n", path)
	}
	return nil
}

func (c *cmd) sshAgentStatus() error {
	if err := c.needSSH(); err != nil {
		return err
	}
	pipe, err := c.ssh.AgentPipe()
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	atLogon, running := c.ssh.AgentState()
	yes := func(b bool, y, n string) string {
		if b {
			return y
		}
		return n
	}
	fmt.Fprintf(c.env.Stdout, "agent:      %s, %s\n", yes(running, "running on "+pipe, "not running"),
		yes(atLogon, "starts at logon", "doesn't start at logon (touchenv ssh agent install)"))
	path, _ := c.sshConfigPath()
	text, _ := c.readSSHConfig()
	fmt.Fprintf(c.env.Stdout, "ssh config: %s\n", yes(strings.Contains(text, sshConfigBlock(pipe)), path+" uses it",
		path+" doesn't use it (touchenv ssh agent install --config)"))
	s, err := loadStore(c.p)
	if err != nil {
		return err
	}
	n := 0
	if s != nil {
		n = len(s.sshIdentities())
	}
	fmt.Fprintf(c.env.Stdout, "keys:       %d (touchenv ssh ls)\n", n)
	if lines := c.sshLogTail(10); len(lines) > 0 {
		fmt.Fprintln(c.env.Stdout, "recent:")
		for _, l := range lines {
			fmt.Fprintln(c.env.Stdout, "  "+l)
		}
	}
	return nil
}

func (c *cmd) sshAgentServe() error {
	if err := c.needSSH(); err != nil {
		return err
	}
	a := &sshAgent{c: c}
	err := c.ssh.Serve(func(conn io.ReadWriteCloser, pid uint32) {
		a.serve(conn, pid)
	})
	if err != nil {
		c.sshLog("agent stopped: %v", err)
		return die(1, "touchenv: %v", err)
	}
	return nil
}
