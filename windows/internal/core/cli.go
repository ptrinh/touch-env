package core

// The command line, kept to the same contract as touchenv.swift: commands, options, messages and exit codes
// (2 for usage, 1 for refusals and failures, the command's own code for run). Differences are listed in docs/windows.md.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Version is set at build time from touchenv.swift's `let version` (see .github/workflows/windows.yml).
var Version = "dev"

const importLifetime = time.Hour

func usage() string {
	return "touchenv " + Version + ` — secrets on this PC, every read behind Windows Hello

  touchenv set NAME                     store a secret (typed with no echo, or piped: touchenv set NAME < file)
  touchenv get NAME                     print it
  touchenv run NAME[:file] ... -- CMD   run CMD with each secret in env var NAME; with :file, NAME holds
                                        the path of a private temp file, removed when CMD ends
  touchenv ls                           list names
  touchenv rm NAME                      delete
  touchenv grant --for 8h --uses 20 NAME ...
                                        one Windows Hello now; then this app and what it runs read those
                                        secrets with touchenv run without asking, also while the PC is locked,
                                        until the time (24h at most) or the uses run out
  touchenv lock                         end every approval now: 5-minute ones and grants
  touchenv status                       list grants and 5-minute approvals, and each use

  Grants and 5-minute approvals need the touchenv service (once, as administrator):
  touchenv service install [--offer-5-minutes] · touchenv service uninstall

  Moving to a new PC or Mac:
  touchenv import --begin               (new machine) prints tenv1:… and a check code
  touchenv export --to tenv1:… [NAME ...] > keys.tenv
                                        (old machine) all secrets, or those named, encrypted for that machine only
  touchenv import [--replace] keys.tenv
                                        (new machine) store them, then delete the file; --replace overwrites

  --intent TEXT after the command (touchenv run --intent "why" NAME -- CMD) puts one line on why in the prompt.`
}

// Env is what a run of touchenv works with.
type Env struct {
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	Platform Platform
	Hello    Hello
	Service  Service // nil: no service on this system (grants and 5-minute approvals refused)
	Now      func() time.Time
}

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validName(name string) bool { return namePattern.MatchString(name) }

// Main runs touchenv with args (without the program name) and returns the exit code.
func Main(args []string, env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}
	err := run(args, &env)
	if err == nil {
		return 0
	}
	var f fail
	if errors.As(err, &f) {
		fmt.Fprintln(env.Stderr, f.msg)
		return f.code
	}
	var exit exitCode
	if errors.As(err, &exit) {
		return int(exit)
	}
	fmt.Fprintln(env.Stderr, "touchenv:", err)
	return 1
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

type options struct {
	intent    string
	hasIntent bool
	sync      bool
	recipient string
	hasTo     bool
	begin     bool
	replace   bool
	localOnly bool
	length    time.Duration // grant --for
	lengthArg string
	uses      int // grant --uses
}

func run(args []string, env *Env) error {
	if len(args) == 0 {
		return die(2, "%s", usage())
	}
	command, args := args[0], args[1:]
	var o options
	for len(args) > 0 && strings.HasPrefix(args[0], "--") && args[0] != "--" {
		option := args[0]
		switch {
		case option == "--sync" && command == "set":
			o.sync = true
			args = args[1:]
		case option == "--to" && command == "export" && len(args) > 1:
			o.recipient, o.hasTo = args[1], true
			args = args[2:]
		case command == "import" && (option == "--begin" || option == "--replace" || option == "--local"):
			switch option {
			case "--begin":
				o.begin = true
			case "--replace":
				o.replace = true
			default:
				o.localOnly = true
			}
			args = args[1:]
		case option == "--password" && (command == "get" || command == "run" || command == "grant"):
			// Approving with the Mac password typed in the terminal exists in the macOS build only (docs/grants.md).
			return die(2, "touchenv: --password is macOS only for now")
		case command == "grant" && (option == "--always" || option == "--for-program" || option == "--list" ||
			option == "--revoke" || option == "--revoke-all"):
			// Standing grants (docs/grants.md) exist in the macOS build only.
			return die(2, "touchenv: standing grants (grant --always, --list, --revoke) are macOS only for now")
		case option == "--for" && command == "grant" && len(args) > 1:
			d, ok := ParseLength(args[1])
			if !ok || d > MaxGrantLength {
				return die(2, "touchenv: --for takes a length like 30m, 8h or 1h30m, 24h at most")
			}
			o.length, o.lengthArg = d, args[1]
			args = args[2:]
		case option == "--uses" && command == "grant" && len(args) > 1:
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 || n > MaxGrantUses {
				return die(2, "touchenv: --uses takes a number from 1 to %d", MaxGrantUses)
			}
			o.uses = n
			args = args[2:]
		case option == "--intent" && len(args) > 1:
			text := strings.ReplaceAll(strings.TrimSpace(args[1]), "\n", " ")
			if utf8.RuneCountInString(text) > 200 {
				text = string([]rune(text)[:199]) + "…"
			}
			o.intent, o.hasIntent = text, text != ""
			args = args[2:]
		default:
			return die(2, "touchenv: unknown option %s", option)
		}
	}

	c := &cmd{env: env, o: o, p: env.Platform, h: env.Hello, svc: env.Service}
	switch command {
	case "set":
		return c.set(args)
	case "get":
		return c.get(args)
	case "rm":
		return c.rm(args)
	case "ls":
		return c.ls(args)
	case "run":
		return c.run(args)
	case "grant":
		return c.grant(args)
	case "lock":
		return c.lock(args)
	case "status":
		return c.status(args)
	case "service":
		return c.service(args)
	case "export":
		return c.export(args)
	case "import":
		return c.importCmd(args)
	case "log":
		// The access log exists in the macOS build only (docs/access-log.md).
		return die(2, "touchenv: the access log is macOS only for now")
	case "ssh":
		// The SSH agent and key commands exist in the macOS build only (docs/ssh.md).
		return die(2, "touchenv: ssh keys are macOS only for now")
	case "help", "-h", "--help":
		fmt.Fprintln(env.Stdout, usage())
		return nil
	case "version", "--version":
		fmt.Fprintln(env.Stdout, Version)
		return nil
	default:
		return die(2, "touchenv: unknown command %s", command)
	}
}

type cmd struct {
	env *Env
	o   options
	p   Platform
	h   Hello
	svc Service
}

func (c *cmd) who() Requester { return ClassifyChain(c.p.Ancestors()) }

// requireIntent: an AI agent must give a reason for anything that asks for Windows Hello or reads a secret, so the
// prompt always says why. Refused before any prompt: the agent reads the error and asks again with one.
func (c *cmd) requireIntent(example string) error {
	if c.o.hasIntent {
		return nil
	}
	if who := c.who(); who.IsAgent {
		return die(2, "touchenv: %s must say why, in a few words: %s\n"+
			"  (--intent goes right after the command; the reason is shown in the Windows Hello prompt)", who.Name, example)
	}
	return nil
}

// promptText is what Windows Hello shows: the question, the intent (or a warning), and the command when given.
func (c *cmd) promptText(title, command string) string {
	lines := []string{"touchenv: " + title}
	if c.o.hasIntent {
		lines = append(lines, "Intent: "+c.o.intent)
	} else if command != "" {
		lines = append(lines, "No reason given. Check the command:")
	}
	if command != "" {
		lines = append(lines, command)
	}
	text := strings.Join(lines, "\n")
	if utf8.RuneCountInString(text) > 600 {
		text = string([]rune(text)[:599]) + "…"
	}
	return text
}

func shortCommand(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if strings.Contains(a, " ") {
			a = "'" + a + "'"
		}
		parts[i] = a
	}
	joined := strings.Join(parts, " ")
	if utf8.RuneCountInString(joined) > 160 {
		joined = string([]rune(joined)[:157]) + "…"
	}
	return joined
}

// modify applies change to the store under the lock, re-reading it first; the store key must not have changed.
func (c *cmd) modify(expectKey []byte, change func(s *storeFile) error) error {
	path, err := storePath(c.p)
	if err != nil {
		return err
	}
	unlock, err := c.p.Lock(path + ".lock")
	if err != nil {
		return die(1, "touchenv: can't lock the store: %v", err)
	}
	defer unlock()
	s, err := loadStore(c.p)
	if err != nil {
		return err
	}
	if s == nil || string(s.StoreKey) != string(expectKey) {
		return die(1, "touchenv: the store changed while touchenv was asking; nothing was changed, try again")
	}
	if err := change(s); err != nil {
		return err
	}
	return s.save(c.p)
}

func (c *cmd) set(args []string) error {
	if len(args) != 1 || !validName(args[0]) {
		return die(2, "usage: touchenv set NAME  (NAME = env var style)")
	}
	if c.o.sync {
		return die(2, "touchenv: --sync isn't available on Windows: keys stay on this PC")
	}
	name := args[0]
	data, err := c.p.ReadSecret(c.env.Stdin, c.env.Stderr)
	if err != nil {
		return die(1, "touchenv: no input")
	}
	if len(data) == 0 {
		return die(1, "touchenv: empty secret, nothing stored")
	}
	defer wipe(data)
	s, err := openOrCreateStore(c.p, c.h)
	if err != nil {
		return err
	}
	if err := s.verify(c.h); err != nil {
		return err
	}
	_, existed := s.Secrets[name]
	if existed {
		if err := c.requireIntent(fmt.Sprintf(`touchenv set --intent "<why>" %s`, name)); err != nil {
			return err
		}
		if _, err := s.unlock(c.h, c.promptText(fmt.Sprintf("Allow %s to replace %s?", c.who().Name, name), "")); err != nil {
			return err
		}
	}
	sealed, err := SealSecret(s.storePublic, name, data)
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	if err := c.modify(s.StoreKey, func(st *storeFile) error {
		if !existed && st.Secrets[name] != nil { // saved meanwhile by another touchenv: replacing it must ask
			return die(1, "touchenv: %s was saved meanwhile by another touchenv; run this again to replace it", name)
		}
		st.Secrets[name] = sealed
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(c.env.Stdout, "stored %s (%d bytes)\n", name, len(data))
	return nil
}

// existing loads the store and checks every name is in it (no prompt).
func (c *cmd) existing(names []string) (*storeFile, error) {
	s, err := loadStore(c.p)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if s == nil || s.Secrets[name] == nil {
			return nil, die(1, "touchenv: no secret named %s", name)
		}
	}
	return s, nil
}

func (c *cmd) get(args []string) error {
	if len(args) != 1 {
		return die(2, "usage: touchenv get NAME")
	}
	if err := c.requireIntent(fmt.Sprintf(`touchenv get --intent "<why>" %s`, args[0])); err != nil {
		return err
	}
	s, err := c.existing(args)
	if err != nil {
		return err
	}
	key, err := s.unlock(c.h, c.promptText(fmt.Sprintf("Show %s %s in full?", c.who().Name, args[0]), ""))
	if err != nil {
		return err
	}
	value, err := OpenSecret(key, args[0], s.Secrets[args[0]])
	if err != nil {
		return die(1, "touchenv: %s can't be opened: the store was changed outside touchenv", args[0])
	}
	defer wipe(value)
	_, err = c.env.Stdout.Write(value)
	return err
}

func (c *cmd) rm(args []string) error {
	if len(args) != 1 {
		return die(2, "usage: touchenv rm NAME")
	}
	if err := c.requireIntent(fmt.Sprintf(`touchenv rm --intent "<why>" %s`, args[0])); err != nil {
		return err
	}
	s, err := c.existing(args)
	if err != nil {
		return err
	}
	if _, err := s.unlock(c.h, c.promptText(fmt.Sprintf("Allow %s to delete %s?", c.who().Name, args[0]), "")); err != nil {
		return err
	}
	if err := c.modify(s.StoreKey, func(st *storeFile) error { delete(st.Secrets, args[0]); return nil }); err != nil {
		return err
	}
	fmt.Fprintf(c.env.Stdout, "deleted %s\n", args[0])
	return nil
}

func (c *cmd) ls(args []string) error {
	if err := c.requireIntent(`touchenv ls --intent "<why>"`); err != nil {
		return err
	}
	// Names are not secret on Windows (they sit in the store file), so no prompt.
	s, err := loadStore(c.p)
	if err != nil || s == nil {
		return err
	}
	for _, name := range s.names() {
		fmt.Fprintln(c.env.Stdout, name)
	}
	return nil
}

// swiftSplit splits on the first ":" leaving out empty pieces, as Swift's split(separator:maxSplits: 1) does.
func swiftSplit(spec string) []string {
	trimmed := strings.TrimLeft(spec, ":")
	if trimmed == "" {
		return nil
	}
	i := strings.Index(trimmed, ":")
	if i < 0 {
		return []string{trimmed}
	}
	rest := trimmed[i+1:]
	if rest == "" {
		return []string{trimmed[:i]}
	}
	return []string{trimmed[:i], rest}
}

type spec struct {
	name string
	file bool
}

func (c *cmd) run(args []string) error {
	split := -1
	for i, a := range args {
		if a == "--" {
			split = i
			break
		}
	}
	if split <= 0 || split >= len(args)-1 {
		return die(2, "usage: touchenv run NAME[:file] ... -- command args...")
	}
	var specs []spec
	for _, s := range args[:split] {
		parts := swiftSplit(s)
		if len(parts) == 0 || !validName(parts[0]) || (len(parts) == 2 && parts[1] != "file") {
			return die(2, "touchenv: bad spec %s", s)
		}
		specs = append(specs, spec{parts[0], len(parts) == 2})
	}
	argv := args[split+1:]
	if err := c.requireIntent(fmt.Sprintf(`touchenv run --intent "<why>" %s -- %s`,
		strings.Join(args[:split], " "), shortCommand(argv))); err != nil {
		return err
	}
	var wanted, unique []string
	for _, s := range specs {
		wanted = append(wanted, s.name)
		if !slices.Contains(unique, s.name) {
			unique = append(unique, s.name)
		}
	}
	commandLine, err := c.p.CommandLine(argv)
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	if utf8.RuneCountInString(commandLine) > 2000 {
		commandLine = string([]rune(commandLine)[:1999]) + "…"
	}
	secrets := map[string][]byte{}
	defer func() {
		for _, v := range secrets {
			wipe(v)
		}
	}()
	// A grant or a 5-minute approval, if one covers this requester and every secret asked for.
	offerKeep := false
	if reply, err := c.askService(Request{Op: "get", Names: unique, Intent: c.o.intent}); err == nil {
		offerKeep = reply.OfferKeep
		if reply.OK && coversAll(reply.Secrets, unique) {
			secrets = reply.Secrets
		} else {
			wipeAll(reply.Secrets)
		}
	} else if !errors.Is(err, ErrNoService) {
		fmt.Fprintf(c.env.Stderr, "touchenv: %v; asking Windows Hello instead\n", err)
	}
	if len(secrets) == 0 {
		if err := c.readForRun(unique, commandLine, offerKeep, secrets); err != nil {
			return err
		}
	}

	environ := c.p.Environ()
	var cleanup func() error
	var dir string
	for _, sp := range specs {
		data := secrets[sp.name]
		var value string
		if sp.file {
			if cleanup == nil {
				c.p.SweepRunDirs()
				dir, cleanup, err = c.p.NewRunDir()
				if err != nil {
					return die(1, "touchenv: %v", err)
				}
			}
			path := filepath.Join(dir, sp.name)
			if err := c.p.WriteFilePrivate(path, data); err != nil {
				cleanup()
				return die(1, "touchenv: %v", err)
			}
			value = path
		} else {
			if !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
				if cleanup != nil {
					cleanup()
				}
				return die(1, "touchenv: %s is not text; use %s:file", sp.name, sp.name)
			}
			value = string(data)
		}
		environ = setEnv(environ, sp.name, value)
	}
	code, runErr := c.p.Run(argv, environ)
	if cleanup != nil {
		if err := cleanup(); err != nil {
			fmt.Fprintf(c.env.Stderr, "touchenv: couldn't delete %s (%v): delete it yourself; the next run tries again\n", dir, err)
		}
	}
	if runErr != nil {
		return die(1, "touchenv: %v", runErr)
	}
	return exitCode(code)
}

// setEnv replaces or adds NAME=value. Windows names are case-insensitive, so any spelling is replaced.
func setEnv(environ []string, name, value string) []string {
	out := environ[:0:0]
	for _, kv := range environ {
		if i := strings.Index(kv, "="); i > 0 && strings.EqualFold(kv[:i], name) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, name+"="+value)
}

type exportEntry struct {
	Name string `json:"name"`
	Sync bool   `json:"sync"`
	Data []byte `json:"data"` // base64, as touchenv.swift writes
}

type exportPayload struct {
	From    string        `json:"from"`
	Secrets []exportEntry `json:"secrets"`
}

func (c *cmd) export(args []string) error {
	for _, a := range args {
		if !validName(a) {
			return die(2, "usage: touchenv export --to tenv1:… [NAME ...] > keys.tenv  (tenv1:… comes from touchenv import --begin on the new machine)")
		}
	}
	if !c.o.hasTo {
		return die(2, "usage: touchenv export --to tenv1:… [NAME ...] > keys.tenv  (tenv1:… comes from touchenv import --begin on the new machine)")
	}
	recipient, err := ParseRecipient(c.o.recipient)
	if err != nil {
		return die(2, "touchenv: %s is not a tenv1:… key from touchenv import --begin", c.o.recipient)
	}
	if c.p.StdoutIsTerminal() {
		return die(2, "touchenv: send it to a file: touchenv export --to … > keys.tenv")
	}
	if err := c.requireIntent(`touchenv export --intent "<why>" --to tenv1:… > keys.tenv`); err != nil {
		return err
	}
	s, err := loadStore(c.p)
	if err != nil {
		return err
	}
	var names []string
	if len(args) > 0 {
		names = args
	} else if s != nil {
		names = s.names()
	}
	if len(names) == 0 {
		return die(1, "touchenv: no secrets to export")
	}
	if _, err := c.existing(names); err != nil {
		return err
	}
	code := CheckCode(recipient)
	what := "all your secrets"
	if len(args) > 0 {
		what = strings.Join(args, ", ")
	}
	// Every export asks; there is nothing that would let it skip the prompt.
	title := fmt.Sprintf("Allow %s to export %s to the machine showing %s? Only if your new machine shows that code.",
		c.who().Name, what, code)
	key, err := s.unlock(c.h, c.promptText(title, ""))
	if err != nil {
		return err
	}
	payload := exportPayload{From: c.p.Hostname()}
	for _, name := range names {
		value, err := OpenSecret(key, name, s.Secrets[name])
		if err != nil {
			return die(1, "touchenv: %s can't be opened: the store was changed outside touchenv", name)
		}
		payload.Secrets = append(payload.Secrets, exportEntry{Name: name, Data: value})
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	defer wipe(plain)
	for _, e := range payload.Secrets {
		wipe(e.Data)
	}
	file, err := SealExport(recipient, plain)
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	if _, err := c.env.Stdout.Write(file); err != nil {
		return die(1, "touchenv: %v", err)
	}
	count := fmt.Sprintf("%d secret%s", len(names), plural(len(names)))
	fmt.Fprintf(c.env.Stderr, "exported %s (%s) for the machine showing %s.\n"+
		"Copy the file there and run: touchenv import <file>. Then delete the file here too.\n",
		count, strings.Join(names, ", "), code)
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (c *cmd) importCmd(args []string) error {
	if c.o.begin {
		if len(args) != 0 {
			return die(2, "usage: touchenv import --begin")
		}
		return c.importBegin()
	}
	if len(args) != 1 {
		return die(2, "usage: touchenv import --begin · touchenv import [--replace] FILE")
	}
	path := args[0]
	if err := c.requireIntent(fmt.Sprintf(`touchenv import --intent "<why>" %s`, path)); err != nil {
		return err
	}
	file, err := os.ReadFile(path)
	if err != nil {
		return die(1, "touchenv: can't read %s", path)
	}
	madeFor, err := ExportRecipient(file)
	if err != nil {
		return die(1, "touchenv: %s is not a file from touchenv export", path)
	}
	s, err := loadStore(c.p)
	if err != nil {
		return err
	}
	if s == nil || s.Import == nil {
		return die(1, "touchenv: no import is waiting on this PC: run touchenv import --begin, then export again with the new tenv1:…")
	}
	pending := s.Import
	if c.env.Now().Sub(pending.Created) > importLifetime || c.env.Now().Before(pending.Created.Add(-time.Minute)) {
		_ = c.modify(s.StoreKey, func(st *storeFile) error { st.Import = nil; return nil })
		return die(1, "touchenv: the import waiting here expired (an hour): run touchenv import --begin again")
	}
	waiting, err := p256().NewPublicKey(pending.Public)
	if err != nil {
		return die(1, "touchenv: the import waiting here is damaged: run touchenv import --begin again")
	}
	if string(compress(madeFor)) != string(compress(waiting)) {
		return die(1, "touchenv: %s was made for the code %s; the import waiting here is %s", path, CheckCode(madeFor), CheckCode(waiting))
	}
	if err := s.verify(c.h); err != nil {
		return err
	}
	// The receiving key is kept encrypted to the Hello key, so opening the file is itself the approval.
	title := fmt.Sprintf("Allow %s to add the secrets in %s (made for %s) to this PC?", c.who().Name, filepath.Base(path), CheckCode(waiting))
	if err := c.h.Ready(); err != nil {
		return die(1, "touchenv: %v", err)
	}
	raw, err := c.h.Decrypt(c.promptText(title, ""), pending.Wrapped)
	if errors.Is(err, ErrCancelled) {
		return die(1, "touchenv: not approved")
	}
	if err != nil {
		return die(1, "touchenv: Windows Hello: %v", err)
	}
	receiving, err := p256().NewPrivateKey(raw)
	wipe(raw)
	if err != nil || string(receiving.PublicKey().Bytes()) != string(pending.Public) {
		return die(1, "touchenv: the import waiting here is damaged: run touchenv import --begin again")
	}
	plain, err := OpenExport(receiving, file)
	if err != nil {
		return die(1, "touchenv: %s can't be opened: damaged, or not made for this PC", path)
	}
	defer wipe(plain)
	var payload exportPayload
	if err := json.Unmarshal(plain, &payload); err != nil || payload.Secrets == nil {
		return die(1, "touchenv: %s holds no secrets", path)
	}
	from := payload.From
	if from == "" {
		from = "another machine"
	}
	type incoming struct {
		name string
		data []byte
	}
	var in []incoming
	for _, e := range payload.Secrets {
		if validName(e.Name) && e.Data != nil {
			in = append(in, incoming{e.Name, e.Data})
		}
	}
	if len(in) == 0 {
		return die(1, "touchenv: %s holds no secrets", path)
	}
	sealed := map[string][]byte{}
	var lines []string
	stored := 0
	for _, secret := range in {
		if s.Secrets[secret.name] != nil && !c.o.replace {
			lines = append(lines, fmt.Sprintf("skipped %s: already here (touchenv import --replace to overwrite)", secret.name))
			continue
		}
		box, err := SealSecret(s.storePublic, secret.name, secret.data)
		wipe(secret.data)
		if err != nil {
			return die(1, "touchenv: %v", err)
		}
		sealed[secret.name] = box
		stored++
		lines = append(lines, fmt.Sprintf("stored %s (%d bytes)", secret.name, len(secret.data)))
	}
	// One import per receiving key, and the file has done its job.
	if err := c.modify(s.StoreKey, func(st *storeFile) error {
		for name, box := range sealed {
			st.Secrets[name] = box
		}
		st.Import = nil
		return nil
	}); err != nil {
		return err
	}
	for _, line := range lines {
		fmt.Fprintln(c.env.Stdout, line)
	}
	if err := os.Remove(path); err != nil {
		fmt.Fprintf(c.env.Stdout, "couldn't delete %s (%v): delete it yourself\n", path, err)
	} else {
		fmt.Fprintf(c.env.Stdout, "deleted %s\n", path)
	}
	fmt.Fprintf(c.env.Stdout, "%d secret%s from %s. Now delete keys.tenv on %s too, and empty its Trash or Recycle Bin.\n",
		stored, plural(stored), from, from)
	return nil
}

func (c *cmd) importBegin() error {
	s, err := openOrCreateStore(c.p, c.h)
	if err != nil {
		return err
	}
	if err := s.verify(c.h); err != nil {
		return err
	}
	receiving, err := p256().GenerateKey(rand.Reader)
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	priv := receiving.Bytes()
	defer wipe(priv)
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, s.helloKey, priv)
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	pending := &pendingImport{Created: c.env.Now().UTC(), Public: receiving.PublicKey().Bytes(), Wrapped: wrapped}
	if err := c.modify(s.StoreKey, func(st *storeFile) error { st.Import = pending; return nil }); err != nil {
		return err
	}
	pub := receiving.PublicKey()
	fmt.Fprintf(c.env.Stdout, `Ready for one import, for the next hour. On the old machine, run:

  touchenv export --to %s > keys.tenv

Approve there only if its prompt shows %s.
Then bring keys.tenv here and run: touchenv import keys.tenv
`, RecipientText(pub), CheckCode(pub))
	return nil
}
