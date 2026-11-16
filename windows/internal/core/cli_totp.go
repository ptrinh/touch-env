package core

// touchenv totp and grant --totp: codes from an authenticator app approve a timed grant from afar. The service
// keeps the key behind the codes and the copies of the secrets allowed from afar, and checks every code (totp.go).

import (
	"bufio"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const totpUsage = `usage: touchenv totp setup [--max-for 12h] [--max-uses 100]   turn on approving timed grants with a code from an
                                                              authenticator app (Windows Hello; --max-…: the most
                                                              one code may approve, before setup)
       touchenv totp allow NAME ... · touchenv totp deny NAME ...   which secrets a code may grant (allow: Windows Hello)
       touchenv totp status · touchenv totp off · touchenv totp unlock`

// totpService sends one codes request, with the hints a refusal needs.
func (c *cmd) totpService(req Request) (Reply, error) {
	reply, err := c.askService(req)
	switch {
	case err == nil:
		return reply, nil
	case errors.Is(err, ErrNoService):
		return reply, die(1, "touchenv: codes are kept by the touchenv service, which isn't installed or isn't running.\n"+
			"  Install it once with: touchenv service install  (Windows asks for administrator approval).")
	case strings.Contains(err.Error(), "didn't understand the request"):
		return reply, die(1, "touchenv: the touchenv service on this PC is older than this touchenv.exe and doesn't know codes: "+
			"run touchenv service install again")
	}
	return reply, die(1, "touchenv: %v", err)
}

func (c *cmd) totp(args []string) error {
	if len(args) == 0 || (args[0] != "setup" && (c.o.totpMaxLength != 0 || c.o.totpMaxUses != 0)) {
		return die(2, "%s", totpUsage)
	}
	sub, names := args[0], args[1:]
	valid := true
	for _, n := range names {
		valid = valid && validName(n)
	}
	switch {
	case (sub == "allow" || sub == "deny") && len(names) > 0 && valid:
	case (sub == "setup" || sub == "status" || sub == "off" || sub == "unlock") && len(names) == 0:
	default:
		return die(2, "%s", totpUsage)
	}
	var wanted []string
	for _, n := range names {
		if !slices.Contains(wanted, n) {
			wanted = append(wanted, n)
		}
	}
	switch sub {
	case "status":
		return c.totpStatus()
	case "off":
		reply, err := c.totpService(Request{Op: "totp-off"})
		if err != nil {
			return err
		}
		if reply.Ended == 0 {
			fmt.Fprintln(c.env.Stdout, "codes were already off")
		} else {
			fmt.Fprintln(c.env.Stdout, "codes are off: the key and the copies kept for grants from afar are deleted from this PC. "+
				"Remove touchenv from your authenticator app too.")
		}
		return nil
	case "deny":
		reply, err := c.totpService(Request{Op: "totp-deny", Names: wanted})
		if err != nil {
			return err
		}
		fmt.Fprintf(c.env.Stdout, "%d of %s no longer allowed from afar: the copy is deleted\n", reply.Ended, strings.Join(wanted, ", "))
		return nil
	case "allow":
		return c.totpAllow(wanted)
	case "unlock":
		return c.totpUnlock()
	}
	return c.totpSetup()
}

func (c *cmd) totpStatus() error {
	reply, err := c.totpService(Request{Op: "totp-status"})
	if err != nil {
		return err
	}
	st := reply.TOTP
	if st == nil || !st.On {
		fmt.Fprintln(c.env.Stdout, "codes: off (touchenv totp setup turns them on: see docs/windows.md)")
		return nil
	}
	day := func(unix int64) string { return time.Unix(unix, 0).Local().Format("2 Jan 2006 15:04") }
	fmt.Fprintf(c.env.Stdout, "codes: on since %s\n", day(st.Created))
	fmt.Fprintf(c.env.Stdout, "a code approves: a timed grant of the secrets below, at most %s and %s\n",
		SpokenLength(time.Duration(st.MaxSeconds)*time.Second), Times(st.MaxUses))
	if len(st.Names) == 0 {
		fmt.Fprintln(c.env.Stdout, "allowed from afar: none yet (touchenv totp allow NAME ...)")
	} else {
		fmt.Fprintf(c.env.Stdout, "allowed from afar: %s\n", strings.Join(st.Names, ", "))
	}
	if st.LastUsed == 0 {
		fmt.Fprintln(c.env.Stdout, "last used: never")
	} else {
		fmt.Fprintf(c.env.Stdout, "last used: %s\n", day(st.LastUsed))
	}
	switch {
	case st.Locked:
		fmt.Fprintf(c.env.Stdout, "LOCKED after %d wrong codes in a row: touchenv totp unlock (Windows Hello)\n", totpTries)
	case st.Failures > 0 && st.Wait > 0:
		fmt.Fprintf(c.env.Stdout, "wrong codes in a row: %d of %d; next try in %d s\n", st.Failures, totpTries, st.Wait)
	case st.Failures > 0:
		fmt.Fprintf(c.env.Stdout, "wrong codes in a row: %d of %d\n", st.Failures, totpTries)
	}
	return nil
}

// groupKey writes the key in fours, for typing into an authenticator app.
func groupKey(key string) string {
	var parts []string
	for len(key) > 4 {
		parts = append(parts, key[:4])
		key = key[4:]
	}
	return strings.Join(append(parts, key), " ")
}

func (c *cmd) totpSetup() error {
	who := c.who()
	// The key must never pass through an AI assistant: it could then make codes of its own for good.
	if who.IsAgent {
		return die(1, "touchenv: %s can't set codes up: the key would pass through it. Run touchenv totp setup yourself, "+
			"in a terminal at the PC.", who.Name)
	}
	state, err := c.totpService(Request{Op: "totp-status"})
	if err != nil {
		return err
	}
	if err := c.h.Ready(); err != nil {
		return die(1, "touchenv: %v", err)
	}
	pub, err := c.h.PublicKey(false)
	if err != nil {
		return die(1, "touchenv: no Windows Hello key for touchenv yet: save a secret first (touchenv set NAME)")
	}
	maxLength, maxUses := c.o.totpMaxLength, c.o.totpMaxUses
	if maxLength == 0 {
		maxLength = TOTPDefaultLength
	}
	if maxUses == 0 {
		maxUses = TOTPDefaultUses
	}
	limits := fmt.Sprintf("at most %s and %s", SpokenLength(maxLength), Times(maxUses))
	replacing := state.TOTP != nil && state.TOTP.On
	seed := make([]byte, totpSeedSize)
	defer wipe(seed)
	if _, err := rand.Read(seed); err != nil {
		return die(1, "touchenv: no random bytes")
	}
	// In a window, never on the terminal: what is printed there stays in its scrollback and in logs.
	ok, err := c.svc.ShowKey("Approve timed grants with a code\n\n" +
		"In an authenticator app on your phone, add an account by typing a setup key (time-based, 6 digits):\n\n" +
		"    Account:  touchenv\n" +
		"    Key:  " + groupKey(Base32Encode(seed)) + "\n\n" +
		"A code from the app will then approve a timed grant of the secrets you allow from afar, " + limits + ", with nobody " +
		"at this PC.\n\nWhoever has this key can make codes: show it to no one, and to no AI assistant.\n\n" +
		"OK when the app shows a code; touchenv then asks for it in the terminal.")
	if err != nil {
		return die(1, "touchenv: can't show the key: %v", err)
	}
	cancelled := "codes stay off"
	if replacing {
		cancelled = "the key set up before still works"
	}
	if !ok {
		return die(1, "touchenv: cancelled; %s", cancelled)
	}
	in := bufio.NewReader(c.env.Stdin)
	confirmed := false
	for try := 0; try < 3 && !confirmed; try++ {
		fmt.Fprint(c.env.Stderr, "Code the app shows now: ")
		line, err := in.ReadString('\n')
		typed := strings.Join(strings.Fields(line), "")
		if typed == "" && err != nil {
			break
		}
		now := TOTPStep(c.env.Now())
		for _, step := range []int64{now - 1, now, now + 1} { // the phone's clock may be a little off at setup
			confirmed = confirmed || typed == TOTPCode(seed, step)
		}
		if !confirmed {
			fmt.Fprintln(c.env.Stderr, "That isn't the code for this key.")
		}
	}
	if !confirmed {
		return die(1, "touchenv: no right code typed; %s", cancelled)
	}
	title := fmt.Sprintf("Allow %s to turn on approving timed grants with a code from an authenticator app? A code then "+
		"approves a grant of the secrets you allow from afar, %s, with nobody at this PC.", who.Name, limits)
	if replacing {
		title += " The key set up before stops working."
	}
	at := c.env.Now().Unix()
	seconds := int(maxLength / time.Second)
	sig, err := c.h.Sign(c.promptText(title, ""), TOTPSignedDigest("setup", at, seed, seconds, maxUses))
	if errors.Is(err, ErrCancelled) {
		return die(1, "touchenv: not approved; %s", cancelled)
	}
	if err != nil {
		return die(1, "touchenv: Windows Hello: %v", err)
	}
	if _, err := c.totpService(Request{Op: "totp-setup", Secrets: map[string][]byte{seedName: seed}, Seconds: seconds,
		Uses: maxUses, At: at, Pub: x509.MarshalPKCS1PublicKey(pub), Sig: sig}); err != nil {
		return err
	}
	fmt.Fprintf(c.env.Stdout, "codes are on. Next, choose what a code may grant: touchenv totp allow NAME ...\n"+
		"Then, from afar: touchenv grant --totp CODE --for 8h --uses 20 NAME ...  (%s a grant)\n"+
		"touchenv totp status shows it; touchenv totp off ends it.\n", limits)
	return nil
}

func (c *cmd) totpUnlock() error {
	state, err := c.totpService(Request{Op: "totp-status"})
	if err != nil {
		return err
	}
	if state.TOTP == nil || !state.TOTP.On {
		return die(1, "touchenv: codes aren't set up (touchenv totp setup)")
	}
	if state.TOTP.Failures == 0 {
		fmt.Fprintln(c.env.Stdout, "codes aren't locked")
		return nil
	}
	if err := c.requireIntent(`touchenv totp --intent "<why>" unlock`); err != nil {
		return err
	}
	if err := c.h.Ready(); err != nil {
		return die(1, "touchenv: %v", err)
	}
	n := state.TOTP.Failures
	wrong := "codes were"
	if n == 1 {
		wrong = "code was"
	}
	title := fmt.Sprintf("Allow %s to take codes from the authenticator app again? %d wrong %s tried in a row.", c.who().Name, n, wrong)
	at := c.env.Now().Unix()
	sig, err := c.h.Sign(c.promptText(title, ""), TOTPSignedDigest("unlock", at, nil, 0, 0))
	if errors.Is(err, ErrCancelled) {
		return die(1, "touchenv: not approved; codes are still locked")
	}
	if err != nil {
		return die(1, "touchenv: Windows Hello: %v", err)
	}
	if _, err := c.totpService(Request{Op: "totp-unlock", At: at, Sig: sig}); err != nil {
		return err
	}
	fmt.Fprintln(c.env.Stdout, "codes are taken again")
	return nil
}

func (c *cmd) totpAllow(wanted []string) error {
	list := strings.Join(wanted, ", ")
	if err := c.requireIntent(fmt.Sprintf(`touchenv totp --intent "<why>" allow %s`, strings.Join(wanted, " "))); err != nil {
		return err
	}
	s, err := c.existing(wanted)
	if err != nil {
		return err
	}
	for _, name := range wanted {
		if s.SSHKeys[name] != "" {
			return die(1, "touchenv: %s is an SSH key: grants don't cover signatures on Windows", name)
		}
	}
	// Before Windows Hello: never ask for what couldn't be kept.
	state, err := c.totpService(Request{Op: "totp-status"})
	if err != nil {
		return err
	}
	if state.TOTP == nil || !state.TOTP.On {
		return die(1, "touchenv: codes aren't set up on this PC. First: touchenv totp setup")
	}
	title := fmt.Sprintf("Allow %s to let a code from your authenticator app grant %s from afar? The touchenv service keeps "+
		"a copy on this PC, outside Windows Hello, until touchenv totp deny.", c.who().Name, list)
	key, err := s.unlock(c.h, c.promptText(title, ""))
	if err != nil {
		return err
	}
	secrets := map[string][]byte{}
	defer wipeAll(secrets)
	for _, name := range wanted {
		value, err := OpenSecret(key, name, s.Secrets[name])
		if err != nil {
			return die(1, "touchenv: %s can't be opened: the store was changed outside touchenv", name)
		}
		secrets[name] = value
	}
	if _, err := c.totpService(Request{Op: "totp-allow", Secrets: secrets}); err != nil {
		return err
	}
	fmt.Fprintf(c.env.Stdout, "a code can now grant %s from afar: touchenv grant --totp CODE --for 8h --uses 20 %s\n"+
		"touchenv totp deny %s ends it.\n", list, strings.Join(wanted, " "), strings.Join(wanted, " "))
	return nil
}

// grantWithCode is grant --totp: no Windows Hello and no store key; the service checks the code and grants from
// the copies it keeps.
func (c *cmd) grantWithCode(wanted []string) error {
	who := c.who()
	if !who.Found {
		return die(1, "touchenv: can't tell which app is asking, so there is nothing to grant to")
	}
	if _, err := c.existing(wanted); err != nil {
		return err
	}
	reply, err := c.totpService(Request{Op: "totp-grant", Names: wanted, Seconds: int(c.o.length / time.Second),
		Uses: c.o.uses, Code: c.o.code})
	if err != nil {
		return err
	}
	name := reply.Who
	if name == "" {
		name = who.Name
	}
	until := c.env.Now().Add(c.o.length).Local().Format("15:04")
	fmt.Fprintf(c.env.Stdout, "%s and what it runs can read %s with touchenv run without asking: %s, until %s, "+
		"also while the PC is locked. touchenv lock ends it.\n", name, strings.Join(wanted, ", "), Times(c.o.uses), until)
	c.svc.StartTray()
	return nil
}

// tellCopies keeps the service's copies in step after set (the new value) or rm (value nil). Best effort: with no
// service, or codes off, there is nothing to tell.
func (c *cmd) tellCopies(name string, value []byte) {
	if c.svc == nil {
		return
	}
	if value == nil {
		if reply, err := c.askService(Request{Op: "totp-deny", Names: []string{name}}); err == nil && reply.Ended > 0 {
			fmt.Fprintf(c.env.Stdout, "deleted the copy of %s kept for grants from afar\n", name)
		}
		return
	}
	reply, err := c.askService(Request{Op: "totp-allow", Update: true, Secrets: map[string][]byte{name: value}})
	if err == nil && reply.Ended > 0 {
		fmt.Fprintf(c.env.Stdout, "updated the copy of %s kept for grants from afar\n", name)
	} else if err != nil && !errors.Is(err, ErrNoService) && !strings.Contains(err.Error(), "didn't understand") {
		fmt.Fprintf(c.env.Stderr, "touchenv: the copy of %s kept for grants from afar may be the old value (%v): "+
			"touchenv totp allow %s puts the new one there\n", name, err, name)
	}
}
