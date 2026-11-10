package core

// grant, lock, status, service, and run's "Don't ask again for 5 minutes": everything that goes through the touchenv
// service. Without the service, grant is refused, lock and status say there is nothing, and run asks Windows Hello
// every time, as before.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// askService sends one request. ErrNoService when there is no service; a HoldError when the service refused.
func (c *cmd) askService(req Request) (Reply, error) {
	if c.svc == nil {
		return Reply{}, ErrNoService
	}
	conn, err := c.svc.Dial()
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	reply, err := Ask(conn, req)
	if err != nil {
		wipeAll(reply.Secrets)
		return Reply{}, fmt.Errorf("the touchenv service didn't answer properly: %v", err)
	}
	if !reply.OK && reply.Error != "" {
		wipeAll(reply.Secrets)
		return reply, HoldError(reply.Error)
	}
	return reply, nil
}

func coversAll(secrets map[string][]byte, names []string) bool {
	for _, n := range names {
		if len(secrets[n]) == 0 {
			return false
		}
	}
	return len(names) > 0
}

// readForRun reads names with Windows Hello for run, first offering "Don't ask again for 5 minutes" when the service
// offers it. Windows Hello's own dialog has no place for a choice, so touchenv asks in its own dialog first, with No
// as the default; the choice is then spelled out in the Windows Hello prompt, which is what approves it. There is no
// flag for it: an agent would always pass one.
func (c *cmd) readForRun(names []string, commandLine string, offerKeep bool, into map[string][]byte) error {
	s, err := c.existing(names)
	if err != nil {
		return err
	}
	who := c.who()
	list := strings.Join(names, ", ")
	keep := false
	if offerKeep && who.Found && c.svc != nil && c.h.Ready() == nil {
		var q strings.Builder
		fmt.Fprintf(&q, "%s wants to read %s.\n", who.Name, list)
		if c.o.hasIntent {
			fmt.Fprintf(&q, "Intent: %s\n", c.o.intent)
		}
		fmt.Fprintf(&q, "\nDon't ask again for 5 minutes?\n\n"+
			"Yes: Windows Hello asks now. Then for 5 minutes %s gets %s without asking, and so could any other "+
			"program running as you.\nNo: just this once.\nCancel: don't run it.", who.Name, list)
		proceed, k, err := c.svc.AskKeep(q.String())
		if err == nil {
			if !proceed {
				return die(1, "touchenv: not approved")
			}
			keep = k
		}
	}
	title := fmt.Sprintf("Allow %s to read %s?", who.Name, list)
	if keep {
		title = fmt.Sprintf("Allow %s to read %s, and again without asking for the next 5 minutes? "+
			"For those 5 minutes any program running as you can get %s too.", who.Name, list, list)
	}
	key, err := s.unlock(c.h, c.promptText(title, commandLine))
	if err != nil {
		return err
	}
	for _, name := range names {
		value, err := OpenSecret(key, name, s.Secrets[name])
		if err != nil {
			return die(1, "touchenv: %s can't be opened: the store was changed outside touchenv", name)
		}
		into[name] = value
	}
	if keep {
		if reply, err := c.askService(Request{Op: "approve", Secrets: into}); err != nil || !reply.OK {
			fmt.Fprintln(c.env.Stderr, "touchenv: couldn't keep the approval; next time asks again")
		} else {
			c.svc.StartTray()
		}
	}
	return nil
}

func (c *cmd) noService(err error) error {
	if err == ErrNoService {
		return die(1, "touchenv: grants on Windows are kept by the touchenv service, which isn't installed or isn't running.\n"+
			"  Install it once with: touchenv service install  (Windows asks for administrator approval). Nothing was allowed.")
	}
	return die(1, "touchenv: %v. Nothing was allowed.", err)
}

func (c *cmd) grant(args []string) error {
	valid := len(args) > 0
	for _, a := range args {
		valid = valid && validName(a)
	}
	if c.o.length == 0 || c.o.uses == 0 || !valid {
		return die(2, "usage: touchenv grant --for 8h --uses 20 NAME [NAME2 ...]  (both limits are required; 24h at most)")
	}
	var wanted []string
	for _, a := range args {
		if !slices.Contains(wanted, a) {
			wanted = append(wanted, a)
		}
	}
	list := strings.Join(wanted, ", ")
	if err := c.requireIntent(fmt.Sprintf(`touchenv grant --intent "<why>" --for %s --uses %d %s`,
		c.o.lengthArg, c.o.uses, strings.Join(wanted, " "))); err != nil {
		return err
	}
	who := c.who()
	// The grant covers the requester and what it runs, so there must be one to name.
	if !who.Found {
		return die(1, "touchenv: can't tell which app is asking, so there is nothing to grant to")
	}
	s, err := c.existing(wanted)
	if err != nil {
		return err
	}
	// Before Windows Hello: never ask for a grant that couldn't be kept.
	if _, err := c.askService(Request{Op: "status"}); err != nil {
		return c.noService(err)
	}
	limits := fmt.Sprintf("for %s, up to %s", SpokenLength(c.o.length), Times(c.o.uses))
	title := fmt.Sprintf("Allow %s and what it runs to read %s without asking, %s? It stays on while the PC is locked. "+
		"Until it ends, any program running as you can get %s too.", who.Name, list, limits, list)
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
	reply, err := c.askService(Request{Op: "allow", Secrets: secrets, Seconds: int(c.o.length / time.Second), Uses: c.o.uses})
	if err != nil || !reply.OK {
		reason := ""
		if err != nil {
			reason = " (" + err.Error() + ")"
		}
		return die(1, "touchenv: couldn't start the grant; nothing was allowed%s", reason)
	}
	name := reply.Who
	if name == "" {
		name = who.Name
	}
	until := c.env.Now().Add(c.o.length).Local().Format("15:04")
	fmt.Fprintf(c.env.Stdout, "%s and what it runs can read %s with touchenv run without asking: %s, until %s, "+
		"also while the PC is locked. touchenv lock ends it.\n", name, list, Times(c.o.uses), until)
	c.svc.StartTray()
	return nil
}

func (c *cmd) lock(_ []string) error {
	_, err := c.askService(Request{Op: "lock"})
	switch {
	case err == nil:
		fmt.Fprintln(c.env.Stdout, "locked: every approval and grant ended")
	case errors.Is(err, ErrNoService):
		fmt.Fprintln(c.env.Stdout, "nothing to lock")
	default:
		return die(1, "touchenv: %v", err)
	}
	return nil
}

func (c *cmd) status(args []string) error {
	if len(args) != 0 {
		return die(2, "usage: touchenv status")
	}
	reply, err := c.askService(Request{Op: "status"})
	if err == ErrNoService {
		fmt.Fprintln(c.env.Stdout, "no touchenv service on this PC, so no grants or 5-minute approvals (touchenv service install sets it up)")
		return nil
	}
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	keep := "5-minute approvals: off"
	if reply.OfferKeep {
		keep = "5-minute approvals: offered"
	}
	fmt.Fprintf(c.env.Stdout, "touchenv service %s, running. %s.\n", reply.Version, keep)
	if len(reply.Items) == 0 {
		fmt.Fprintln(c.env.Stdout, "nothing active")
	}
	for _, it := range reply.Items {
		names := strings.Join(it.Names, ", ")
		if it.Grant {
			fmt.Fprintf(c.env.Stdout, "%s and what it runs can read %s without asking: %s, %s left (session %d)\n",
				it.Who, names, Times(it.Uses), Clock(it.Left), it.Session)
		} else {
			fmt.Fprintf(c.env.Stdout, "%s can read %s without asking for %s more (session %d)\n", it.Who, names, Clock(it.Left), it.Session)
		}
		for _, u := range it.Used {
			line := fmt.Sprintf("  %s  %s read %s (touchenv pid %d)", u.At.Local().Format("15:04:05"), u.By, strings.Join(u.Names, ", "), u.PID)
			if u.Intent != "" {
				line += "  Intent: " + u.Intent
			}
			fmt.Fprintln(c.env.Stdout, line)
		}
	}
	return nil
}

func (c *cmd) service(args []string) error {
	const usage = "usage: touchenv service install [--offer-5-minutes] · touchenv service uninstall"
	install, offer := false, false
	switch {
	case len(args) == 1 && args[0] == "install":
		install = true
	case len(args) == 2 && args[0] == "install" && args[1] == "--offer-5-minutes":
		install, offer = true, true
	case len(args) == 1 && args[0] == "uninstall":
	default:
		return die(2, usage)
	}
	if c.svc == nil {
		return die(1, "touchenv: the touchenv service is Windows only")
	}
	var err error
	if install {
		err = c.svc.Install(offer, c.env.Stdout)
	} else {
		err = c.svc.Uninstall(c.env.Stdout)
	}
	if err != nil {
		return die(1, "touchenv: %v", err)
	}
	return nil
}
