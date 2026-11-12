# Not being asked every time: approvals, grants, lock and --password

How to let reads through without a touch each time, for 5 minutes, for a while, or for one program, how to end
that, and how to approve with your Mac password in the terminal. macOS only, except where it says Windows.

| | Covers | Ends | Works with |
|---|---|---|---|
| 5-minute approval | the app that asked, for those keys | after 5 minutes, when the app quits, `lock` | `run` |
| Timed grant | the app you ran `grant` from, and what it runs | at the time (24 h at most) or after the uses, when the app quits, `lock`, logout | `run` |
| Standing grant | one script or signed program | when you revoke it, or at its own `--for` / `--uses` limit | `get`, `run` |

Other apps and other keys still ask. `export` always asks.

## For 5 minutes

Tick **Don't ask again for 5 minutes** on a `run` prompt (only `run` offers it; there is no flag, or an agent would
always pass one). For those 5 minutes any command from that same app (that Claude Code session, say) gets those
keys **without asking**, including one a booby-trapped page talked it into. Each use flashes a notice at the top
right; the menu bar shows the time left and **Lock Now**. It never covers other apps or other keys, and ends when
the app quits. Each key gets its own 5 minutes from the prompt that approved it: approving another key later doesn't
lengthen the first one's. Ticked on an SSH signing prompt, it covers signatures with that key only, never a
`touchenv run` or `get` of it. Don't tick it for the keys that matter most.

## While you step away: timed grants

Driving an agent from your phone or over SSH, you can't touch the sensor. Before you leave, allow what the task
needs:

```sh
touchenv grant --for 8h --uses 20 ASC_KEY OPENAI_API_KEY
```

One touch; the prompt spells out the keys and both limits (both are required). Then the app you ran it from (that
Claude Code session, or everything in that terminal app) and the commands it starts get those keys from
`touchenv run` without asking, **also while the Mac is locked**. It ends at the time (24 hours at most), after that
many runs (500 at most), on `touchenv lock` or **Lock Now**, when that app quits, or when you log out. `get` still
asks.

Until it ends, anything that app runs can take those keys, as with the 5-minute approval but for longer and with
nobody watching. Grants also cover SSH signatures (see [ssh.md](ssh.md)).

## One program, from now on: standing grants

Some programs read a secret over and over with nobody there: a helper script that hands Claude Code an MCP
server's token every time it connects, also from scheduled tasks. A timed grant runs out and belongs to the app
you made it in. A standing grant belongs to one program, with no end until you end it:

```sh
touchenv grant --always --for-program ~/.claude/mcp-trinh-headers.sh MCP_TRINH_AUTH
touchenv grant --always --for-program /Applications/Tool.app --for 90d --uses 10000 TOOL_KEY   # with limits
touchenv grant --list                        # every grant: program, secrets, made, last used, reads
touchenv grant --revoke ~/.claude/mcp-trinh-headers.sh       # no Touch ID
touchenv grant --revoke-all
```

One touch; the prompt names the program and the secrets and says this is from now on (`--for` up to 3650 days,
`--uses` up to 1,000,000, both optional). After that, when that program runs `touchenv get` or `touchenv run`, it
gets those secrets without a prompt, after a restart too, and **also while the Mac is locked** (once you have logged
in since it started). Named secrets only. A new grant for the same program replaces the old one. An AI agent still
has to give `--intent`, and every read is in the [access log](access-log.md).

**What counts as that program** is checked on every read, against the process that ran touchenv:

- **A shell script** (`#!/bin/sh`, bash, zsh, dash, ksh or csh, also through `#!/usr/bin/env`):
  - The process must be the Mac's own shell in `/bin`, its Apple signature checked, started on that file:
    `sh helper.sh`, `/full/path/helper.sh`, the script run directly, through a symbolic link, or with options like
    `-e`. Not `sh -c '…'`: those are someone else's commands.
  - The file must still have the SHA-256 it had when you made the grant.
  - It and every folder above it must be changeable only by you or root (a root-owned sticky folder like `/tmp` is
    fine), with no symbolic links on the way.
  - **Edit the script and the grant stops**: touchenv refuses outright, with no prompt, so an unattended run fails
    instead of waiting, and logs why. Make the grant again after you have checked the change.
  - Call touchenv from the script, not with `exec touchenv`. If the script `cd`s elsewhere before calling
    touchenv, start it by its full path.
- **A signed program or app**: its code signature, checked by macOS on the running process. Team and identifier
  for a Developer ID program, so its updates keep the grant; the exact build for an ad hoc signed one. The process
  must be the app's own executable, not a helper inside it.

A grant that expired or used up its uses is logged and then touchenv asks as usual.

It is not tied to the app that runs the program: scheduled tasks start it from `launchd`, Claude's app or the
`claude` CLI, not from the terminal where you made the grant, and a rule like that would stop the very runs it is
for.

**The check is on the process, by its id.** touchenv checks its parent process, and the parent is known by process
id and start time, which stay the same when a process replaces itself with another program. So a program running as
you can start a `touchenv get` that waits a moment, then turn itself into the granted script or program: by the
time touchenv looks, its parent *is* that program, and the read goes through. touchenv can't tell this apart, and
macOS gives it no way to: treat a standing grant as reachable by anything running as you, as below.

**What it does not stop.** Any program running as you can run that script or program and read what it prints, or
start the script's shell with code of its own slipped in, or use the trick above, and so get the secret. See
[security.md](security.md#standing-grants). Grant one program and the fewest secrets, and prefer a program that uses
the secret itself over one that prints it.

`touchenv set` of a granted secret updates the grant's copy; `touchenv rm` takes it out of the grant (a grant left
with no secret ends). Grants stay on this Mac: export and import don't carry them.

## Seeing and ending them

```sh
touchenv grant --list        # standing grants, timed grants and 5-minute approvals
touchenv lock                # ends every 5-minute approval and timed grant, and says which standing grants remain
touchenv lock --all          # ends standing grants too
```

**Lock Now** in the menu bar ends 5-minute approvals and timed grants and leaves standing grants on. The menu bar
icon shows only while a 5-minute approval or timed grant is on; its menu then also lists the standing grants.
Revoking needs no Touch ID: anything running as you can end a grant, which only means it asks again.

Right after an update from touchenv 1.7.2 or older, a background copy still running from before can't be used:
touchenv says so and asks for Touch ID instead. `touchenv lock` (or **Lock Now**) ends it.

## Typing the Mac password instead (synced secrets only)

Over ssh, or with the lid closed, there is no sensor to touch. For secrets synced through iCloud Keychain
(`set --sync`), `--password` takes your Mac password, typed in the terminal:

```sh
touchenv get --password --intent "deploy" API_KEY | pbcopy    # stdout carries only the secret
touchenv run --password API_KEY -- ./deploy.sh
touchenv grant --password --for 8h --uses 20 API_KEY          # timed or standing grants too
```

- touchenv first prints what you are approving on the terminal (who asks, which secrets, the intent, a grant's
  limits), then asks `Mac password for <you> (not shown):`.
- The password is read only from the terminal (`/dev/tty`), with echo off; echo comes back on however touchenv
  ends, Ctrl-C included. It is never taken from an argument, the environment or a pipe: with no terminal (an AI
  agent's shell, a script) `--password` is refused.
- With `run`, anything typed ahead is dropped before the command starts.
- A password approval never starts a 5-minute approval: each `--password` read asks again. Use
  `grant --password` to cover a while. A standing grant or a timed grant that already covers the read is used
  first, without asking.
- **Local secrets refuse it.** If any secret named is kept on this Mac only, the whole request is refused before
  the prompt, naming them. macOS itself locks those, and only Touch ID or the system's own password window can open
  them: it has no public way to take a password typed elsewhere. Ask again without `--password`.
- **Wrong passwords:** three tries per run. Each wrong one doubles the wait before the next (1 s, 2 s, 4 s … up to
  an hour), counted across runs, so a loop of `touchenv get --password` gets no faster. A right password clears the
  count. Your account's own lockout policy, if it has one, counts them too.
- An AI agent still has to give `--intent`.

How the password is checked and what it doesn't protect against: [security.md](security.md#typing-the-mac-password).
