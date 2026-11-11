# touch-env

**API keys behind your fingerprint: no app, script or AI agent reads them without your touch.**

<p align="center"><img src="docs/touch-id-prompt.png" width="260" alt="Touch ID prompt: Allow Claude Code to read OPENAI_API_KEY from your Keychain? INTENT: make the monthly sales report. More detail shows the command. Don't ask again for 5 minutes."></p>

## Why

Keys in `.env` files can be taken by anything that reads files: a hacked dev server, malware, or an AI agent tricked
by a web page. touch-env moves them into the Mac's Keychain. Each use shows **who** wants **which key** and **why**;
only your finger says yes.

## Install

macOS 13 or later:

```sh
brew install --cask ptrinh/tap/touchenv
```

Or unzip the app from [Releases](https://github.com/ptrinh/touch-env/releases/latest) into `~/Applications` and
link `touchenv.app/Contents/MacOS/touchenv` into your `PATH`.

## Use

```sh
touchenv set OPENAI_API_KEY                  # save (paste it; not shown)
touchenv set MY_KEY < AuthKey.p8             # save a key file
touchenv set --sync OPENAI_API_KEY           # save and sync to your other Macs (see below)
touchenv run OPENAI_API_KEY -- python report.py
touchenv run MY_KEY:file -- fastlane beta    # the command gets a temp file path, deleted afterwards
touchenv run --intent "monthly report" OPENAI_API_KEY -- python report.py   # shows why in the prompt
touchenv ls                                  # names only
touchenv get NAME · touchenv rm NAME
touchenv grant --for 8h --uses 20 MY_KEY     # one touch now, then no asking: for when you step away (below)
touchenv grant --always --for-program ~/bin/helper.sh MY_KEY   # one program, from now on (below)
touchenv grant --list                        # what is allowed without asking, and to whom
touchenv lock                                # end every 5-minute approval and timed grant now
touchenv log --summary                       # who read what, and how (below)
touchenv import --begin · touchenv export --to tenv1:… > keys.tenv · touchenv import keys.tenv   # new Mac, below
touchenv ssh add ~/.ssh/id_ed25519           # an SSH key, used through Touch ID (below)
```

Delete the original files after saving.

**AI assistants:** add to `CLAUDE.md` / `AGENTS.md`:

> My secrets are in touchenv. Never read key files. Use `touchenv run --intent "<why>" NAME -- <command>`.

Claude Code also needs `"touchenv *"` in `sandbox.excludedCommands`.

AI agents (Claude Code, Codex, Cursor's agent, Gemini CLI, aider, Goose, opencode) **must** pass `--intent`: without
one, touchenv refuses before any prompt and tells the agent how to ask again, so every prompt says why. Typed in
your own terminal, `--intent` is optional; without it the prompt says **No reason given** and shows the command.

## Stepping away

Driving an agent from your phone or over SSH, you can't touch the sensor. Before you leave, allow what the task
needs:

```sh
touchenv grant --for 8h --uses 20 ASC_KEY OPENAI_API_KEY
```

One touch, and the prompt spells out the keys and both limits. After that the app you ran it from (that Claude Code
session, or everything in that terminal app) and the commands it starts get those keys from `touchenv run` without
asking, **also while the Mac is locked**. It ends at the time (24 hours at most), after that many runs, on
`touchenv lock` or **Lock Now** in the menu bar, when that app quits, or when you log out (for a program that runs
unattended, use a standing grant instead, below). Other apps and other keys
still ask, and so do `get` and `export`.

Until it ends, anything that app runs can take those keys, as with the 5-minute approval but for longer and with
nobody watching. Grant the fewest keys, the shortest time and the fewest uses the task needs.

## One program, from now on (standing grants)

Some programs read a secret over and over with nobody there: a helper script that hands Claude Code an MCP
server's token every time it connects, also from scheduled tasks. A timed grant runs out and belongs to the app
you made it in. A standing grant belongs to one program instead, and has no end until you end it:

```sh
touchenv grant --always --for-program ~/.claude/mcp-trinh-headers.sh MCP_TRINH_AUTH
touchenv grant --always --for-program /Applications/Tool.app --for 90d --uses 10000 TOOL_KEY   # with limits
touchenv grant --list                        # every grant: program, secrets, made, last used, reads
touchenv grant --revoke ~/.claude/mcp-trinh-headers.sh · touchenv grant --revoke-all   # no Touch ID
```

One touch, and the prompt names the program and the secrets and says this is from now on. After that, when that
program runs `touchenv get` or `touchenv run`, it gets those secrets without a prompt, after a restart too, and
**also while the Mac is locked** (once you have logged in since it started). An AI agent still has to give
`--intent`. Every read is in the access log (below). Other programs, and other secrets, still ask.

**What counts as that program**, checked on every read against the process that ran touchenv:

- **A shell script** (`#!/bin/sh`, bash, zsh, dash, ksh or csh): the process must be the Mac's own shell (its Apple
  signature is checked) started on that file: `sh helper.sh`, `/full/path/helper.sh`, through a symbolic link, with
  options like `-e`; not `sh -c '…'`, which is someone else's commands. The file must still have the SHA-256 it had
  when you made the grant, and it and every folder above it must be changeable only by you (or root). **Edit the
  script and the grant stops**: touchenv refuses it outright (no prompt, so an unattended run fails rather than
  waits) and logs why. Make the grant again after you have checked the change. If the script `cd`s elsewhere
  before calling touchenv, start it by its full path.
- **A signed program or app**: its code signature, checked by macOS on the running process: team and identifier for
  a Developer ID program, so its updates keep the grant; the exact build for an ad hoc signed one. The process must
  be the app's own executable, not a helper inside it.

It is not tied to the app that runs the program: scheduled tasks start it from `launchd`, Claude's app or the
`claude` CLI, not from the terminal where you made the grant, and a rule like that would stop the very runs it is
for.

**What it does not stop.** Any program running as you can *run* that script or program and read what it prints, so
a standing grant for a helper that prints a token gives that token to anything that knows to run the helper. What
it does stop: a copied or stolen file (the secret isn't in it), programs that don't know about the helper, a changed
helper, and anything that only reads files. It is not a defence against malware aimed at you: a program that
starts the script's shell with exported shell functions (`BASH_FUNC_…`, which `/bin/sh` takes too) or `BASH_ENV`
runs its own code inside that shell, and gets the secret even when the script itself never prints it; macOS doesn't
let touchenv see a process's environment to spot that. Grant one program,
the fewest secrets, and prefer a program that uses the secret itself over one that prints it.

`touchenv lock` and **Lock Now** leave standing grants on (and say so); `touchenv lock --all` ends them too. The
menu bar icon, while it shows, lists them. `touchenv set` of a granted secret updates the grant's copy; `touchenv rm`
takes it out of the grant. Grants stay on this Mac: export and import don't carry them.

The grant and its copy of the secrets are one Keychain item (service `touchenv-standing`, this device only, readable
after first unlock) in touchenv's own access group: only the signed touchenv can make, read or change one; there is
no file another program could write to give itself a grant. Revoking needs no Touch ID: anything running as you can
end a grant, which only means it asks again.

## The access log

Every read of a secret by `get` and `run` is one line in `~/Library/Logs/touchenv-access-YYYY-MM.log`: the time,
the secret names, who asked (the app named in the prompt, and the calling program's path), the intent, and the
outcome: `touch-id` (Touch ID or the Mac's password), `5-minute`, `grant` (a timed grant), `standing-grant`,
`refused` (with why: no such secret, no `--intent`, a changed script, a signature that doesn't match…), `cancelled`,
or `failed` (a Keychain error). So are grants made, revoked and ended by `lock`, `set` and `rm`, `export` and
`import`. Never a value, any part of one, or its length.

```sh
touchenv log                                 # all of it, newest last
touchenv log --since 24h MCP_TRINH_AUTH      # one secret, the last day
touchenv log --summary                       # per secret: reads per outcome, and which programs ask most
```

Reading it needs no Touch ID. Entries are kept **two years** (730 days): files for months entirely older than that
are deleted and the oldest month is pruned line by line, checked at most once a day when touchenv writes. Within two
years nothing goes for size in normal use; all files together are capped at 64 MB, and past that the oldest entries
go first, with a line saying how many. The files are `0600` in a folder only you can write; the intent and every
other field lose control characters and are cut short, so a caller can't add or disguise a line. Like any file of
yours, any program running as you could edit it: it is your record, not proof against malware. The SSH agent keeps
its own log, `~/Library/Logs/touchenv-ssh-agent.log`, as before.

## SSH keys

SSH private keys without a passphrase sit in `~/.ssh` for anything to copy. touchenv keeps them behind Touch ID
instead, and signs for `ssh`, `git`, `scp` and `rsync` without them ever seeing the key.

```sh
touchenv ssh add ~/.ssh/id_ed25519           # stored as SSH_ID_ED25519, on this Mac only
touchenv ssh add --sync WORK ~/.ssh/work     # named WORK, synced to your other Macs (see --sync below)
touchenv ssh ls                              # names, types, fingerprints; no Touch ID
touchenv ssh rm SSH_ID_ED25519
```

- Any key file `ssh-keygen` reads: OpenSSH's, or the older PEM and PKCS#8 ones. If it has a passphrase, touchenv
  asks for it once (not shown) and keeps the key without one, behind Touch ID. For those files `/usr/bin/ssh-keygen`
  does the decrypting, on a copy in a private temp folder that is overwritten and removed straight after; the
  passphrase reaches it through a pipe, never an argument or a file.
- It signs with Ed25519, ECDSA (P-256, P-384, P-521) and RSA (`rsa-sha2-256`, `rsa-sha2-512`; not the SHA-1
  `ssh-rsa`, which OpenSSH itself turned off in 8.8). Security-key (`sk-`), DSA and certificate files are refused.
- **touchenv never deletes your key file.** After `add` it prints what to do next for this Mac: set up the agent,
  try it, and only then the `rm` command for the old file. Run in a terminal, it offers to do the setup there and
  then; it changes `~/.ssh/config` only if you say yes to a question that shows the lines, after a backup.
- The public half goes to `~/Library/Application Support/touchenv/ssh/NAME.pub`.

Then use them one of two ways.

### touchenv as your SSH agent (recommended)

```sh
touchenv ssh agent install --config          # without --config it prints the lines to add instead
```

That installs a LaunchAgent: launchd keeps the socket `~/Library/Application Support/touchenv/ssh-agent.sock` from
now on and at every login, and starts touchenv when ssh connects. `--config` adds to the end of `~/.ssh/config`
(a copy goes to `config.touchenv-backup` first):

```
Host *
    IdentityAgent "~/Library/Application Support/touchenv/ssh-agent.sock"
```

Then every signature asks: who (Claude Code, Terminal… and through what: `git`, `ssh`), which key in **bold**, and
the server. `ssh` tells the agent which server key it has already accepted, signed for that session
(`session-bind@openssh.com`, OpenSSH 8.9 and later; macOS has 10). touchenv checks that signature, refuses a login
for any other session, and looks the key up in your `known_hosts`: *Server: github.com, its key as in your
known_hosts*. The name comes from the ssh command line, the key from the server. When ssh sends nothing, the prompt
says the server is unknown. Commit signing (`gpg.format ssh`) reads *sign a git commit or tag*.

- **"Don't ask again for 5 minutes"** is on the prompt, and **grants** cover signatures:
  `touchenv grant --for 1h --uses 50 SSH_ID_ED25519` before a long deploy. One use per signature; an ssh
  connection or a `git fetch` normally signs once. Each silent use flashes the usual notice.
- **Locked screen, or a request through an SSH session to this Mac:** nobody can touch, so touchenv refuses at once
  (ssh says *agent refused operation*) unless a grant covers it. `touchenv ssh agent status` shows recent refusals
  and why.
- Requests at the same time wait their turn: one prompt at a time, four waiting at most.
- With several keys, offer each host only its own (ssh gives up after a few tries):

  ```
  Host github.com
      IdentityFile "~/Library/Application Support/touchenv/ssh/SSH_ID_ED25519.pub"
      IdentitiesOnly yes
  ```

- Clients can't add, remove or lock keys, and no client ever gets one.
- **What the socket protects.** It is `0600` in a `0700` folder: only programs running as you can connect.
  touchenv can't check who connects by code signature as it does for its own pieces (`ssh` is Apple's), so any
  program running as you can list your public keys and ask for a signature. Asking shows a prompt naming that
  program; it gets no signature without your touch or a grant or 5-minute approval that covers it, and never the
  key. The app named in the prompt is read from the processes (a program can call itself `ssh`); the server line
  is checked cryptographically.

### Loaded into ssh-agent for a while

```sh
touchenv ssh load --for 8h SSH_ID_ED25519    # one touch; 1 hour if --for is left out, 24 hours at most
touchenv ssh unload SSH_ID_ED25519
```

The key goes to macOS's own `ssh-agent` (the one `SSH_AUTH_SOCK` names, checked to be Apple-signed) over its socket,
with a lifetime, as `ssh-add -t` would, but straight from memory: no file, no `ssh-add`. Until the time runs out,
**any program running as you can have ssh-agent sign with it, without a prompt and without a notice**. What it
can't do is take the key away: the agent protocol has no way to read a key back, and ssh-agent refuses debuggers,
so getting it out of its memory takes root. With `ssh -A`, the servers you forward to can use it too.

Pick the agent for everyday use: each signature is seen and touched. Pick `load` for a long run of signatures
when grants don't fit, or for an app that reads only `SSH_AUTH_SOCK` and that you'd rather not point at touchenv's
socket.

### iCloud and undoing

`--sync` keys have the same weakness as other synced keys (the table below): every signature is gated by touchenv's
own prompt rather than by macOS's access control. That's why SSH keys stay on this Mac unless you ask.

To undo everything:

```sh
touchenv ssh agent uninstall --config        # stops the agent; removes exactly touchenv's lines from ~/.ssh/config
touchenv ssh unload SSH_ID_ED25519           # if you loaded it into ssh-agent
(umask 077; touchenv get SSH_ID_ED25519 > ~/.ssh/id_ed25519)   # the key file back, if you deleted it
touchenv ssh rm SSH_ID_ED25519
```

## Moving to a new Mac

Keys stay on the Mac they were saved on: Migration Assistant and Time Machine don't carry them. Move them with
touchenv itself, both Macs on 1.4.0 or later:

1. **New Mac:** `touchenv import --begin`. It prints a `tenv1:…` line and a check code like `K7QM-2XRD-9FTA`.
2. **Old Mac:** `touchenv export --to tenv1:… > keys.tenv` (add names to send only some). The `tenv1:…` line isn't
   secret: AirDrop, Universal Clipboard or a chat is fine. **Touch only if the prompt shows the same check code.**
3. Copy `keys.tenv` to the new Mac (AirDrop) and run `touchenv import keys.tenv`. One touch; then touchenv deletes
   the file. **Delete `keys.tenv` on the old Mac too**, and empty its Trash.

`--replace` overwrites keys the new Mac already has (otherwise they're skipped); `--local` keeps none synced.
SSH keys arrive as ordinary secrets: `touchenv run SSH_ID_ED25519:file -- touchenv ssh add SSH_KEY "$SSH_ID_ED25519"`
makes one an SSH key again under a new name (then `touchenv rm` the old one).

The file opens only on that Mac, once, within an hour: the key that opens it is made in the new Mac's Secure
Enclave and deleted after the import. A copy left behind is useless. The check code is what stops a tricked agent
exporting to someone else's key: the prompt names the receiving Mac's code, and only you can compare it.

## Good to know

- **Read before you touch.** An approved command can do anything with the key. The intent is written by the asker;
  check the command under **More detail**.
- **"Don't ask again for 5 minutes"** (for `run` only) saves touching for each step of one task. For those 5
  minutes, any command from that same app (that Claude Code session, say) gets those keys **without asking**,
  including one a booby-trapped page talked it into. Each use flashes a notice; the menu bar shows the time left and
  **Lock Now**. It never covers other apps or other keys, and ends when the app quits. Don't tick it for keys that
  matter most.
- **No Touch ID?** It asks for your Mac password.
- Old copies of a key (files, backups, shell history) are still yours to delete.
- **`--sync` is weaker.** iCloud Keychain won't take the Mac's own Touch ID lock, so only touchenv guards synced keys:

  | If… | Local key | Synced key |
  |---|---|---|
  | Malware runs as you | Safe | Safe |
  | Attacker has admin and disables SIP, or a macOS bug | Still needs your finger | **Readable** |
  | Another Mac on your Apple Account is hacked | Not there | **Exposed** |

  Keep signing keys and admin tokens local. SSH keys added with `touchenv ssh add --sync` are synced keys too: for
  them the Touch ID before each signature is touchenv's prompt, not macOS's lock, so the second and third rows apply.

## Windows

**Preview.** Builds and passes its tests, but the Windows Hello part, and grants through the touchenv service,
have not yet been tried on a real PC.

Windows 10 or 11, x64 or Arm, with Windows Hello set up (a PIN at least; fingerprint or face too if you like).
Download `touchenv-<version>-windows-x64.zip` (or `-arm64`) from
[Releases](https://github.com/ptrinh/touch-env/releases/latest), check it against the `.sha256` file
(`Get-FileHash touchenv-*.zip`), and put `touchenv.exe` in a folder on your `PATH`. The exe isn't code-signed yet,
so SmartScreen may warn the first time.

Same commands as on a Mac. Every read asks Windows Hello, and the Hello window shows touchenv's text: who asks,
which keys, the intent and the command. Differences:

- **No standing grants and no access log yet**: `touchenv grant --always`, `--list`, `--revoke` and `touchenv log`
  say they are macOS only.

- **Grants and "Don't ask again for 5 minutes" need the touchenv service**, installed once (below). Without it,
  `grant` is refused, `lock` says there's nothing to lock, and every `run` asks.
- **`touchenv status`** lists grants and approvals, and each use.
- **No `--sync`.** Keys stay on the PC they were saved on.
- **`ls` doesn't ask.** The names sit in the store file anyway.
- **Not over Remote Desktop, SSH or from a service.** touchenv refuses rather than ask where you can't answer.
- **No `touchenv ssh`** yet: the SSH agent and key commands are macOS only.
- **Moving keys** works the same way, and between a Mac and a PC in both directions (`import --begin` on the new
  one, `export --to` on the old one).

How it's kept: `%LOCALAPPDATA%\touchenv\store.json`, readable only by you. Each key is encrypted to a store key whose
private half is itself encrypted to an RSA key that Windows Hello holds (in the TPM when the PC has one) and that
touchenv makes with "ask on every use". A copy of the file is useless anywhere else.

### Grants on Windows

```sh
touchenv service install                     # once: Windows asks for administrator approval
touchenv grant --for 8h --uses 20 MY_KEY     # then as on a Mac
touchenv status · touchenv lock
```

The service runs as its own account, `NT SERVICE\touchenv`, from `C:\Program Files\touchenv`, and keeps grants in
its memory only. A grant ends at the time, after the last use, on `touchenv lock` (or **Lock Now** on its icon in the
notification area), when the app you granted quits, or when you log off. It goes on while the PC is locked; a
5-minute approval ends when you lock it. Each use shows a notification. Installing again (a new version) ends every
grant. `touchenv service uninstall` removes it all.

**What it can't do on Windows.** On a Mac only touchenv itself, signed, collects a grant, and only from under the app
you granted. Windows can't tell touchenv apart from another program running as you, and any program running as you
can start a process under that app or inject code into it. So **while a grant or approval is on, any program running
as you can get those keys**, up to the uses left. What the service does hold to, because programs running as you
can't read or change its memory:

- Every use counts, and is listed in `touchenv status`, which those programs can't erase.
- The time and the number of uses are kept, and `touchenv lock` ends it: after that nothing gets those keys from
  touchenv without Windows Hello. A key already handed out stays out: change it if you suspect anything.
- Other Windows accounts, other sessions and the network never get your grants.

It doesn't stand up to malware running as administrator (that can read the service's memory), and on an account
that is an administrator, malware running as you can usually get there: Microsoft doesn't count the UAC prompt as a
security boundary. Grant the fewest keys, the shortest time and the fewest uses the task needs.

**"Don't ask again for 5 minutes"** is off unless the service is installed with `touchenv service install
--offer-5-minutes`. Then each `run` first asks in a small box, No preselected; choose Yes and the Windows Hello
prompt says so, and that's what you approve. There's no flag for it, so an agent can't choose it for you (it could
press the button by script, but the Hello prompt would still say what you're approving).

Weaker than on a Mac:

| If… | Mac | Windows |
|---|---|---|
| Malware runs as you | Can't use touchenv's key | **Can ask Windows Hello to use it**, with its own prompt text: you'd see a prompt you didn't expect. It can also delete keys or replace one with its own value |
| Malware runs as admin | Still needs your finger | Not designed to stop it |
| The PC has no TPM | — | Windows Hello keeps the key in software |
| A grant is on and malware runs as you | Gets nothing: only touchenv, under the app you granted, collects it | **Gets those keys**, one use each time; each use is listed in `touchenv status` |
| A grant is on and malware runs as admin | Not designed to stop it | **Gets those keys** (reads the service's memory) |

So on Windows, **only touch for a prompt you were expecting**, and read who's asking. AI agents are recognised by
program name (`claude.exe`, `codex.exe`…); one that runs inside `node.exe` isn't, so it isn't made to give an intent.

## For developers

One Swift file, [`touchenv.swift`](touchenv.swift) (kept to one: with a second file Swift would want the commands in a
`main.swift`). Local keys: Data Protection keychain, `userPresence`,
`WhenUnlockedThisDeviceOnly`. Synced keys: `kSecAttrSynchronizable`, no access control (iCloud refuses one). Both
sit in an access group only the signed app holds. The prompt embeds `LAAuthenticationView` (no Allow button); the
Touch ID icon comes from macOS, with a copy in `Resources/`. 5-minute approvals live in memory in `touchenv agent`,
keyed by the requester's pid and start time (a grant also covers the processes below that requester), behind a `0600` Unix socket; each end checks that the other satisfies
touchenv's designated code requirement. Standing grants are Data Protection keychain items (service
`touchenv-standing`, account = the program's real path, `AfterFirstUnlockThisDeviceOnly`, no access control): the
record (JSON) in `kSecAttrGeneric`, the secrets' copy in the value, so listing never touches a value. The caller is
`getppid()`: a script is matched from the shell's arguments (`KERN_PROCARGS2`, trusted only from a shell that
satisfies `anchor apple`), its folder (`PROC_PIDVNODEPATHINFO`), `realpath`, SHA-256 and an `lstat` of every folder
up to `/`; a signed program with `SecCodeCheckValidity` against the recorded designated requirement; the pid's start
time is checked again after. `tests/standing-tests.swift` runs those checks on real shells (the grants kept in
memory, never the Keychain) and tests the access log.

SSH: the OpenSSH key format, the agent protocol and the RSA/ECDSA/Ed25519 signing are in the same file, on CryptoKit
and Security.framework, no other code. `tests/run.sh` compiles that file with `-D TOUCHENV_TESTS` (which leaves out
the command dispatch) plus `tests/ssh-tests.swift`, and checks it against OpenSSH's own tools: keys made by
`ssh-keygen`, signatures checked with `ssh-keygen -Y verify`, `ssh-add` and `ssh-keygen -Y sign` talking to the agent,
a throwaway `ssh-agent` for `load`; `tests/run.sh --sshd` adds real logins against a throwaway `sshd` on a high port.
None of it reads your keys, agent, config or Keychain.

Building needs a paid Apple Developer account: an App ID, a Developer ID provisioning profile, and the values in the
header of `build.sh` put in `build.local`. Then `./build.sh`. Your build can't read keys saved by the prebuilt app;
move them with `old run A:file -- sh -c 'touchenv set A < "$A"'`.

Windows: a Go module in [`windows/`](windows), standard library plus `golang.org/x/sys`. The Hello key is made with
CNG (`NCryptCreatePersistedKey` in the Microsoft Passport key storage provider, `NgcCacheType` = ask every time,
the prompt text from `NCRYPT_USE_CONTEXT_PROPERTY`); `internal/core` holds everything that isn't Windows and is
tested on any OS with a stand-in key. `cd windows && GOOS=windows GOARCH=amd64 go build -o touchenv.exe .` The same exe is the service
(`touchenv service run`, started by Windows): `internal/core/holder.go` is what it holds and how long, tested anywhere;
`internal/winplat/service_windows.go` is the named pipe (`\\.\pipe\touchenv`, interactive users only, the client
identified from its token and pid, never from what it says) and the process list.
Releases: publishing the GitHub release runs [`windows.yml`](.github/workflows/windows.yml), which attaches the
Windows zips. Both builds are checked against the same command-line cases: `conformance/run.sh path/to/touchenv`.
On a real PC, go through [`windows/MANUAL-TEST.md`](windows/MANUAL-TEST.md).

## License

MIT
