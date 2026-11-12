# SSH keys

How to keep SSH private keys behind Touch ID and sign with them for `ssh`, `git`, `scp` and `rsync`, without those
tools ever seeing the key. Windows has the agent too, with Windows Hello: see [On Windows](#on-windows) at the end.

## Adding a key

```sh
touchenv ssh add ~/.ssh/id_ed25519           # stored as SSH_ID_ED25519, on this Mac only
touchenv ssh add --sync WORK ~/.ssh/work     # named WORK, synced to your other Macs (weaker: see below)
touchenv ssh ls                              # names, types, fingerprints; no Touch ID
touchenv ssh rm SSH_ID_ED25519
```

- Any key file `ssh-keygen` reads: OpenSSH's, or the older PEM and PKCS#8 ones. If it has a passphrase, touchenv
  asks for it once (not shown) and keeps the key without one, behind Touch ID. For those files
  `/usr/bin/ssh-keygen` does the decrypting, on a copy in a private temp folder that is overwritten and removed
  straight after; the passphrase reaches it through a pipe, never an argument or a file.
- It signs with Ed25519, ECDSA (P-256, P-384, P-521) and RSA (`rsa-sha2-256`, `rsa-sha2-512`; not the SHA-1
  `ssh-rsa`, which OpenSSH turned off in 8.8). Security-key (`sk-`), DSA and certificate files are refused.
- **touchenv never deletes your key file.** After `add` it prints the next steps for this Mac: set up the agent,
  try it, and only then the `rm` command for the old file. In a terminal it offers to do the setup there and then;
  it changes `~/.ssh/config` only if you say yes to a question that shows the lines, after a backup.
- The public half goes to `~/Library/Application Support/touchenv/ssh/NAME.pub`, so listing never asks.

Then use the key one of two ways.

## touchenv as your SSH agent (recommended)

```sh
touchenv ssh agent install --config          # without --config it prints the lines to add instead
touchenv ssh agent status                    # also shows recent refusals and why
```

That installs a LaunchAgent: launchd keeps the socket `~/Library/Application Support/touchenv/ssh-agent.sock`
from now on and at every login, and starts touchenv when ssh connects. `--config` adds these lines to the end of
`~/.ssh/config`, after copying it to `config.touchenv-backup`:

```
Host *
    IdentityAgent "~/Library/Application Support/touchenv/ssh-agent.sock"
```

Then every signature asks: who (Claude Code, Terminal… and through what: `git`, `ssh`), which key in **bold**, and
the server.

- **The server.** `ssh` tells the agent which server key it has accepted, signed for that session
  (`session-bind@openssh.com`, OpenSSH 8.9 and later; macOS has 10). touchenv checks that signature, refuses a
  login for any other session, and looks the key up in your `known_hosts`: *Server: github.com, its key as in your
  known_hosts*. The name comes from the ssh command line, the key from the server. When ssh sends nothing, the
  prompt says the server is unknown. Commit signing (`gpg.format ssh`) reads *sign a git commit or tag*.
- **Not asking every time.** "Don't ask again for 5 minutes" is on the prompt (it covers signatures only: a
  `touchenv run` of the key from the same app still asks), and timed grants cover signatures:
  `touchenv grant --for 1h --uses 50 SSH_ID_ED25519` before a long deploy. One use per signature; an ssh connection
  or a `git fetch` normally signs once. Each silent use flashes the usual notice. See [grants.md](grants.md).
- **Locked screen, or a request through an SSH session to this Mac:** nobody can touch, so touchenv refuses at
  once (ssh says *agent refused operation*) unless a grant covers it.
- Requests at the same time wait their turn: one prompt at a time, four waiting at most.
- With several keys, offer each host only its own (ssh gives up after a few tries):

  ```
  Host github.com
      IdentityFile "~/Library/Application Support/touchenv/ssh/SSH_ID_ED25519.pub"
      IdentitiesOnly yes
  ```

- Clients can't add, remove or lock keys, and no client ever gets one.
- The agent logs its refusals, and the signatures it made under a grant or 5-minute approval, to
  `~/Library/Logs/touchenv-ssh-agent.log`.

**What the socket protects.** It is `0600` in a `0700` folder: only programs running as you can connect. touchenv
can't check who connects by code signature as it does for its own pieces (`ssh` is Apple's), so any program running
as you can list your public keys and ask for a signature. Asking shows a prompt naming that program; it gets no
signature without your touch or a grant or 5-minute approval that covers it, and never the key: a 5-minute
approval given on a signing prompt covers only signatures, so `touchenv run` of that key from the same app asks
again. touchenv's SSH agent talks to touchenv's background copy over a socket whose messages are sealed with a key
only touchenv can read (see [security.md](security.md#what-a-touch-approves)). The app named in the
prompt is read from the processes (a program can call itself `ssh`); the server line is checked cryptographically.

## Loaded into ssh-agent for a while

```sh
touchenv ssh load --for 8h SSH_ID_ED25519    # one touch; 1 hour without --for, 24 hours at most
touchenv ssh unload SSH_ID_ED25519
```

The key goes to macOS's own `ssh-agent` over the socket `SSH_AUTH_SOCK` names, with a lifetime, as `ssh-add -t`
would, but straight from memory: no file, no `ssh-add`.

**Which ssh-agent.** Only the one launchd starts for macOS (`com.openssh.ssh-agent`, from
`/System/Library/LaunchAgents`, running `/usr/bin/ssh-agent`). touchenv first has the agent list its keys, then asks
the kernel which process served that connection and launchd which process is its ssh-agent: they must be the same
process. A code-signature check alone isn't enough here: the socket's folder belongs to you, so a program running
as you could put its own socket there, accept the connection, keep it open in a child process and turn itself into
Apple's `ssh-agent`; it would pass a signature check and its child would read the key. The process launchd started
was `ssh-agent` from its first instruction, and never hands a connection on, so that trick fails the check. An
`ssh-agent` you started yourself (`eval $(ssh-agent)`) is refused: touchenv can't tell it from a program posing as
one; use touchenv's own agent instead. If a macOS update changes what `launchctl print` shows, `load` refuses rather
than guesses.

Until the time runs
out, **any program running as you can have ssh-agent sign with it, without a prompt and without a notice**. It
can't take the key away: the agent protocol has no way to read a key back, and ssh-agent refuses debuggers, so
getting it out of its memory takes root. With `ssh -A`, the servers you forward to can use it too.

Pick the agent for everyday use: each signature is seen and touched. Pick `load` for a long run of signatures when
grants don't fit, or for an app that reads only `SSH_AUTH_SOCK` that you'd rather not point at touchenv's socket.

## Synced keys and undoing

`--sync` keys have the same weakness as other synced secrets: every signature is gated by touchenv's own prompt
rather than by macOS's lock (see [security.md](security.md)). That's why SSH keys stay on this Mac unless you ask.

To undo everything:

```sh
touchenv ssh agent uninstall --config        # stops the agent; removes exactly touchenv's lines from ~/.ssh/config
touchenv ssh unload SSH_ID_ED25519           # if you loaded it into ssh-agent
(umask 077; touchenv get SSH_ID_ED25519 > ~/.ssh/id_ed25519)   # the key file back, if you deleted it
touchenv ssh rm SSH_ID_ED25519
```

## On Windows

**Preview: built and tested with fakes and on CI, not yet tried with Windows Hello on a real PC.**

```powershell
touchenv ssh add $HOME\.ssh\id_ed25519       # stored as SSH_ID_ED25519, on this PC only
touchenv ssh agent install --config         # the agent, now and at every logon, and the lines in .ssh\config
ssh -T git@github.com                       # Windows Hello asks
```

- **The same as on a Mac:** which keys are accepted (a passphrase is asked once; touchenv keeps the key without one,
  behind Windows Hello), names, `.pub` files (in `%LOCALAPPDATA%\touchenv\ssh`), the prompt (who, through which
  tools, which key, the server checked against your `known_hosts`), refusing `ssh-rsa` (SHA-1), refusing at once when
  nobody can answer Windows Hello (a locked screen, Remote Desktop, an SSH session into the PC), one prompt at a time,
  and touchenv never deleting your key file.
- **The agent** is `touchenv ssh agent serve`, started at logon by a value under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and at once by `install`. It runs in your session and serves
  `\\.\pipe\touchenv-ssh-<your SID>`, which only your account (and SYSTEM) can open, never over the network. A
  console window may flash at logon while it starts. `touchenv ssh agent status` checks that what answers on the pipe
  is touchenv's agent (its program file and your account), and says so when it's something else. `--config` adds
  this to the end of `%USERPROFILE%\.ssh\config`, after copying it to `config.touchenv-backup` (if `config` is a link,
  the file it points to is changed, and keeps its permissions):

  ```
  Host *
      IdentityAgent "//./pipe/touchenv-ssh-<your SID>"
  ```

  (Forward slashes on purpose: ssh's config parser turns `\\` into `\`, so the usual `\\.\pipe\…` spelling never opens.)
  Programs that don't read `.ssh\config` (JetBrains IDEs, apps built on libgit2) need the environment variable
  instead: `setx SSH_AUTH_SOCK \\.\pipe\touchenv-ssh-<your SID>`.
- **Use Windows' own OpenSSH**, 8.9 or later (`ssh -V`; Windows 11 has it, Windows 10 may need the newer
  [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/releases)). Older ones don't tell the agent which
  server they reached, so the prompt says the server is unknown. The ssh that comes with Git for Windows can't reach
  the agent at all: `git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe`.

  Stop Windows' own `ssh-agent` service if you used it, and remove the keys you added to it (`ssh-add -D`): it keeps
  them in the registry, where any program running as you can have them used.
- **Every signature asks Windows Hello.** No grants or 5-minute approvals cover signatures on Windows, and there's no
  `ssh load`.
- **Weaker than on a Mac,** as everything on Windows is (see [windows.md](windows.md#weaker-than-on-a-mac)): any
  program running as you can ask Windows Hello for a signature with its own prompt text, so only touch for a prompt
  you expected. The agent never hands a key to a client, and never holds one: it runs for as long as you're logged
  on, so for each signature it starts `touchenv ssh agent sign`, a process of its own that asks Windows Hello, opens
  that one key, signs and exits. What Windows Hello unlocked (the store's key, the SSH key) is gone with it, as it is
  when `touchenv run` or `get` ends; a program reading the agent's memory finds public keys and requests only. Any
  program running as you can start that helper too, with its own text: that is the limit above, not a new one. The
  helper still signs only an ssh login or a git/SSHSIG signature, with a key you added, and only with a prompt whose
  first line says what is signed with which key.
- **A request nobody waits for any more is dropped:** if ssh is stopped (Ctrl-C, a cancelled `git fetch`) while its
  request waits its turn, there's no prompt for it. A prompt left unanswered for 3 minutes is closed and refused.
- Refusals and signatures are logged to `%LOCALAPPDATA%\touchenv\ssh-agent.log`; `touchenv ssh agent status` shows
  the latest.
- An SSH key moved with `export`/`import` (either way between a Mac and a PC) is an SSH key again on Windows:
  `touchenv ssh ls` lists it. (On a Mac it arrives as a plain secret: `touchenv get NAME` it into a file and
  `touchenv ssh add` that.)
- Undo: `touchenv ssh agent uninstall --config`, then `touchenv ssh rm NAME`.
