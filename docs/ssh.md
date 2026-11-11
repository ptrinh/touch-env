# SSH keys

How to keep SSH private keys behind Touch ID and sign with them for `ssh`, `git`, `scp` and `rsync`, without those
tools ever seeing the key. macOS only.

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
- **Not asking every time.** "Don't ask again for 5 minutes" is on the prompt, and timed grants cover signatures:
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
signature without your touch or a grant or 5-minute approval that covers it, and never the key. The app named in the
prompt is read from the processes (a program can call itself `ssh`); the server line is checked cryptographically.

## Loaded into ssh-agent for a while

```sh
touchenv ssh load --for 8h SSH_ID_ED25519    # one touch; 1 hour without --for, 24 hours at most
touchenv ssh unload SSH_ID_ED25519
```

The key goes to macOS's own `ssh-agent` (the one `SSH_AUTH_SOCK` names, checked to be Apple-signed) over its
socket, with a lifetime, as `ssh-add -t` would, but straight from memory: no file, no `ssh-add`. Until the time runs
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
