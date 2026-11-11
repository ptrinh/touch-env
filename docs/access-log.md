# The access log

What touchenv records about each read and change of a secret, how to read it, and how long it is kept. macOS only.

```sh
touchenv log                                 # all of it, newest last
touchenv log --since 24h MCP_TRINH_AUTH      # one secret, the last day (d, h or m)
touchenv log --summary                       # per secret: reads per outcome, and which programs ask most
touchenv log --help
```

Reading it needs no Touch ID.

## What a line holds

Each read attempt by `get` or `run` is one line, naming all the secrets asked for together: the time, the secret
names, who asked (the app named in the prompt, and the calling program's path: the script when a shell runs one),
the intent, and the outcome:

| Outcome | Meaning |
|---|---|
| `touch-id` | approved with Touch ID, or the Mac password in the system's window |
| `5-minute` | a "Don't ask again for 5 minutes" approval |
| `grant` | a timed grant |
| `standing-grant` | a standing grant |
| `password-cli` | the Mac password typed in the terminal (`--password`) |
| `refused` | with the reason: no such secret, no `--intent` from an agent, a changed script, a signature that doesn't match, a local secret with `--password`, no terminal, a wrong password (one line per try), too many wrong passwords… |
| `cancelled` | cancelled at the prompt, or no password typed |
| `failed` | a Keychain error, or the password couldn't be checked |

Also logged: grants made (timed and standing: which secrets, for whom, the limits), revoked, or ended by `lock` or
**Lock Now**; `set` and `rm`; `export` and `import`. Never a value, any part of one, or its length, and never a
password.

The SSH agent keeps its own log, `~/Library/Logs/touchenv-ssh-agent.log` (see [ssh.md](ssh.md)); its signatures are
not in this one.

## Where and how long

- Monthly files: `~/Library/Logs/touchenv-access-YYYY-MM.log`, tab-separated, `0600`, in a folder only you can
  write. touchenv won't write into a folder others can write to; it says so once on stderr instead.
- Entries are kept **two years** (730 days). Files for months entirely older than that are deleted, and the oldest
  month is pruned line by line. This is checked at most once a day, when touchenv writes; there is no background
  job.
- Within two years nothing goes for size in normal use. All files together are capped at 64 MB; past that, the
  oldest entries go first, with one line saying how many.
- The intent and every other field lose control characters and are cut short, so whoever asks can't add a line or
  disguise one.

Like any file of yours, any program running as you could edit or delete it: it is your record, not proof against
malware.
