# What touchenv protects, and what it doesn't

The limits to know before trusting touchenv with a key: local versus synced secrets, approvals and grants,
standing grants, the typed password, the menu bar and the log. For Windows, see [windows.md](windows.md).

## Local and synced secrets

A secret saved without `--sync` is a Keychain item on this Mac only, with a `userPresence` lock: macOS itself asks
for Touch ID (or the Mac password, in its own window) on every read, whoever reads. A synced secret (`set --sync`,
`ssh add --sync`) can't carry that lock, because iCloud Keychain won't take one. Only the signed touchenv can read it,
and touchenv asks for Touch ID itself before every read: the gate is touchenv's code, not macOS's lock.

| If… | Local secret | Synced secret |
|---|---|---|
| Malware runs as you, and you approve nothing | Safe | Safe |
| Malware runs as you, and you approve a request or a grant is on | What you approved, for the command shown (see [the threat model](threat-model.md)) | Same |
| An attacker has admin and turns off SIP, or a macOS bug | Still needs your finger, unless it is in a standing grant | **Readable** |
| Another Mac on your Apple Account is hacked | Not there | **Exposed** |

Keep signing keys and admin tokens local. For synced SSH keys, the Touch ID before each signature is touchenv's
prompt, not macOS's lock, so the last two rows apply.

Both kinds sit in a keychain access group that only touchenv, signed with its team's entitlement, holds. Other
programs running as you can't read them.

## What a touch approves

- **Read before you touch.** An approved command can do anything with the key, including sending it elsewhere. The
  intent is written by whoever asks; check the command: its first lines are always shown, all of it under **More
  detail** (a very long one as its start and its end, with how many characters are left out between; control,
  bidi and other invisible characters shown as �). The app named in the prompt, and its icon, are read from the
  running processes: they tell you who asks, but a program could fake them. Inside tmux or screen the chain of
  processes ends at its server, so that is who asks: an approval or a grant there covers every window in it.
- **Switching sync.** `set NAME` on a synced secret, without `--sync`, takes it out of iCloud Keychain, and so off
  your other Macs; `set --sync` on a local one puts it there. The prompt says so; the new copy is stored before the
  old one is deleted.
- **5-minute approvals and timed grants** hand the key to anything that app runs, without asking, until they end:
  including a command a booby-trapped web page talked an agent into. Each use flashes a notice. They are kept only
  in the memory of touchenv's background copy, and only for processes under the app that was approved. Each key in a
  5-minute approval has its own 5 minutes: approving another key later doesn't lengthen it. A 5-minute approval
  given on an SSH signing prompt covers signatures only: `touchenv run` from that app still asks before handing out
  the key itself.
- **The background copy's socket.** Every message to and from touchenv's background copy is sealed (AES-GCM) with a
  random key kept in the Keychain in touchenv's access group (this device only, no Touch ID lock, so reading it never
  asks), which only the signed touchenv can read. A program running as you can connect to the socket, or put its own
  in its place, but can't read what is sent there or make a request the background copy will take: checking the
  code signature of the process at the other end alone isn't enough, because macOS describes whatever that process
  runs *now*, and a program can connect and then start touchenv in its place. Each request also carries the sender's
  process id, checked against the socket's, a time and a one-time number, so one can't be relayed through another
  process or replayed; each reply is sealed to its request. Anything that doesn't open is refused, and touchenv asks
  for Touch ID as if no approval existed.
- **SSH keys loaded into `ssh-agent`** (`touchenv ssh load`) sign for any program running as you, without a prompt
  or a notice, until the time runs out. touchenv hands the key only to the ssh-agent launchd runs for macOS
  (`com.openssh.ssh-agent`), recognised by the process serving the connection rather than by its signature alone.
  See [ssh.md](ssh.md#loaded-into-ssh-agent-for-a-while).

## Standing grants

A standing grant ([grants.md](grants.md#one-program-from-now-on-standing-grants)) lets one program read named
secrets without asking, also while the Mac is locked, until you revoke it.

- **Where it lives.** The grant and its copy of the secrets are one Keychain item (service `touchenv-standing`,
  this device only, readable after first unlock) in touchenv's access group. Only the signed touchenv can make,
  read or change one; there is no file another program could write to give itself a grant. The copy carries no
  Touch ID lock: that is what lets it be read unattended.
- **What it stops:** a copied or stolen file (the secret isn't in it), programs that don't know about the helper, a
  changed helper (refused and logged), and anything that only reads files.
- **What it doesn't stop.** Any program running as you can run the script or program and read what it prints, so a
  standing grant for a helper that prints a token gives that token to anything that knows to run the helper. A
  program can also start the script's shell with exported shell functions (`BASH_FUNC_…`, which `/bin/sh` takes
  too) or `BASH_ENV`; its own code then runs inside that shell and gets the secret, even when the script never
  prints it. touchenv does not check another process's environment to spot that. Between the shell reading
  the script and touchenv checking its hash, a program running as you could swap the file and put it back. And the
  program is recognised as the process that ran touchenv, by its process id: a program can start a `touchenv get`
  that waits a moment, then replace itself with the granted script or program (same process id, same start time),
  and the read then passes for that program's. It is not a defence against malware aimed at you.
- **Ending one** needs no Touch ID, so anything running as you can revoke a grant; that only means it asks again.

## Typing the Mac password

`--password` ([grants.md](grants.md#typing-the-mac-password-instead-synced-secrets-only)) approves a read or a grant of
synced secrets with the Mac password typed in the terminal.

- **Synced secrets only.** For those, touchenv's own check is the gate whether you use Touch ID or a password, so
  the password adds no way in that wasn't there. Local secrets stay behind Touch ID or the system's own window:
  macOS offers no public way to open them with a password typed elsewhere (`LAContext.setCredential` takes only an
  application password or a smart card PIN, not the account password).
- **Weaker than a fingerprint.** A password can be watched over your shoulder or caught by a keylogger; a
  fingerprint can't.
- **The check.** OpenDirectory checks the password of the account running touchenv (`ODRecord.verifyPassword` on
  your own record; touchenv takes no user name). Any error from it, such as a network account that can't be reached,
  refuses. As root, `--password` is refused.
- **The password in memory.** It is read from `/dev/tty` into a buffer touchenv allocates, and that buffer is wiped
  (`memset_s`) as soon as the check is done. OpenDirectory takes the password as a string object, and that copy
  can't be erased: it stays in touchenv's memory until it is freed, and touchenv exits soon after. The password is
  never put in an argument, the environment, a file or the log.
- **Guessing.** Wrong passwords are counted in a Keychain item in touchenv's access group, which other programs
  running as you can't reset; each one doubles the wait before the next try, across runs, up to an hour. If that
  count can't be read, no password is checked.

## Codes from an authenticator app

`grant --totp` ([grants.md](grants.md#from-afar-with-a-code-from-your-phone-synced-secrets-only)) approves a timed
grant of synced secrets with a six-digit code (RFC 6238: HMAC-SHA1, 30 seconds), with nobody at the Mac.

- **Synced secrets only**, as for `--password`: touchenv's own check is their gate either way. A local secret's
  lock is macOS's, and a code can't open it.
- **Weaker than a fingerprint, and than the password.** A fingerprint shows someone is at the Mac; a code shows
  someone has the phone, or the key. And the code passes through whoever runs the command: it is in the agent's
  conversation, on the command line and in the process list for a moment.
- **Not tied to the request.** The code is the same whatever grant it is spent on. Whoever is handed one, an agent
  misled by a web page included, picks the secrets, the time and the uses, among all synced secrets and up to the
  limits of setup (`--max-for`, `--max-uses`; 12 hours and 100 uses unless you chose less). Those limits and what
  you sync are the fence.
- **A race.** A program running as you that reads the code where the agent keeps its conversation can try to spend
  it first, on a grant for itself. A code works once, so yours then fails with "already used": treat that as an
  alarm (`touchenv lock`, then the access log). Such a program can also reach any grant the agent holds
  ([the threat model](threat-model.md)), so this adds little it did not have.
- **The key.** 20 random bytes, in one Keychain item in touchenv's access group with the limits and the counts:
  this device only, never synced, readable after first unlock, no Touch ID lock (codes must be checked with nobody
  there). Other programs running as you can't read it. An attacker with admin rights who turns off SIP can, and
  can then make codes; that attacker reads synced secrets directly anyway. The other copy is in your authenticator
  app: whoever has that phone unlocked, or a backup of the app, can make codes. `touchenv totp setup` again replaces
  the key; `touchenv totp off` deletes it.
- **Setup** asks for Touch ID and shows the key only in touchenv's window, which asks macOS to leave it out of
  screenshots, recordings and screen sharing (macOS decides whether every capture path honours that). It is
  refused for a recognised AI assistant. Never paste the key or the QR code anywhere.
- **Guessing.** A guess is right two times in a million. Wrong codes are counted in the same Keychain item (other
  programs can't reset it): each doubles the wait, and the fifth in a row locks codes until `touchenv totp unlock`
  with Touch ID. So any program running as you can lock codes on purpose with five wrong tries; you are then asked
  to come to the Mac, nothing is opened.
- **Once.** The step of the last accepted code is saved before the grant is made; nothing at or before it is
  accepted again, the code typed at setup included. If it can't be saved, nothing is approved.

## The menu bar and notices

The lock icon in the menu bar shows while a 5-minute approval or timed grant is on, with the time left and **Lock
Now**; its menu also lists standing grants. Each use of an approval or grant flashes a notice at the top right.
Standing-grant reads and `--password` reads show no notice: they are in the access log. A grant made with a code
shows in the menu bar like any timed grant, and each use of it flashes the notice.

## The log

The [access log](access-log.md) records every read and change, never a value or a password. Any program running as
you can edit or delete it: it is a record for you, not evidence against malware.
