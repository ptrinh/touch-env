# touchenv on Windows

How to install and use the Windows build, how grants work there, and how it is weaker than on a Mac.

**Beta.** Tried on a real PC with Windows Hello: saving and reading keys (`set`, `get`, `run`, `rm`), the
touchenv service with grants and 5-minute approvals, and the SSH agent. Moving keys with `export` / `import` has
only run in tests so far.

## Install

Windows 10 or 11, x64 or Arm, with Windows Hello set up (a PIN at least; fingerprint or face too if you like).
Download `touchenv-<version>-windows-x64.zip` (or `-arm64`) from
[Releases](https://github.com/ptrinh/touch-env/releases) (the newest release that has Windows zips; some releases are Mac-only), check it against the `.sha256` file
(`Get-FileHash touchenv-*.zip`), and put `touchenv.exe` in a folder on your `PATH`.

`touchenv.exe` is code-signed by **SENPRINTS LLC** (Microsoft's Trusted Signing), with a timestamp, from the
releases after 1.7.2 on (older zips aren't signed). To check it in PowerShell:

```powershell
Get-AuthenticodeSignature .\touchenv.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid` and the signer's subject start with `CN=SENPRINTS LLC`. The certificate is new, so
SmartScreen may still warn the first time until it has built a reputation; the signature is what to check.

## How it differs from the Mac

Same commands as on a Mac. Every read asks Windows Hello, and the Hello window shows touchenv's text: who asks,
which keys, the intent and the command. Differences:

- **Grants and "Don't ask again for 5 minutes" need the touchenv service**, installed once (below). Without it,
  `grant` is refused, `lock` says there's nothing to lock, and every `run` asks.
- **`touchenv status`** lists grants and approvals, and each use.
- **No `--sync`.** Keys stay on the PC they were saved on.
- **`ls` doesn't ask.** The names sit in the store file anyway.
- **Not over Remote Desktop, SSH, from a service or while the PC is locked.** touchenv refuses rather than ask
  where you can't answer.
- **SSH keys** (`touchenv ssh add`, `ls`, `rm`, `agent install`) work as on a Mac, with Windows Hello for every
  signature: see [ssh.md](ssh.md#on-windows). No grants or 5-minute approvals for signatures, and no
  `ssh load`/`unload`.
- **Grants from afar with a code from your phone** (`grant --totp`) work, with one more step than on a Mac: you
  choose which keys a code may grant ([below](#grants-from-afar-with-a-code-from-your-phone)).
- **macOS only for now:** standing grants (`grant --always`, `--list`, `--revoke`), the access log
  (`touchenv log`), `--password` and `touchenv ssh load`/`unload`. They exit with a message saying so.
- **Moving keys** works the same way, and between a Mac and a PC in both directions (`import --begin` on the new
  one, `export --to` on the old one; see [new-mac.md](new-mac.md)).
- AI agents are recognised by program name (`claude.exe`, `codex.exe`…); one that runs inside `node.exe` isn't, so
  it isn't made to give an intent.

**How it's kept:** `%LOCALAPPDATA%\touchenv\store.json`, readable only by you. Each key is encrypted to a store key
whose private half is itself encrypted to an RSA key that Windows Hello holds (in the TPM when the PC has one) and
that touchenv makes with "ask on every use". A copy of the file is useless anywhere else.

## Grants on Windows

```sh
touchenv service install                     # once: Windows asks for administrator approval
touchenv grant --for 8h --uses 20 MY_KEY     # then as on a Mac
touchenv status · touchenv lock
touchenv service uninstall                   # removes it all
```

The service runs as its own account, `NT SERVICE\touchenv`, from `C:\Program Files\touchenv`, and keeps grants in
its memory only. A grant ends at the time, after the last use, on `touchenv lock` (or **Lock Now** on its icon in
the notification area), when the app you granted quits, or when you log off. It goes on while the PC is locked; a
5-minute approval ends when you lock it. Each use shows a notification. Installing again (a new version) ends every
grant.

**"Don't ask again for 5 minutes"** is off unless the service is installed with
`touchenv service install --offer-5-minutes`. Then each `run` first asks in a small box, No preselected; choose Yes
and the Windows Hello prompt says so, and that is what you approve. There's no flag for it, so an agent can't choose
it for you (it could press the button by script, but the Hello prompt would still say what you're approving).

**What grants can't do on Windows.** On a Mac only touchenv itself, signed, collects a grant, and only from under
the app you granted. Windows can't tell touchenv apart from another program running as you, and any program running
as you can start a process under that app or inject code into it. So **while a grant or approval is on, any program
running as you can get those keys**, up to the uses left. What the service does hold to, because programs running
as you can't read or change its memory:

- Every use counts, and is listed in `touchenv status`, which those programs can't erase.
- The time and the number of uses are kept, and `touchenv lock` ends it: after that nothing gets those keys from
  touchenv without Windows Hello. A key already handed out stays out: change it if you suspect anything.
- Other Windows accounts, other sessions and the network never get your grants.

It doesn't stand up to malware running as administrator (that can read the service's memory), and on an account
that is an administrator, malware running as you can usually get there: Microsoft doesn't count the UAC prompt as a
security boundary. Grant the fewest keys, the shortest time and the fewest uses the task needs.

## Grants from afar with a code from your phone

A grant lasts a day at most, and Windows Hello can't be answered over Remote Desktop, SSH or with the PC locked.
Away for longer, driving an agent from your phone, you can approve the next grant with a six-digit code from an
authenticator app. Not yet tried on a real PC ([`windows/MANUAL-TEST.md`](../windows/MANUAL-TEST.md), steps 50 to
58).

Once, at the PC, yourself, in a terminal (the service must be installed):

```sh
touchenv totp setup --max-for 8h --max-uses 20   # the most one code may approve; 12 hours and 100 uses if left out
touchenv totp allow MY_KEY OTHER_KEY             # which keys a code may grant
```

`setup` shows a key in a window: add it to the app by typing it (time-based, 6 digits), type the code the app shows,
then approve with Windows Hello. The key is never printed in the terminal, and an AI assistant can't run `setup`: one
that saw the key could make its own codes for good. `allow` asks Windows Hello and hands the service a copy of those
keys.

Then, from afar, read the code to the agent, which runs:

```sh
touchenv grant --intent "deploy" --totp 123456 --for 8h --uses 20 MY_KEY
```

No Windows Hello is asked. The grant is the ordinary one (`touchenv status`, `touchenv lock`).

- **Only the keys you allowed**, and within the limits of setup. A refusal for either doesn't use the code up.
- **A code works once**, for the 30 seconds the app shows it and the 30 after. Keep the PC's clock set automatically.
- **Wrong codes** make the next try wait (2 s, 3 s, 5 s, 9 s); the fifth in a row locks codes until
  `touchenv totp unlock`, with Windows Hello at the PC.
- `touchenv totp status` shows the limits, the keys allowed, the last use and the wrong tries.
  `touchenv totp deny NAME` deletes one copy and `touchenv totp off` deletes the key and every copy; neither asks.
  `touchenv set` of an allowed key updates its copy and `touchenv rm` deletes it.

**What this gives up.** On Windows every key is sealed to Windows Hello. An allowed key also has a copy that isn't:

- **Where the copy is.** With the key behind the codes, in one file in the service account's own profile
  (`C:\Windows\ServiceProfiles\touchenv\AppData\Local\touchenv\codes.bin`), in a folder only that account,
  SYSTEM and administrators can open, encrypted to that account. It is still there after a restart;
  `touchenv service uninstall` removes it. Programs running as you can't read it. **Malware running as
  administrator can**, without Windows Hello and whether a grant is on or not. Allow only keys you would grant from
  afar anyway.
- **A code doesn't say what it approves.** You read six digits; the agent chooses the keys, the time and the uses,
  among the keys allowed and up to the limits of setup. An agent that a web page talked into something can ask you
  for a code and spend it on a wider grant than you meant. Keep the limits and the list of allowed keys short.
- **A code can be taken on the way.** It is in the agent's conversation and on the command line; a program running
  as you can try to spend it first. A code works once, so yours then fails with "already used": treat that as an
  alarm (`touchenv lock`, `touchenv status`).
- **What a program running as you can't do**, because the service checks it: read the key or the copies; make
  codes; put a key of its own behind the codes (setup and unlock must be signed by your Windows Hello key, which
  asks every time, and the first setup fixes which key that is); undo the count of wrong codes or use a code twice.
  It can lock codes on purpose with five wrong tries, which opens nothing.
- **A PC several people use.** Each Windows account has its own codes and its own allowed keys.

## Weaker than on a Mac

| If… | Mac | Windows |
|---|---|---|
| Malware runs as you | Can't use touchenv's key | **Can ask Windows Hello to use it**, with its own prompt text: you'd see a prompt you didn't expect. It can also delete keys or replace one with its own value |
| Malware runs as admin | Still needs your finger | Not designed to stop it |
| The PC has no TPM | — | Windows Hello keeps the key in software |
| A grant is on and malware runs as you | Gets nothing unless it gets a process started under the app you granted (a new terminal tab, a tmux window), which then collects it | **Gets those keys**, one use each time; each use is listed in `touchenv status` |
| A grant is on and malware runs as admin | Not designed to stop it | **Gets those keys** (reads the service's memory) |
| Keys can be granted with a code from afar | Synced keys only; an admin who turns off SIP reads those anyway | The keys you allowed: **malware running as admin reads their copies at any time** |

So on Windows, **only touch for a prompt you were expecting**, and read who's asking.

Testing on a real PC: [`windows/MANUAL-TEST.md`](../windows/MANUAL-TEST.md). Building: [building.md](building.md).
