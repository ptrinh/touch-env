# touchenv on Windows

How to install and use the Windows build, how grants work there, and how it is weaker than on a Mac.

**Preview.** It builds and passes its tests, but the Windows Hello part, and grants through the touchenv service,
have not yet been tried on a real PC.

## Install

Windows 10 or 11, x64 or Arm, with Windows Hello set up (a PIN at least; fingerprint or face too if you like).
Download `touchenv-<version>-windows-x64.zip` (or `-arm64`) from
[Releases](https://github.com/ptrinh/touch-env/releases/latest), check it against the `.sha256` file
(`Get-FileHash touchenv-*.zip`), and put `touchenv.exe` in a folder on your `PATH`. The exe isn't code-signed yet,
so SmartScreen may warn the first time.

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

## Weaker than on a Mac

| If… | Mac | Windows |
|---|---|---|
| Malware runs as you | Can't use touchenv's key | **Can ask Windows Hello to use it**, with its own prompt text: you'd see a prompt you didn't expect. It can also delete keys or replace one with its own value |
| Malware runs as admin | Still needs your finger | Not designed to stop it |
| The PC has no TPM | — | Windows Hello keeps the key in software |
| A grant is on and malware runs as you | Gets nothing: only touchenv, under the app you granted, collects it | **Gets those keys**, one use each time; each use is listed in `touchenv status` |
| A grant is on and malware runs as admin | Not designed to stop it | **Gets those keys** (reads the service's memory) |

So on Windows, **only touch for a prompt you were expecting**, and read who's asking.

Testing on a real PC: [`windows/MANUAL-TEST.md`](../windows/MANUAL-TEST.md). Building: [building.md](building.md).
