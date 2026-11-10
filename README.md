# touch-env

**API keys behind your fingerprint: no app, script or AI agent reads them without your touch.**

<p align="center"><img src="docs/touch-id-prompt.png" width="260" alt="Touch ID prompt: Allow Claude Code to read OPENAI_API_KEY from your Keychain? Intent: make the monthly sales report. More detail shows the command. Don't ask again for 5 minutes."></p>

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
touchenv lock                                # end every 5-minute approval now
touchenv import --begin · touchenv export --to tenv1:… > keys.tenv · touchenv import keys.tenv   # new Mac, below
```

Delete the original files after saving.

**AI assistants:** add to `CLAUDE.md` / `AGENTS.md`:

> My secrets are in touchenv. Never read key files. Use `touchenv run --intent "<why>" NAME -- <command>`.

Claude Code also needs `"touchenv *"` in `sandbox.excludedCommands`.

AI agents (Claude Code, Codex, Cursor's agent, Gemini CLI, aider, Goose, opencode) **must** pass `--intent`: without
one, touchenv refuses before any prompt and tells the agent how to ask again, so every prompt says why. Typed in
your own terminal, `--intent` is optional; without it the prompt says **No reason given** and shows the command.

## Moving to a new Mac

Keys stay on the Mac they were saved on: Migration Assistant and Time Machine don't carry them. Move them with
touchenv itself, both Macs on 1.4.0 or later:

1. **New Mac:** `touchenv import --begin`. It prints a `tenv1:…` line and a check code like `K7QM-2XRD-9FTA`.
2. **Old Mac:** `touchenv export --to tenv1:… > keys.tenv` (add names to send only some). The `tenv1:…` line isn't
   secret: AirDrop, Universal Clipboard or a chat is fine. **Touch only if the prompt shows the same check code.**
3. Copy `keys.tenv` to the new Mac (AirDrop) and run `touchenv import keys.tenv`. One touch; then touchenv deletes
   the file. **Delete `keys.tenv` on the old Mac too**, and empty its Trash.

`--replace` overwrites keys the new Mac already has (otherwise they're skipped); `--local` keeps none synced.

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

  Keep signing keys and admin tokens local.

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

- **Grants and "Don't ask again for 5 minutes" need the touchenv service**, installed once (below). Without it,
  `grant` is refused, `lock` says there's nothing to lock, and every `run` asks.
- **`touchenv status`** lists grants and approvals, and each use.
- **No `--sync`.** Keys stay on the PC they were saved on.
- **`ls` doesn't ask.** The names sit in the store file anyway.
- **Not over Remote Desktop, SSH or from a service.** touchenv refuses rather than ask where you can't answer.
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

One Swift file, [`touchenv.swift`](touchenv.swift). Local keys: Data Protection keychain, `userPresence`,
`WhenUnlockedThisDeviceOnly`. Synced keys: `kSecAttrSynchronizable`, no access control (iCloud refuses one). Both
sit in an access group only the signed app holds. The prompt embeds `LAAuthenticationView` (no Allow button); the
Touch ID icon comes from macOS, with a copy in `Resources/`. 5-minute approvals live in memory in `touchenv agent`,
keyed by the requester's pid and start time, behind a `0600` Unix socket; each end checks that the other satisfies
touchenv's designated code requirement.

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
