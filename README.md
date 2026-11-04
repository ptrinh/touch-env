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

## License

MIT
