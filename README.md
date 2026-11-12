# touch-env

**API keys behind your fingerprint: no app, script or AI agent reads them without your touch.**

<p align="center"><img src="docs/touch-id-prompt.png" width="260" alt="Touch ID prompt: Allow Claude Code to read OPENAI_API_KEY from your Keychain? INTENT: make the monthly sales report. More detail shows the command. Don't ask again for 5 minutes."></p>

Keys in `.env` files can be taken by anything that reads files: a hacked dev server, malware, or an AI agent tricked
by a web page. touchenv keeps them in the Mac's Keychain instead. Each use shows **who** wants **which key** and
**why**, and only your finger says yes.

## Install

macOS 13 or later:

```sh
brew install --cask ptrinh/tap/touchenv
```

Or unzip the app from [Releases](https://github.com/ptrinh/touch-env/releases/latest) into `~/Applications` and
link `touchenv.app/Contents/MacOS/touchenv` into your `PATH`. Windows (preview): see [docs/windows.md](docs/windows.md).

## Everyday use

```sh
touchenv set OPENAI_API_KEY                  # save: paste it, it isn't shown
touchenv set MY_KEY < AuthKey.p8             # save a key file
touchenv set --sync OPENAI_API_KEY           # save and sync to your other Macs (weaker: see below)
touchenv run OPENAI_API_KEY -- python report.py      # the command gets it in $OPENAI_API_KEY
touchenv run MY_KEY:file -- fastlane beta    # the command gets a private temp file's path, deleted afterwards
touchenv get NAME                            # print it
touchenv ls                                  # names only; "(iCloud)" marks synced ones
touchenv rm NAME
```

Delete the original files after saving. Old copies (backups, shell history) are still yours to delete.

`--intent "why"` after the command puts a reason in the prompt: `touchenv run --intent "monthly report" KEY -- …`.
AI agents (Claude Code, Codex, Cursor's agent, Gemini CLI, aider, Goose, opencode) **must** give one: without it
touchenv refuses before any prompt and tells the agent how to ask again. Typed in your own terminal it is
optional; without it the prompt says **No reason given** and shows the command.

**For AI assistants**, add to `CLAUDE.md` / `AGENTS.md`:

> My secrets are in touchenv. Never read key files. Use `touchenv run --intent "<why>" NAME -- <command>`.

Claude Code also needs `"touchenv *"` in `sandbox.excludedCommands`.

## Not being asked every time

All of this is in [docs/grants.md](docs/grants.md).

- **For 5 minutes.** Tick "Don't ask again for 5 minutes" on a `run` prompt: the same app gets those keys from
  `run` without asking until then.
- **While you step away.** `touchenv grant --for 8h --uses 20 KEY …`: one touch, then the app you ran it from, and
  what it runs, gets those keys from `run`, also while the Mac is locked, until the time or the uses run out.
- **One program, from now on.** `touchenv grant --always --for-program ~/bin/helper.sh KEY`: that script (bound to
  its contents) or signed program reads the key with `get` or `run` without asking, until you revoke it. For
  helpers that run unattended, such as from scheduled tasks.
- **No sensor at hand.** `--password` on `get`, `run` or `grant` takes your Mac password, typed in the terminal,
  for iCloud-synced secrets only.
- `touchenv grant --list` shows what is allowed; `touchenv lock` ends 5-minute approvals and timed grants
  (`--all`: standing grants too).

## Who read what

`touchenv log` prints the access log: every read with who asked, the calling program, the intent and how it was
approved or refused; grants, `set`, `rm`, export and import too. Never a value. `touchenv log --summary` shows
which programs ask for each secret most. Kept two years. See [docs/access-log.md](docs/access-log.md).

## SSH keys

`touchenv ssh add ~/.ssh/id_ed25519` keeps an SSH key behind Touch ID. touchenv then acts as your SSH agent
(`touchenv ssh agent install --config`), asking for every signature and showing the server, or loads the key into
`ssh-agent` for a while (`touchenv ssh load --for 8h`). touchenv never deletes your key file. See
[docs/ssh.md](docs/ssh.md).

## Moving to a new Mac

Migration Assistant and Time Machine don't carry the keys. `touchenv import --begin` on the new Mac,
`touchenv export --to tenv1:… > keys.tenv` on the old one, `touchenv import keys.tenv` on the new one: the file
opens only on that Mac, once, within an hour. See [docs/new-mac.md](docs/new-mac.md).

## Windows

A preview: the same commands, with Windows Hello instead of Touch ID, and grants through a service. Weaker than on a
Mac: any program running as you can ask Windows Hello, and can collect a grant while one is on. SSH keys work, with
Windows Hello for every signature. No standing grants, access log or `--password` yet. See [docs/windows.md](docs/windows.md).

## Good to know

- **Read before you touch.** An approved command can do anything with the key. The intent is written by whoever
  asks; check the command: its first lines are always in the prompt, all of it under **More detail** (a very long
  one as its start and its end, with how much is left out between).
- **Local keys are locked by macOS.** A key saved without `--sync` stays on this Mac and the Keychain itself asks
  for Touch ID (or the Mac password) on every read: malware running as you can't read it without your finger.
- **Synced keys (`--sync`) are guarded by touchenv, not by macOS.** iCloud Keychain won't take the Touch ID lock,
  so an attacker with admin rights who turns off SIP, a macOS bug, or another hacked Mac on your Apple Account can
  read them. Keep signing keys and admin tokens local.
- **What Touch ID doesn't cover.** Once you approve, the command has the key. A 5-minute approval or a grant lets
  anything that app runs (or, for a standing grant, anything that can run that program) take those keys without
  asking. Grant the fewest keys, the shortest time and the fewest uses the task needs.
- **No Touch ID?** It asks for your Mac password in the system's window.

The whole picture, including what a typed password and a standing grant don't protect against:
[docs/security.md](docs/security.md). Building and testing: [docs/building.md](docs/building.md).

## See also

[bordercheck](https://github.com/ptrinh/bordercheck) finds the keys still lying around in plain text on a work
laptop (`.env` files, shell history, SSH keys without a passphrase, tokens in AI agent configs) and the other
open doors, so you know what to move into touch-env.

## License

MIT
