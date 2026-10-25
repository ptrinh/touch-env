# touch-env

**Lock your passwords and API keys behind your fingerprint, so AI agents can't read them without your touch.**

Each time something needs one of your secrets, your Mac shows this:

> **give Claude Code the secret OPENAI_API_KEY for the command: python report.py**
> 👆 Touch ID

Touch the sensor and that one command gets the key. Don't touch, and nobody gets it.

## Why

AI assistants like Claude Code, Codex and Cursor can run commands on your Mac. That means they can open any file
you can open, including the files where your keys usually live.

Most of the time they don't mean to. But a mistake, or a booby-trapped web page or project the assistant reads, can
make it copy a key out. Then that key can end up in a chat log or on someone else's server.

touch-env stores your keys in the Mac's Keychain, behind Touch ID. You approve every use, and the prompt says
**who** is asking, for **which key**, and **what command** will use it.

## Install

You need macOS 13 or later.

1. Download `touchenv-…-macos.zip` from [Releases](https://github.com/ptrinh/touch-env/releases/latest).
2. Open **Terminal** and paste:

   ```sh
   mkdir -p ~/Applications ~/.local/bin
   unzip ~/Downloads/touchenv-*-macos.zip -d ~/Applications
   ln -sf ~/Applications/touchenv.app/Contents/MacOS/touchenv ~/.local/bin/touchenv
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
   ```

3. Open a new Terminal window and check that it works: `touchenv --version`

## Use

**Save a key.** It asks you to paste the key, and the key is not shown on screen:

```sh
touchenv set OPENAI_API_KEY
```

**Save a key file** (`.p8`, `.pem`, `.json`):

```sh
touchenv set MY_KEY < ~/Downloads/AuthKey.p8
```

After saving, delete the original. Keep a backup somewhere offline, such as a USB stick.

**Use a key.** Put `touchenv run NAME --` in front of the command:

```sh
touchenv run OPENAI_API_KEY -- python report.py
touchenv run MY_KEY:file -- fastlane beta     # :file means the command gets the key as a file path
```

**Other commands:**

| Command | What it does | Asks for Touch ID? |
|---|---|---|
| `touchenv ls` | Lists the names of your saved keys | No |
| `touchenv get NAME` | Shows a key on screen | Yes |
| `touchenv rm NAME` | Deletes a key | Yes |

## Telling your AI assistant

Add this line to your assistant's instructions, for example `CLAUDE.md` or `AGENTS.md`:

> My secrets are in touchenv. Never read key files. To run a command that needs one, use
> `touchenv run NAME -- <command>` and I'll approve it with Touch ID.

If you use Claude Code, also add `"touchenv *"` to `sandbox.excludedCommands` in `~/.claude/settings.json`.

## Good to know

- **Read the prompt before you touch.** Once you approve, that command can use the key however it wants. If the
  command looks strange, don't touch.
- **Your keys never leave your Mac.** They are not synced to iCloud, and touch-env has no internet access.
- **No Touch ID?** Your Mac asks for your login password instead.
- **Other apps can't see the keys at all.** Not even Apple's own `security` tool can read them. There is also no
  "Always Allow" button you could click by mistake.
- **touch-env can't clean up old copies.** Copies of a key that are already elsewhere, such as old files, backups or
  shell history, are still there. Delete them yourself.

## For developers

touch-env is one Swift file, [`touchenv.swift`](touchenv.swift).

**How it works:**
- Keys are stored in the Data Protection keychain with a `userPresence` access control and
  `WhenUnlockedThisDeviceOnly`.
- They sit in a keychain access group that only the signed app holds. This is why it ships as a signed `.app` with a
  provisioning profile.
- The prompt names the nearest parent process that isn't a shell.
- `NAME:file` writes the key to a `0600` file in a private temp folder. The folder is deleted when the command ends.

**Building it yourself** needs a paid Apple Developer account:
1. Register a macOS App ID.
2. Create a Developer ID provisioning profile for it.
3. Put these values in `build.local`, then run `./build.sh`:
   - `TOUCHENV_TEAM_ID`
   - `TOUCHENV_BUNDLE_ID`
   - `TOUCHENV_SIGN_ID`
   - `TOUCHENV_PROFILE`

   The header of `build.sh` explains each one.

Keys saved by the prebuilt app can't be read by your own build, because the two use different signatures. Move them
over with:

```sh
old run A:file -- sh -c 'touchenv set A < "$A"'
```

## License

MIT
