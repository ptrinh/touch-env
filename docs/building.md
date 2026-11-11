# Building and testing touchenv

For developers: how the code is laid out, how secrets are stored, how to build, test and release.

## The Mac build

One Swift file, [`touchenv.swift`](../touchenv.swift), kept to one (with a second file Swift would want the commands
in a `main.swift`).

- **Local keys:** Data Protection keychain, `userPresence`, `WhenUnlockedThisDeviceOnly`. **Synced keys:**
  `kSecAttrSynchronizable`, no access control (iCloud refuses one). Both sit in an access group only the signed app
  holds.
- **The prompt** embeds `LAAuthenticationView` (no Allow button). The Touch ID icon comes from macOS, with a copy in
  `Resources/`.
- **5-minute approvals and timed grants** live in memory in `touchenv agent`, keyed by the requester's pid and start
  time (a grant also covers the processes below that requester), behind a `0600` Unix socket; each end checks that
  the other satisfies touchenv's designated code requirement.
- **Standing grants** are Data Protection keychain items: service `touchenv-standing`, account = the program's real
  path, `AfterFirstUnlockThisDeviceOnly`, no access control. The record (JSON) is in `kSecAttrGeneric` and the
  secrets' copy in the value, so listing never touches a value. The caller is `getppid()`. A script is matched from
  the shell's arguments (`KERN_PROCARGS2`, trusted only from a shell that satisfies `anchor apple`), its folder
  (`PROC_PIDVNODEPATHINFO`), `realpath`, SHA-256 and an `lstat` of every folder up to `/`; a signed program with
  `SecCodeCheckValidity` against the recorded designated requirement. The pid's start time is checked again after.
- **`--password`:** OpenDirectory (`ODRecord.verifyPassword`); the wrong-password count is a keychain item
  (service `touchenv-password-throttle`) in the same access group.
- **The access log:** monthly files in `~/Library/Logs`, written under a `flock`.
- **SSH:** the OpenSSH key format, the agent protocol and the RSA/ECDSA/Ed25519 signing are in the same file, on
  CryptoKit and Security.framework, no other code.

## Tests

```sh
tests/run.sh                 # everything below
tests/run.sh --sshd          # adds real logins against a throwaway sshd on a high port
conformance/run.sh path/to/touchenv
```

`tests/run.sh` compiles `touchenv.swift` with `-D TOUCHENV_TESTS` (which leaves out the command dispatch) together
with each test file:

- `tests/ssh-tests.swift` checks the SSH code against OpenSSH's own tools: keys made by `ssh-keygen`, signatures
  checked with `ssh-keygen -Y verify`, `ssh-add` and `ssh-keygen -Y sign` talking to the agent, a throwaway
  `ssh-agent` for `load`.
- `tests/standing-tests.swift` runs the standing-grant checks on real shells and real signature checks, with the
  grants kept in memory, and tests the access log.
- `tests/password-tests.swift` drives the `--password` prompt on a pseudo-terminal with a fake password check.

None of it reads your keys, agent, config, Keychain or password, or shows a prompt.

`conformance/run.sh` checks any build, Mac or Windows, against the command-line cases in `conformance/cases.txt`.
Every case ends before touchenv reads a secret or asks, so it is safe against a real install.

## Building it yourself

Building needs a paid Apple Developer account: the keychain access group is a restricted entitlement, so the app
must be signed with your Developer ID and carry a provisioning profile that grants it. Make an App ID and a
Developer ID provisioning profile, put the values listed in the header of `build.sh` in `build.local`, then run
`./build.sh`. Your build can't read keys saved by the prebuilt app; move them with
`old run A:file -- sh -c 'touchenv set A < "$A"'`.

## Windows

A Go module in [`windows/`](../windows), standard library plus `golang.org/x/sys`.

- The Hello key is made with CNG (`NCryptCreatePersistedKey` in the Microsoft Passport key storage provider,
  `NgcCacheType` = ask every time, the prompt text from `NCRYPT_USE_CONTEXT_PROPERTY`).
- `internal/core` holds everything that isn't Windows and is tested on any OS with a stand-in key
  (`cd windows && go test ./internal/core`).
- Build: `cd windows && GOOS=windows GOARCH=amd64 go build -o touchenv.exe .`
- The same exe is the service (`touchenv service run`, started by Windows). `internal/core/holder.go` is what it
  holds and for how long, tested anywhere; `internal/winplat/service_windows.go` is the named pipe
  (`\\.\pipe\touchenv`, interactive users only, the client identified from its token and pid, never from what it
  says) and the process list.
- On a real PC, go through [`windows/MANUAL-TEST.md`](../windows/MANUAL-TEST.md).

## Releases

`release.sh` (maintainer only) builds into `dist/`, notarizes, staples and zips the Mac app. Publishing the GitHub
release then runs [`windows.yml`](../.github/workflows/windows.yml), which tests the Windows build and attaches its
zips.
