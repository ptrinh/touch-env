# Security policy

touchenv holds API keys, signing keys and passwords, and its promise is narrow: a secret is read only after a Touch ID
the person approved, for the command shown. Anything that breaks that promise is a vulnerability.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository. Please do not open a public
issue for a security problem. You will get an answer within 7 days; a fix for a serious problem is released as soon as
it is ready, and you are credited in the release notes unless you would rather not be.

## Bounty

**US$100** for each confirmed vulnerability in scope that was not already known (the limits listed in the threat model are) or reported, paid once the fix is
released. When several reports describe the same problem, the first one gets it. Reports must come through private
reporting and stay private until the fix is out; testing must not touch other people's computers, accounts or data.

## Scope

Most worth a look (see [the threat model](docs/threat-model.md) for how each part is meant to hold):

- **Reading without Touch ID**: any way for another program (same user, no admin rights) to read an item that is kept
  on this Mac only, or to get a secret out of `touchenv` without the person's finger.
- **Synced items** (`--sync`, iCloud Keychain): these are guarded by touchenv's own code, not by macOS's Touch ID lock.
  How strong that is, and what an attacker needs, is the part most in need of an independent eye.
- **Grants** (`touchenv grant`): whether a grant can be widened, extended or used by a program it was not meant for.
- **The Touch ID dialog**: whether a requester can make it show a different program, command or intent than the real
  one.
- **`run`**: the environment and the `NAME:file` temporary files (mode 0600, deleted when the command ends), and the
  masking of values in output.
- **The Windows port** (beta), and the release chain: Homebrew cask, GitHub releases, code signing and notarization.

Out of scope: an attacker with administrator rights who disables System Integrity Protection (stated as a limit for
synced items), a secret read by the program the person approved (that is the point), and malware the person runs
and approves at the Touch ID dialog.

## Supported versions

Only the latest release.
