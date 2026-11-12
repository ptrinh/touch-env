# Testing touchenv on a real Windows PC

CI can't run Windows Hello, so this is the only check of the part that matters. Use a test key (`sk-test-…`), not a
real one. Run from Windows Terminal unless a step says otherwise. Note the Windows version and whether the PC has a
TPM (`tpm.msc`).

**Must pass before a release:** 3, 4, 5, 6, 9, 10, and with the service 20, 22, 24, 30, 31. A failure at 5, 9, 30 or
31 means the design doesn't hold on that Windows.

1. **Contract.** In Git Bash: `conformance/run.sh ./touchenv.exe`: all pass.
2. **No Hello.** On an account with no Windows Hello PIN: `echo x | touchenv set A` says Windows Hello isn't set up,
   exit 1.
3. **First save.** `echo sk-test-1 | touchenv set A`: one Hello prompt saying touchenv is setting up. Then
   `certutil -csp "Microsoft Passport Key Storage Provider" -user -key` lists `<your SID>//touchenv//store`.
   A second `echo two | touchenv set B` asks nothing.
4. **Prompt text.** `touchenv run --intent "manual test" A -- cmd /c echo %A%`: the Hello window shows "touchenv: Allow
   Windows Terminal to read A?", "Intent: manual test" and the command line, then prints the key. Try a 200-character
   intent: note where Windows cuts the text, if it does. Screenshot it for docs/windows.md.
5. **Every read asks.** `touchenv get A` twice within a few seconds: two prompts. Again right after unlocking the PC,
   and after approving with a fingerprint, then the PIN, then face (whatever the PC has).
6. **Cancel.** Cancel the prompt: `touchenv: not approved`, exit 1 (`$LASTEXITCODE` in PowerShell), nothing printed.
7. **Placement.** The prompt comes up in front of Windows Terminal, the old console (`conhost`), and VS Code's
   terminal, not behind them.
8. **Remote.** Over Remote Desktop: `touchenv get A` refuses (Remote Desktop message). Over SSH (OpenSSH Server):
   refuses (no desktop).
9. **No silent way in.** In PowerShell, with `$w` = the `wrapped_store_key` value from `store.json`:

   ```powershell
   $p = [Security.Cryptography.CngProvider]::new("Microsoft Passport Key Storage Provider")
   $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
   $k = [Security.Cryptography.CngKey]::Open("$sid//touchenv//store", $p, [Security.Cryptography.CngKeyOpenOptions]::Silent)
   [Security.Cryptography.RSACng]::new($k).Decrypt([Convert]::FromBase64String($w), [Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
   ```

   It must throw, never print bytes. Without `Silent` it must show a Hello prompt (with Windows' generic text: the gap
   docs/windows.md describes). Approving it there gives the store key, so cancel.
10. **`:file`.** `touchenv run A:file -- cmd /c "type %A% & icacls %A%"`: prints the key; `icacls` lists only you.
    Afterwards `%LOCALAPPDATA%\touchenv\run` is empty. Then `touchenv run A:file -- cmd /c pause`, close the window
    while it waits, open a new one and run another `:file` command: the leftover folder is gone.
11. **Exit codes and Ctrl-C.** `touchenv run A -- cmd /c exit 7` gives 7. `touchenv run A:file -- ping -t localhost`,
    Ctrl-C: ping stops, touchenv exits, the run folder is empty.
12. **ACLs.** `icacls %LOCALAPPDATA%\touchenv` and `icacls %LOCALAPPDATA%\touchenv\store.json`: only you, nothing
    inherited.
13. **Agents.** From Claude Code on Windows: `touchenv get A` is refused and asks for `--intent`; with one, the prompt
    names Claude Code.
14. **Batch files.** `touchenv run A -- npm --version` works (npm is `npm.cmd`); `touchenv run A -- npm run "a&b"` is
    refused with the batch-file message.
15. **Moving keys.** PC to PC, PC to Mac and Mac to PC: `import --begin` on the receiver, `export --to …` on the
    sender. The check codes match; the import asks once; the file is deleted; importing again is refused; `--replace`
    overwrites, otherwise existing names are skipped. An hour later, an unused `--begin` has expired.
16. **Tampering.** Change one character of `store_key` in `store.json`: `get` and `set` refuse ("changed outside
    touchenv"). Put the file back. Remove and re-add the Hello PIN: `get` says the Hello key is gone.
17. **No TPM.** On a VM without a virtual TPM: 3 to 6 still behave the same (the key is in software).
18. **Arm64.** Steps 3 to 6 and 10 on an Arm PC with the arm64 build.
19. **Console.** Messages with "…" display correctly in `conhost`; `chcp` shows the same code page after touchenv as
    before.

## The touchenv service: grants and 5-minute approvals

Never run on a real PC yet. CI installs, upgrades and removes the service, and checks the pipe and the caller's
identity in a test, but can't use Windows Hello, so nothing below has been seen working end to end.

20. **Install.** From a normal (not administrator) Windows Terminal: `touchenv service install`. A UAC prompt
    appears. Decline it: "not approved: Windows asked for administrator approval and it was declined", exit 1, and
    `sc query touchenv` says the service doesn't exist. Again, approve: the message names `NT SERVICE\touchenv` and
    `C:\Program Files\touchenv\touchenv.exe`. Then:
    - `sc qc touchenv`: SERVICE_START_NAME `NT SERVICE\touchenv`, BINARY_PATH_NAME in Program Files.
    - `sc qprivs touchenv`: only SeChangeNotifyPrivilege.
    - `icacls "C:\Program Files\touchenv"`: Users and your account can read and run, not write.
    - Task Manager, Details: touchenv.exe runs as user name "touchenv".
    - `touchenv status`: "touchenv service <version>, running. 5-minute approvals: off." and "nothing active".
21. **Pipe.** In PowerShell: `[System.IO.Directory]::GetAccessControl("\\.\pipe\touchenv").Access` (or
    Sysinternals `accesschk -l \pipe\touchenv`): SYSTEM and the service full, INTERACTIVE read/write, NETWORK denied,
    nothing for Everyone or ANONYMOUS LOGON.
22. **Grant.** `touchenv grant --intent "manual test" --for 10m --uses 2 A`: one Windows Hello prompt that names
    Windows Terminal, A, "10 minutes", "up to 2 times", "stays on while the PC is locked" and "any program running
    as you can get A too". A shield icon appears in the notification area. Then
    `touchenv run A -- cmd /c echo %A%` twice: no prompt, the key printed, a notification each time ("Windows Terminal
    read A", "No Windows Hello asked: …"; the second says it was the last use). A third run asks again.
    `touchenv status` lists both uses with times and pids. Screenshot the prompt and a notification for docs/windows.md.
23. **What a grant doesn't cover.** Grant from Windows Terminal, then from VS Code's terminal `touchenv run A -- …`:
    asks. `touchenv get A` and `touchenv export …`: ask. A second key not in the grant: asks.
24. **Screen lock.** Grant for 10 minutes, then in the granted terminal:
    `cmd /c "timeout /t 60 & touchenv run A -- cmd /c echo %A% > %TEMP%\grant-test.txt"`, press Win+L at once, wait
    a minute, unlock: the file holds the key (and a notification may be waiting). Delete the file.
25. **Lock.** Grant, then right-click the icon: it lists the grant and "Lock Now". Choose it: the icon goes, `status`
    says nothing active, the next run asks. Again with `touchenv lock`: "locked: every approval and grant ended".
26. **The app quits.** Grant from Windows Terminal, close every Windows Terminal window, open a new one: the next run
    asks, and `status` is empty within a couple of seconds.
27. **Log off.** Grant, sign out, sign in: `status` says nothing active.
28. **Other accounts and sessions.** With a grant on, switch user (fast user switching) to another account that has
    touchenv set up: its `status` shows nothing and its runs ask. Back in the first account, the grant is still on.
29. **Remote Desktop.** Grant at the PC, disconnect, connect again over Remote Desktop to the same session: a run
    from the granted terminal works without asking (Windows Hello itself can't ask there). A new grant over Remote
    Desktop is refused (it needs Windows Hello). Note what happens and put it in docs/windows.md.
30. **Impostor.** As administrator `sc stop touchenv`. Then as yourself in PowerShell:
    `$s = [System.IO.Pipes.NamedPipeServerStream]::new("touchenv"); $s.WaitForConnection()`. In another window:
    `touchenv grant --for 5m --uses 1 A` fails with "something other than the touchenv service is answering" and
    **no Windows Hello prompt**; `touchenv run A -- cmd /c echo ok` warns and then asks Windows Hello. Close
    PowerShell, `sc start touchenv` as administrator: it starts again (if the impostor still held the name, the
    service would refuse to start rather than share it).
31. **The service's memory.** With a grant on, as yourself (not elevated): Sysinternals `procdump -ma touchenv` and
    Process Explorer's Strings tab on touchenv.exe (the service) are refused (access denied). From an elevated
    prompt they work: that is the documented limit.
32. **5 minutes.** `touchenv service install --offer-5-minutes` (UAC again; existing grants end). `touchenv run A --
    cmd /c echo %A%`: first a touchenv question box with No preselected; press Enter (No): the Hello prompt says
    nothing about 5 minutes, and the next run asks again. Choose Yes: the Hello prompt says "and again without asking
    for the next 5 minutes" and that any program running as you can get A too; the next run from the same terminal
    doesn't ask and shows a notification. Cancel in the box: nothing runs, no Hello prompt. Lock the screen with an
    approval on: after unlocking, the next run asks. From Claude Code, check the box appears and an agent can't get
    past it without you.
33. **Upgrade.** With a grant on, run `touchenv service install` from a newer build: the grant ends (status: nothing
    active) and `status` shows the new version. An old touchenv.exe against the new service (or the reverse): the
    error says to install again with this touchenv.exe.
34. **Uninstall.** `touchenv service uninstall` (UAC): the service and `C:\Program Files\touchenv` are gone,
    `touchenv grant` says the service isn't installed, `touchenv lock` says nothing to lock, runs ask every time.
35. **Arm64.** 20, 22 and 25 on an Arm PC with the arm64 build.

## SSH keys

Windows' own OpenSSH client (`ssh -V`: OpenSSH_for_Windows 8.9 or later sends the server to the agent). Stop the
stock agent first if it runs (`Get-Service ssh-agent`), so it can't answer instead.

36. **Add.** `ssh-keygen -t ed25519 -f $HOME\.ssh\tenv_test` with a passphrase. `touchenv ssh add
    $HOME\.ssh\tenv_test`: asks the passphrase once (not shown), prints `stored SSH_TENV_TEST: ED25519 256 SHA256:…`,
    the `.pub` path under `%LOCALAPPDATA%\touchenv\ssh` and the next steps; the key file is still there.
    `touchenv ssh ls` lists it without a prompt. Try an RSA key from PuTTYgen's "Export OpenSSH key" too.
37. **Install.** `touchenv ssh agent install --config`: `.ssh\config` gets the block at its end (and
    `config.touchenv-backup` the old one); `touchenv ssh agent status` says running, starts at logon, config uses it.
    **Check `IdentityAgent "//./pipe/touchenv-ssh-<SID>"` is accepted** (`ssh -G github.com | findstr identityagent`,
    then `ssh-add -l` lists the key). If this OpenSSH can't open it, try `$env:SSH_AUTH_SOCK =
    "\\.\pipe\touchenv-ssh-<SID>"` and report which works.
38. **Sign in.** Add the `.pub` to a GitHub account (or a test server). `ssh -T git@github.com`: a Windows Hello
    prompt naming PowerShell (or Windows Terminal) and ssh, the key, "log in as git" and "Server: github.com, its key
    as in your known_hosts". Touch: GitHub greets you. Cancel: ssh says "agent refused operation" and
    `touchenv ssh agent status` lists why under recent.
39. **Through git and agents.** `git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe`, then `git clone git@github.com:<you>/<repo>.git`: the prompt says "(through git, ssh)".
    From Claude Code: the prompt names Claude Code. A server not in known_hosts: "Server: not in your known_hosts".
    Commit signing (`git config gpg.format ssh`, `user.signingkey` = the `.pub`, `git commit -S`): "sign a git commit
    or tag".
40. **Nobody to ask.** `ssh` from another PC into this one (or Remote Desktop), then `ssh -T git@github.com` there:
    refused at once. With the screen locked and a request made some other way (a scheduled `git fetch`): note what
    happens; touchenv doesn't check for the lock yet, so a prompt may be waiting after you unlock.
    Also: does the Windows Hello prompt come to the front, or open behind other windows?
41. **Logon and console.** Sign out and in: the agent runs again (status). Note whether a console window flashes at
    logon and for how long.
42. **Remove.** `touchenv ssh agent uninstall --config`: stopped, not at logon, the block gone from `.ssh\config`
    (backup kept). `touchenv ssh rm SSH_TENV_TEST`: one Hello prompt; the `.pub` is gone.
