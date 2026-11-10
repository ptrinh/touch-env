# Testing touchenv on a real Windows PC

CI can't run Windows Hello, so this is the only check of the part that matters. Use a test key (`sk-test-…`), not a
real one. Run from Windows Terminal unless a step says otherwise. Note the Windows version and whether the PC has a
TPM (`tpm.msc`).

**Must pass before a release:** 3, 4, 5, 6, 9, 10. A failure at 5 or 9 means the design doesn't hold on that Windows.

1. **Contract.** In Git Bash: `conformance/run.sh ./touchenv.exe`: all pass.
2. **No Hello.** On an account with no Windows Hello PIN: `echo x | touchenv set A` says Windows Hello isn't set up,
   exit 1.
3. **First save.** `echo sk-test-1 | touchenv set A`: one Hello prompt saying touchenv is setting up. Then
   `certutil -csp "Microsoft Passport Key Storage Provider" -user -key` lists `<your SID>//touchenv//store`.
   A second `echo two | touchenv set B` asks nothing.
4. **Prompt text.** `touchenv run --intent "manual test" A -- cmd /c echo %A%`: the Hello window shows "touchenv: Allow
   Windows Terminal to read A?", "Intent: manual test" and the command line, then prints the key. Try a 200-character
   intent: note where Windows cuts the text, if it does. Screenshot it for the README.
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
   the README describes). Approving it there gives the store key, so cancel.
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
