# Moving to a new Mac

How to move your secrets to another Mac (or PC) with `export` and `import`. Keys stay on the Mac they were saved on:
Migration Assistant and Time Machine don't carry them. Both Macs need touchenv 1.4.0 or later.

1. **New Mac:** `touchenv import --begin`. It prints a `tenv1:…` line and a check code like `K7QM-2XRD-9FTA`.
2. **Old Mac:** `touchenv export --to tenv1:… > keys.tenv` (add names to send only some). The `tenv1:…` line isn't
   secret: AirDrop, Universal Clipboard or a chat is fine. **Touch only if the prompt shows the same check code.**
3. Copy `keys.tenv` to the new Mac (AirDrop) and run `touchenv import keys.tenv`. One touch; then touchenv deletes
   the file. **Delete `keys.tenv` on the old Mac too**, and empty its Trash.

```sh
touchenv import --replace keys.tenv          # overwrite keys the new Mac already has (otherwise they're skipped)
touchenv import --local keys.tenv            # keep none synced
```

- **Why it is safe to send.** The file opens only on that Mac, once, within an hour: the key that opens it is made
  in the new Mac's Secure Enclave and deleted after the import. A copy left behind is useless.
- **Why the check code matters.** It stops a tricked agent exporting to someone else's key: the prompt names the
  receiving Mac's code, and only you can compare it. Export never uses a 5-minute approval or a grant.
- **SSH keys** arrive as ordinary secrets. To make one an SSH key again under a new name:
  `touchenv run SSH_ID_ED25519:file -- touchenv ssh add SSH_KEY "$SSH_ID_ED25519"`, then `touchenv rm` the old one.
- **Grants** don't move: make them again on the new Mac.
- **Between a Mac and a PC** it works the same way, in both directions (see [windows.md](windows.md)).
