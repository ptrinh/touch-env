// touchenv — secrets in the macOS Keychain, every read behind Touch ID (or the Mac password).
//
//   touchenv [cmd] --intent TEXT ...   one line on why, shown in the prompt (set, get, rm, run)
//   touchenv set NAME          secret from stdin (typed with no echo, or piped: touchenv set NAME < file)
//   touchenv set --sync NAME   the same, synced to your other Macs through iCloud Keychain
//   touchenv get NAME          print the secret
//   touchenv run NAME[:file] [NAME2[:file] ...] -- command args...
//                              run the command with each secret in env var NAME (one Touch ID for all);
//                              ":file" puts it in a private temp file instead and NAME holds the path,
//                              the file is removed when the command ends (a hang-up, TERM or QUIT is passed on
//                              to the command first); one left by a killed touchenv goes at the next run
//   touchenv ls               list names, "(iCloud)" after synced ones (Touch ID: macOS guards even names; no values)
//   touchenv rm NAME           delete
//   touchenv grant --for 8h --uses 20 NAME [NAME2 ...]
//                              one Touch ID now; then the app that asked, and what it runs, reads those secrets
//                              with touchenv run without asking, until the time or the uses run out
//   touchenv grant --always --for-program PROGRAM [--for 90d] [--uses N] NAME [NAME2 ...]
//                              a standing grant: one Touch ID now; then that one program reads those secrets with
//                              get or run without asking, until revoked (see "Standing grants" below)
//   touchenv grant --list · --revoke PROGRAM · --revoke-all
//   touchenv lock [--all]      end every approval now (5-minute ones and timed grants; --all: standing ones too)
//   touchenv log [--since 7d] [--summary] [NAME ...]
//                              the access log: every read, who asked, the outcome; never a value; kept two years
//   touchenv import --begin    on a new Mac: make a one-time receiving key, print it as tenv1:… and a check code
//   touchenv export --to tenv1:… [NAME ...] > keys.tenv
//                              on the old Mac: every secret (or those named) encrypted to that key, one Touch ID
//   touchenv import keys.tenv  on the new Mac: store them (--replace overwrites, --local keeps none synced),
//                              then delete keys.tenv and the receiving key
//   touchenv ssh add [--sync] [NAME] KEYFILE
//                              store an SSH private key (any type ssh-keygen reads, decrypted once if it has a
//                              passphrase; signs with Ed25519, ECDSA P-256/384/521 and RSA); the file is left alone
//   touchenv ssh ls · ssh rm NAME
//   touchenv ssh agent install [--config] · uninstall [--config] · status
//                              touchenv as ssh's agent (IdentityAgent): a LaunchAgent whose socket launchd holds;
//                              every signature asks for Touch ID, unless a grant or a 5-minute approval covers it
//   touchenv ssh load [--for 1h] NAME ... · ssh unload NAME ...
//                              one Touch ID, then the key is in the stock ssh-agent for that long (only launchd's
//                              com.openssh.ssh-agent, identified by the pid serving the connection)
//
// Items are generic passwords (service "touchenv") in the Data Protection keychain, in the keychain access group
// the signed touchenv.app holds (its only keychain-access-groups entitlement), with a userPresence access control:
// macOS itself asks for Touch ID (or the Mac password) on every read, this device only, never synced.
// Synced items (set --sync) can't carry that access control, so iCloud Keychain will take them: only the signed app
// can read them, and touchenv asks for Touch ID itself before every read.
// The Touch ID prompt is touchenv's own window with the sensor embedded (LAAuthenticationView): who asks (the nearest
// parent process that is not a shell; inside tmux or screen, that server), which secrets, the stated intent, and the
// command: its first two lines always, all of it (a very long one as head and end) under "More detail", scrolling.
// Without Touch ID, or on "Use Password…", the macOS dialog asks instead.
// For run, the prompt offers "Don't ask again for 5 minutes" (only there: no flag, or an agent would always pass it).
// Ticked, touchenv starts a background copy of itself (touchenv agent) that keeps those secrets in memory, each for 5
// minutes from its own approval, and hands them to later touchenv runs from the same requester (same pid and start
// time). Every message on its socket is AES-GCM sealed with a key only the signed touchenv can read from the Keychain
// (see "The background copy's socket" below); both ends also check the other's code signature. One approved from
// touchenv's SSH agent is good for signatures only, never for run. A menu bar timer shows the approval; each use
// flashes a notice.
// grant: the same background copy keeps the named secrets for the length given (24 hours at most) and a number of
// uses (one per touchenv run). It covers the requester of the grant command and every process below it, checked from
// the kernel's process tree, and goes on while the screen is locked. It ends at the time, at the last use, on
// touchenv lock, when that requester quits, or at logout.
// grant --always: a standing grant to one program (a shell script, by real path and SHA-256, or a signed program, by
// designated requirement), kept as a Keychain item in touchenv's access group with a copy of the secrets; get and run
// check the process that ran them (their parent, by pid) against it and read without a prompt (see "Standing
// grants" below). That parent can have forked touchenv before it exec'd the granted program: docs/grants.md. lock leaves
// those on unless --all. Every read, grant, revoke, set, rm, export and import is a line in the access log
// (~/Library/Logs/touchenv-access-YYYY-MM.log, kept two years; see "The access log" below).
// export/import: the receiving key lives in the new Mac's Secure Enclave (a keychain item, this device only, when there
// is none) and is deleted after one import or an hour. The file: "TENV" 1 | receiving key (33 bytes) | ephemeral key
// (65) | AES-GCM over JSON, key from ECDH + HKDF-SHA256, the header authenticated. Export never uses a 5-minute
// approval, and its prompt shows the receiving key's check code: approve only if the new Mac shows the same.
// SSH keys are ordinary items (the OpenSSH private key text, unencrypted) marked with kSecAttrDescription
// "touchenv ssh key" and their public key line in kSecAttrComment; the public half is also written to
// ~/Library/Application Support/touchenv/ssh/NAME.pub, so listing them never asks. The SSH agent (touchenv ssh agent
// serve, started by launchd on the socket ssh-agent.sock beside it) answers identities from the public halves and, for
// a signature, asks the background copy for a grant or approval covering the process at the other end of the socket,
// else shows the prompt (one at a time), reads the key, signs and wipes it. It refuses to add, remove or lock keys,
// and to sign when the screen is locked or the request came through an ssh session, unless a grant covers it.
// Build and sign with ./build.sh.

import AppKit
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import OpenDirectory
import Security

let version = "1.7.5"
let service = "touchenv"
let usage = """
touchenv \(version) — secrets in the macOS Keychain, every read behind Touch ID
© Phil Trinh - SENPRINTS 2026

  touchenv set NAME                     store a secret (typed with no echo, or piped: touchenv set NAME < file)
  touchenv set --sync NAME              the same, synced to your other Macs through iCloud Keychain
  touchenv sync NAME ...                start syncing secrets kept on this Mac only (one Touch ID for all)
  touchenv unsync NAME ...              stop syncing: keep them on this Mac only, deleted from your other Macs
  touchenv get NAME                     print it
  touchenv run NAME[:file] ... -- CMD   run CMD with each secret in env var NAME; with :file, NAME holds
                                        the path of a private temp file, removed when CMD ends
  touchenv ls                           list names; "(iCloud)" marks synced ones
  touchenv rm NAME                      delete
  touchenv grant --for 8h --uses 20 NAME ...
                                        one Touch ID now; then this app and what it runs read those secrets
                                        with touchenv run without asking, also while the Mac is locked, until
                                        the time (24h at most) or the uses run out
  touchenv grant --always --for-program PROGRAM [--for 90d] [--uses N] NAME ...
                                        a standing grant: one Touch ID now; then that one program (a shell
                                        script, bound to its contents, or a signed program or .app, bound
                                        to its signature) reads those secrets with get or run without
                                        asking, from now on, also while the Mac is locked. Anything
                                        running as you can start that program and get them through
                                        it: see docs/grants.md
  touchenv grant --list                 standing grants, timed grants and 5-minute approvals
  touchenv grant --revoke PROGRAM · --revoke-all
                                        end standing grants (no Touch ID)
  --password (get, run, grant)          for secrets synced through iCloud only: type your Mac password at
                                        a hidden prompt in the terminal instead of Touch ID
  touchenv lock [--all]                 end every 5-minute approval and timed grant now; --all ends
                                        standing grants too
  touchenv log [--since 7d] [--summary] [NAME ...]
                                        the access log: every read, who asked, the outcome; never a value.
                                        Kept two years (touchenv log --help)

  SSH keys (see touchenv ssh for more):
  touchenv ssh add [--sync] [NAME] KEYFILE
                                        store an SSH private key (the file stays: delete it yourself)
  touchenv ssh ls · touchenv ssh rm NAME
  touchenv ssh agent install [--config] touchenv as your SSH agent: every signature asks for Touch ID
  touchenv ssh load [--for 1h] NAME ... one Touch ID, then the key is in ssh-agent until the time runs out
  touchenv ssh unload NAME ...

  Moving to a new Mac:
  touchenv import --begin               (new Mac) prints tenv1:… and a check code
  touchenv export --to tenv1:… [NAME ...] > keys.tenv
                                        (old Mac) all secrets, or those named, encrypted for that Mac only
  touchenv import [--replace] [--local] keys.tenv
                                        (new Mac) store them, then delete the file; --replace overwrites,
                                        --local keeps none synced

  --intent TEXT after the command (touchenv run --intent "why" NAME -- CMD) puts one line on why in the prompt.
"""
var context = LAContext()

func die(_ message: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(code)
}

// MARK: Who is asking

/// The name the process was started as (argv[0]), not its file name: Claude Code's file is named after its
/// version (…/claude/versions/2.1.310) but it runs as "claude". Falls back to the file name.
func executableName(_ pid: pid_t) -> String? {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    if sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size {
        var buffer = [UInt8](repeating: 0, count: size)
        if sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 {
            // Layout: argc (Int32), the executable path, NUL padding, then argv[0].
            var i = MemoryLayout<Int32>.size
            while i < size && buffer[i] != 0 { i += 1 }
            while i < size && buffer[i] == 0 { i += 1 }
            var end = i
            while end < size && buffer[end] != 0 { end += 1 }
            if end > i, let argv0 = String(bytes: buffer[i..<end], encoding: .utf8) {
                return URL(fileURLWithPath: argv0).lastPathComponent
            }
        }
    }
    var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
    return URL(fileURLWithPath: String(cString: path)).lastPathComponent
}

func bsdInfo(_ pid: pid_t) -> proc_bsdinfo? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size ? info : nil
}

func parentPid(_ pid: pid_t) -> pid_t? { bsdInfo(pid).map { pid_t($0.pbi_ppid) } }

/// When the process started, in microseconds: with the pid, it names one process even after the pid is reused.
func startTime(_ pid: pid_t) -> UInt64? {
    bsdInfo(pid).map { UInt64($0.pbi_start_tvsec) * 1_000_000 + UInt64($0.pbi_start_tvusec) }
}

struct Requester { let pid: pid_t; let start: UInt64; let name: String; var isAgent = false; var exec = "" }

/// The nearest ancestor that is not a shell or a wrapper: the agent, or the terminal when you typed it yourself.
func requester(from first: pid_t = getppid(), through extra: Set<String> = []) -> Requester {
    let passThrough: Set<String> = ["sh", "zsh", "bash", "fish", "dash", "ksh", "tcsh", "env", "sudo", "login",
                                    "nohup", "time", "timeout", "xargs", "make", "script"]
    // AI agents (by executable name, not the apps of the same name): they must say why (--intent).
    let agents: Set<String> = ["claude", "codex", "cursor-agent", "gemini", "aider", "goose", "opencode"]
    let known = ["claude": "Claude Code", "codex": "Codex", "cursor-agent": "Cursor", "Cursor": "Cursor",
                 "gemini": "Gemini CLI", "aider": "aider", "goose": "Goose", "opencode": "opencode",
                 "ghostty": "Ghostty", "Terminal": "Terminal", "iTerm2": "iTerm", "Code": "VS Code",
                 "Code Helper": "VS Code", "WezTerm": "WezTerm", "wezterm-gui": "WezTerm", "kitty": "kitty",
                 "alacritty": "Alacritty", "warp": "Warp", "stable": "Warp"]
    var pid = first
    // tmux's and screen's servers are started by launchd, not by the terminal: inside one, the chain ends there.
    var multiplexer: (pid: pid_t, name: String)?
    for _ in 0..<32 {
        guard pid > 1, let name = executableName(pid) else { break }
        let bare = name.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        if let kind = multiplexerKind(bare) {
            if multiplexer == nil { multiplexer = (pid, kind) }
        } else if !passThrough.contains(bare) && !extra.contains(bare) {
            return Requester(pid: pid, start: startTime(pid) ?? 0, name: known[name] ?? visibleText(name, limit: 60),
                             isAgent: agents.contains(name), exec: name)
        }
        guard let parent = parentPid(pid) else { break }
        pid = parent
    }
    if let multiplexer, let start = startTime(multiplexer.pid) {
        return Requester(pid: multiplexer.pid, start: start, name: multiplexer.name, exec: multiplexer.name)
    }
    return Requester(pid: 0, start: 0, name: "a process")
}

/// "tmux" or "screen" for their processes (also "tmux: server", "SCREEN"), else nil.
func multiplexerKind(_ name: String) -> String? {
    let word = name.lowercased().split(whereSeparator: { $0 == ":" || $0 == " " }).first.map(String.init) ?? ""
    return word == "tmux" || word == "screen" ? word : nil
}

/// The badge on the Touch ID disc: the icon of whoever asks. For an AI agent that runs in a terminal, its maker's
/// app when this Mac has it (Claude Code shows Claude.app's icon, Codex shows Codex.app's or ChatGPT.app's);
/// otherwise the app the request came from: the AI app itself, the editor, or the terminal. Icons are read from
/// the apps installed here; touchenv ships no one's logo. Like the name in the prompt, it tells you who asks; it
/// proves nothing a program could not fake.
func requesterIcon(_ who: Requester = requester()) -> NSImage {
    let makers = ["claude": ["Claude"], "codex": ["Codex", "ChatGPT"], "cursor-agent": ["Cursor"], "gemini": ["Gemini"],
                  "goose": ["Goose"], "opencode": ["OpenCode"]]
    for app in makers[who.exec] ?? [] {
        for folder in ["/Applications", NSHomeDirectory() + "/Applications"] {
            let path = "\(folder)/\(app).app"
            if FileManager.default.fileExists(atPath: path) { return NSWorkspace.shared.icon(forFile: path) }
        }
    }
    var pid = who.pid
    for _ in 0..<32 {
        guard pid > 1 else { break }
        if let app = NSRunningApplication(processIdentifier: pid), app.activationPolicy == .regular, let icon = app.icon {
            return icon
        }
        guard let parent = parentPid(pid) else { break }
        pid = parent
    }
    return NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath)
}

/// Text another process chose (its name, a command's arguments), made safe to show: a line break becomes ⏎ and a
/// tab a space; any other control, format (a bidi override, strong()'s \u{1} and \u{2}), separator, private-use or
/// unassigned character becomes �, so it can neither restyle the prompt nor disguise or hide what follows it.
/// With `limit`, longer text keeps its head and tail (see elided).
func visibleText(_ raw: String, limit: Int? = nil) -> String {
    var scalars = String.UnicodeScalarView()
    for scalar in raw.unicodeScalars {
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate, .privateUse, .unassigned:
            scalars.append(scalar == "\n" || scalar == "\r" ? "⏎" : scalar == "\t" ? " " : "\u{FFFD}")
        default:
            scalars.append(scalar)
        }
    }
    let text = String(scalars)
    return limit.map { elided(text, limit: $0) } ?? text
}

/// At most about `limit` characters: the head and the tail, with how many were left out between them, so what comes
/// last (the payload at the end of a long sh -c) is never cut off unseen.
func elided(_ text: String, limit: Int) -> String {
    guard text.count > limit else { return text }
    let keep = max(limit - 30, 2)
    let head = keep * 3 / 5, tail = keep - head
    let hidden = text.count - head - tail
    return String(text.prefix(head)) + " …[\(hidden) characters not shown]… " + String(text.suffix(tail))
}

/// A command line to show: each argument cleaned (visibleText), quoted when it has a space or is empty.
func commandText(_ argv: [String]) -> String {
    argv.map { argument -> String in
        let shown = visibleText(argument)
        return shown.isEmpty || shown.contains(" ") ? "'\(shown)'" : shown
    }.joined(separator: " ")
}

func shortCommand(_ argv: [String]) -> String { elided(commandText(argv), limit: 160) }

/// An AI agent must give a reason (--intent) for anything that asks for Touch ID or reads a secret, so the prompt
/// always says why. Refused before any prompt: the agent reads the error and asks again with one.
func requireIntent(_ intent: String?, example: String, who known: Requester? = nil) {
    guard intent == nil else { return }
    let who = known ?? requester()
    if who.isAgent {
        endAttempt("refused", note: "no --intent from an agent",
                   message: "touchenv: \(who.name) must say why, in a few words: \(example)\n"
                       + "  (--intent goes right after the command; the reason is shown in the Touch ID prompt)", code: 2)
    }
}

// MARK: Prompt

/// Marks text to show in bold in a prompt's title. Only the secrets' names are marked, so the eye lands on what is
/// being asked for rather than on the sentence around it.
func strong(_ text: String) -> String { "\u{1}\(text)\u{2}" }
func strong(_ names: [String]) -> String { names.map { strong($0) }.joined(separator: ", ") }

/// A prompt's title: regular text, with the parts marked by strong() in bold.
func titleText(_ marked: String) -> NSAttributedString {
    let out = NSMutableAttributedString()
    var bold = false, run = ""
    func flush() {
        guard !run.isEmpty else { return }
        out.append(NSAttributedString(string: run, attributes: [
            .font: bold ? NSFont.boldSystemFont(ofSize: 13) : NSFont.systemFont(ofSize: 13),
            .foregroundColor: NSColor.labelColor]))
        run = ""
    }
    for character in marked {
        if character == "\u{1}" || character == "\u{2}" {
            flush()
            bold = character == "\u{1}"
        } else {
            run.append(character)
        }
    }
    flush()
    return out
}

/// The scheme of the links behind a prompt title's copy icons: touchenv-copy:NAME.
let copyLinkScheme = "touchenv-copy"

/// The small icon shown after a secret's name in a prompt's title; `done` is the tick shown once it was copied.
func copyIcon(done: Bool) -> NSTextAttachment {
    let attachment = NSTextAttachment()
    let config = NSImage.SymbolConfiguration(pointSize: 11, weight: .regular)
        .applying(NSImage.SymbolConfiguration(paletteColors: [done ? .systemGreen : .secondaryLabelColor]))
    if let image = NSImage(systemSymbolName: done ? "checkmark" : "doc.on.doc", accessibilityDescription: "Copy the name")?
        .withSymbolConfiguration(config) {
        attachment.image = image
        attachment.bounds = NSRect(x: 0, y: -2, width: image.size.width, height: image.size.height)
    }
    return attachment
}

/// A prompt's title like titleText, with a copy icon after each name marked by strong(): a click on the icon puts
/// that name (never a value) on the clipboard.
func titleTextWithCopyIcons(_ marked: String) -> NSAttributedString {
    let out = NSMutableAttributedString()
    var bold = false, run = ""
    func flush() {
        guard !run.isEmpty else { return }
        out.append(NSAttributedString(string: run, attributes: [
            .font: bold ? NSFont.boldSystemFont(ofSize: 13) : NSFont.systemFont(ofSize: 13),
            .foregroundColor: NSColor.labelColor]))
        if bold, let name = run.addingPercentEncoding(withAllowedCharacters: .alphanumerics),
           let link = URL(string: "\(copyLinkScheme):\(name)") {
            out.append(NSAttributedString(string: "\u{2009}", attributes: [.font: NSFont.systemFont(ofSize: 13)]))
            let icon = NSMutableAttributedString(attachment: copyIcon(done: false))
            icon.addAttributes([.link: link, .toolTip: "Copy \(run)", .cursor: NSCursor.pointingHand],
                               range: NSRange(location: 0, length: icon.length))
            out.append(icon)
        }
        run = ""
    }
    for character in marked {
        if character == "\u{1}" || character == "\u{2}" {
            flush()
            bold = character == "\u{1}"
        } else {
            run.append(character)
        }
    }
    flush()
    return out
}

enum Outcome { case approved, denied, password }

/// touchenv's own window: the question, the intent, the command (all of it under "More detail"), and the Touch ID sensor
/// embedded, so macOS shows no dialog of its own. There is no Allow button: only a finger approves.
final class Prompt: NSObject, NSTextViewDelegate {
    let panel = NSPanel(contentRect: .zero, styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
    let detailToggle = NSButton(title: "More detail ›", target: nil, action: nil)
    var detailPreview: NSTextField?
    var detailScroll: NSScrollView?
    var sessionBox: NSButton?
    var keepFor5Minutes: Bool { sessionBox?.state == .on }
    var chosen: Outcome?
    var outcome = Outcome.denied

    /// `notes`: lines shown under the title (the SSH sign prompt: the server); `asker`: who asks, when it is not
    /// this process's parent (the SSH agent asks for the process at the other end of its socket).
    init(title: String, intent: String?, detail: String?, offerSession: Bool, notes: [String] = [],
         asker: Requester? = nil) {
        super.init()
        // Laid out like the macOS authentication dialog: icon top left, text left aligned, buttons stacked full width.
        let width: CGFloat = 228
        func label(_ text: String, _ font: NSFont, _ color: NSColor = .labelColor) -> NSTextField {
            let field = NSTextField(wrappingLabelWithString: text)
            field.font = font
            field.textColor = color
            // A wrapping label is selectable; without this, clicking it hands the text to the field
            // editor, which drops the bold of an attributed string.
            field.allowsEditingTextAttributes = true
            field.preferredMaxLayoutWidth = width
            field.widthAnchor.constraint(equalToConstant: width).isActive = true
            return field
        }
        // The system view drives Touch ID but pulses while it waits. It must stay visible to read a finger, so the
        // dialog's own still icon (the Touch ID disc badged with the asker's icon) sits over it on an opaque cover.
        let reader = LAAuthenticationView(context: context, controlSize: .large)
        let cover = NSView()
        cover.wantsLayer = true
        cover.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        // The system's own disc first; the copy in Resources if a macOS release moves it.
        let disc = NSImageView(image: Bundle(path: "/System/Library/PrivateFrameworks/LocalAuthenticationCoreUI.framework")?
            .image(forResource: "touchID") ?? Bundle.main.image(forResource: "touchID")
            ?? NSImage(systemSymbolName: "touchid", accessibilityDescription: "Touch ID")!)
        disc.imageScaling = .scaleProportionallyUpOrDown
        disc.contentTintColor = .systemRed
        let badge = NSImageView(image: requesterIcon(asker ?? requester()))
        badge.imageScaling = .scaleProportionallyUpOrDown
        let sensor = NSView()
        let frames: [(NSView, CGFloat, CGFloat, CGFloat)] = [(reader, 0, 6, 64), (cover, 0, 0, 74), (disc, 0, 6, 64),
                                                            (badge, 38, 0, 36)]   // view, x, y from bottom left, size
        for (view, x, y, size) in frames {
            view.translatesAutoresizingMaskIntoConstraints = false
            sensor.addSubview(view)
            NSLayoutConstraint.activate([view.leadingAnchor.constraint(equalTo: sensor.leadingAnchor, constant: x),
                                         view.bottomAnchor.constraint(equalTo: sensor.bottomAnchor, constant: -y),
                                         view.widthAnchor.constraint(equalToConstant: size),
                                         view.heightAnchor.constraint(equalToConstant: size)])
        }
        sensor.widthAnchor.constraint(equalToConstant: 74).isActive = true
        sensor.heightAnchor.constraint(equalToConstant: 70).isActive = true

        // The title is a text view, not a label, so the copy icon after each secret's name can be clicked.
        let heading = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 10))
        heading.isEditable = false
        heading.isSelectable = true
        heading.drawsBackground = false
        heading.textContainerInset = .zero
        heading.textContainer?.lineFragmentPadding = 0
        heading.textContainer?.widthTracksTextView = true
        heading.linkTextAttributes = [.cursor: NSCursor.pointingHand]
        heading.delegate = self
        heading.textStorage?.setAttributedString(titleTextWithCopyIcons(title))
        heading.translatesAutoresizingMaskIntoConstraints = false
        heading.widthAnchor.constraint(equalToConstant: width).isActive = true
        if let container = heading.textContainer, let layout = heading.layoutManager {
            container.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
            layout.ensureLayout(for: container)
            heading.heightAnchor.constraint(equalToConstant: ceil(layout.usedRect(for: container).height)).isActive = true
        }
        var views: [NSView] = [sensor, heading]
        for note in notes {
            let line = label("", .systemFont(ofSize: 12))
            line.attributedStringValue = titleText(note)
            views.append(line)
        }
        if let intent {
            let line = label("", .systemFont(ofSize: 13))
            line.attributedStringValue = titleText("\(strong("INTENT:")) \(intent)")
            views.append(line)
        }
        else if detail != nil && notes.isEmpty {
            // No reason given: say so, and show the command without a click.
            views.append(label("No reason given. Check the command:", .systemFont(ofSize: 13), .systemOrange))
        }
        if let detail {
            // The whole detail sits in a scroll view no taller than a third of the screen, so a long command never
            // pushes Cancel off it. With an intent it starts folded to its first two lines: the command is always
            // in view, "More detail" shows the rest.
            let font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            let text = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 10))
            text.isEditable = false
            text.isSelectable = true
            text.drawsBackground = false
            text.textContainerInset = .zero
            text.textContainer?.lineFragmentPadding = 0
            text.textContainer?.widthTracksTextView = true
            text.isVerticallyResizable = true
            text.isHorizontallyResizable = false
            text.autoresizingMask = [.width]
            text.textStorage?.setAttributedString(NSAttributedString(string: detail, attributes: [
                .font: font, .foregroundColor: NSColor.secondaryLabelColor]))
            var fullHeight: CGFloat = 0, lineHeight: CGFloat = 14
            if let container = text.textContainer, let layout = text.layoutManager {
                container.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
                layout.ensureLayout(for: container)
                fullHeight = ceil(layout.usedRect(for: container).height)
                lineHeight = ceil(layout.defaultLineHeight(for: font))
            }
            text.frame.size.height = fullHeight
            let maxHeight = min(240, max(80, (NSScreen.main?.visibleFrame.height ?? 800) / 3))
            let scroll = NSScrollView()
            scroll.documentView = text
            scroll.hasVerticalScroller = fullHeight > maxHeight
            scroll.autohidesScrollers = false
            scroll.drawsBackground = false
            scroll.borderType = .noBorder
            scroll.translatesAutoresizingMaskIntoConstraints = false
            scroll.widthAnchor.constraint(equalToConstant: width).isActive = true
            scroll.heightAnchor.constraint(equalToConstant: min(fullHeight, maxHeight)).isActive = true
            if fullHeight <= lineHeight * 2 + 1 {
                views.append(scroll)   // two lines at most: all of it, nothing to fold
            } else {
                let preview = label(detail, font, .secondaryLabelColor)
                preview.maximumNumberOfLines = 2
                preview.lineBreakMode = .byCharWrapping
                preview.cell?.truncatesLastVisibleLine = true
                preview.isSelectable = false
                detailToggle.target = self
                detailToggle.action = #selector(toggleDetail)
                detailToggle.isBordered = false
                detailToggle.refusesFirstResponder = true
                detailToggle.contentTintColor = .linkColor
                detailToggle.font = .systemFont(ofSize: 11)
                scroll.isHidden = intent != nil
                preview.isHidden = !scroll.isHidden
                detailToggle.title = scroll.isHidden ? "More detail ›" : "Less detail ‹"
                views += [preview, scroll, detailToggle]
                detailPreview = preview
                detailScroll = scroll
            }
        }
        if offerSession {
            let box = NSButton(checkboxWithTitle: "Don't ask again for 5 minutes", target: nil, action: nil)
            box.font = .systemFont(ofSize: 12)
            box.refusesFirstResponder = true
            views.append(box)
            sessionBox = box
        }
        let footnote = label("Touch ID or use your password to continue with touchenv.", .systemFont(ofSize: 11),
                             .secondaryLabelColor)
        views.append(footnote)
        let password = NSButton(title: "Use Password…", target: self, action: #selector(usePassword))
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancel))
        cancel.keyEquivalent = "\u{1b}"
        for button in [password, cancel] {
            button.controlSize = .large
            button.widthAnchor.constraint(equalToConstant: width).isActive = true
            views.append(button)
        }

        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.setCustomSpacing(14, after: sensor)
        stack.setCustomSpacing(20, after: footnote)
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 16, bottom: 16, right: 16)
        panel.contentView = stack
        panel.titlebarAppearsTransparent = true
        panel.titleVisibility = .hidden
        panel.isMovableByWindowBackground = true
        // Stay in front like the macOS dialog does: a panel hides when its app stops being the active one, so a click
        // anywhere else would make the prompt vanish while touchenv still waits for a finger.
        panel.level = .modalPanel
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.setContentSize(stack.fittingSize)
    }

    /// A click on a copy icon in the title: the name goes on the clipboard and the icon becomes a tick for a moment.
    func textView(_ textView: NSTextView, clickedOnLink link: Any, at charIndex: Int) -> Bool {
        guard let url = link as? URL, url.scheme == copyLinkScheme,
              let name = String(url.absoluteString.dropFirst(copyLinkScheme.count + 1)).removingPercentEncoding,
              let storage = textView.textStorage, charIndex < storage.length else { return true }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(name, forType: .string)
        let range = NSRange(location: charIndex, length: 1)
        storage.addAttribute(.attachment, value: copyIcon(done: true), range: range)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak textView] in
            guard let storage = textView?.textStorage, range.location < storage.length else { return }
            storage.addAttribute(.attachment, value: copyIcon(done: false), range: range)
        }
        return true // handled: never hand the link to the system
    }

    @objc func toggleDetail() {
        guard let scroll = detailScroll, let preview = detailPreview else { return }
        scroll.isHidden.toggle()
        preview.isHidden = !scroll.isHidden
        detailToggle.title = scroll.isHidden ? "More detail ›" : "Less detail ‹"
        let frame = panel.frame
        let size = panel.frameRect(forContentRect: NSRect(origin: .zero, size: panel.contentView!.fittingSize)).size
        var y = frame.maxY - size.height
        // Grown past the bottom of the screen: move it up, so the buttons stay on it.
        if let visible = (panel.screen ?? NSScreen.main)?.visibleFrame, y < visible.minY {
            y = min(visible.minY, visible.maxY - size.height)
        }
        panel.setFrame(NSRect(x: frame.minX, y: y, width: size.width, height: size.height), display: true, animate: true)
    }

    @objc func usePassword() { chosen = .password; context.invalidate() }
    @objc func cancel() { chosen = .denied; context.invalidate() }

    /// Shows the window and waits for a finger without blocking: `done` runs on the main thread with the outcome.
    /// With `timeout`, no answer in that time counts as Cancel.
    func show(reason: String, timeout: TimeInterval? = nil, done: @escaping (Outcome) -> Void) {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        panel.center()
        // Who has the keyboard now: it goes back there when the prompt closes.
        let previous = NSWorkspace.shared.frontmostApplication
        app.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        var finished = false
        let asked = context
        if let timeout {
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self, !finished else { return }
                self.chosen = .denied
                asked.invalidate()
            }
        }
        asked.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                finished = true
                let code = (error as? LAError)?.code
                if success { self.outcome = .approved }
                else if let chosen = self.chosen { self.outcome = chosen }
                else if code == .authenticationFailed || code == .biometryLockout || code == .userFallback {
                    self.outcome = .password
                }
                self.panel.orderOut(nil)
                Prompt.giveFocusBack(to: previous)
                done(self.outcome)
            }
        }
    }

    /// touchenv took the keyboard to show the prompt and has no window left to hold it: hand it back to the app that
    /// had it, unless the person has moved on to another app meanwhile.
    static func giveFocusBack(to previous: NSRunningApplication?) {
        guard let previous, previous.processIdentifier != getpid(), !previous.isTerminated, NSApp.isActive else { return }
        if #available(macOS 14.0, *) {
            NSApp.yieldActivation(to: previous)
            previous.activate()
        } else {
            previous.activate(options: [.activateIgnoringOtherApps])
        }
    }

    func run(reason: String) -> Outcome {
        let app = NSApplication.shared
        show(reason: reason) { _ in
            app.stop(nil)
            app.postEvent(NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [],
                                             timestamp: 0, windowNumber: 0, context: nil, subtype: 0,
                                             data1: 0, data2: 0)!, atStart: true)
        }
        app.run()
        return outcome
    }
}

/// Asks with touchenv's window; falls back to the macOS dialog (with `reason`) without Touch ID or on request.
/// Returns whether "Don't ask again for 5 minutes" was ticked (offered only with `offerSession`).
@discardableResult
func authenticate(_ title: String, intent: String?, detail: String? = nil, reason: String,
                  offerSession: Bool = false, asker: Requester? = nil) -> Bool {
    var keep = false
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
        let prompt = Prompt(title: title, intent: intent, detail: detail, offerSession: offerSession, asker: asker)
        let outcome = prompt.run(reason: reason)
        keep = prompt.keepFor5Minutes
        switch outcome {
        case .approved: return keep
        case .denied: endAttempt("cancelled", message: "touchenv: not approved")
        case .password: context = LAContext()
        }
    }
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        endAttempt("failed", note: "can't ask for Touch ID",
                   message: "touchenv: cannot ask for Touch ID: \(error?.localizedDescription ?? "unknown")")
    }
    let done = DispatchSemaphore(value: 0)
    var ok = false
    let full = intent.map { "\(reason) (intent: \($0))" } ?? reason
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: full) { success, _ in
        ok = success
        done.signal()
    }
    done.wait()
    if !ok { endAttempt("cancelled", message: "touchenv: not approved") }
    return keep
}

/// The same questions as authenticate(), for a process that keeps running (the SSH agent): nothing blocks the main
/// thread and nothing exits. A fresh LAContext each time; on approval the global `context` has passed, for the read.
/// `done(approved, keepFor5Minutes)` runs on the main thread. Call on the main thread, one at a time.
var activePrompt: Prompt?
func authenticateAsync(_ title: String, notes: [String], detail: String?, reason: String, asker: Requester,
                       offerSession: Bool, timeout: TimeInterval, done: @escaping (Bool, Bool) -> Void) {
    context = LAContext()
    func systemDialog() {
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { done(false, false); return }
        let asked = context
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { asked.invalidate() }
        asked.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            DispatchQueue.main.async { done(success, false) }
        }
    }
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { systemDialog(); return }
    let prompt = Prompt(title: title, intent: nil, detail: detail, offerSession: offerSession, notes: notes, asker: asker)
    activePrompt = prompt
    prompt.show(reason: reason, timeout: timeout) { outcome in
        activePrompt = nil
        switch outcome {
        case .approved: done(true, prompt.keepFor5Minutes)
        case .denied: done(false, false)
        case .password:
            context = LAContext()
            systemDialog()
        }
    }
}

// MARK: Keychain

func query(_ name: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: name,
     kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
     kSecUseDataProtectionKeychain as String: true, kSecUseAuthenticationContext as String: context]
}

// Any look at a local item, even its name, needs Touch ID: unless the context has passed it, macOS shows its own
// "touchenv needs to authenticate" dialog. Synced items carry no access control and can be looked at freely.

/// Names of the secrets in iCloud Keychain. No Touch ID.
func syncedNames() -> Set<String> {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                            kSecAttrSynchronizable as String: true, kSecUseDataProtectionKeychain as String: true,
                            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
                            kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
    var out: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let found = out as? [[String: Any]] else { return [] }
    return Set(found.compactMap { $0[kSecAttrAccount as String] as? String })
}

/// Whether the secret syncs through iCloud Keychain; nil when there is none. No Touch ID: a local item answers
/// "interaction not allowed" when it exists.
/// `all`: syncedNames(), when already at hand.
func synced(_ name: String, among all: Set<String>? = nil) -> Bool? {
    if (all ?? syncedNames()).contains(name) { return true }
    let probe = LAContext()
    probe.interactionNotAllowed = true
    var q = query(name)
    q[kSecAttrSynchronizable as String] = false
    q[kSecUseAuthenticationContext as String] = probe
    return SecItemCopyMatching(q as CFDictionary, nil) == errSecItemNotFound ? nil : false
}

/// Every secret's name and whether it syncs, read with the context that has passed Touch ID.
func items() -> [String: Bool] {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
                            kSecUseDataProtectionKeychain as String: true, kSecUseAuthenticationContext as String: context,
                            kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
    var out: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let found = out as? [[String: Any]] else { return [:] }
    var result: [String: Bool] = [:]
    for item in found {
        if let name = item[kSecAttrAccount as String] as? String {
            result[name] = item[kSecAttrSynchronizable as String] as? Bool ?? false
        }
    }
    return result
}

/// Where the secrets live, for the prompt.
func place(_ names: [String], among all: Set<String>? = nil) -> String {
    let all = all ?? syncedNames()
    let sync = Set(names.map { all.contains($0) })
    return sync == [true] ? "iCloud Keychain" : sync == [false] ? "your Keychain" : "your Keychain and iCloud Keychain"
}

/// Before a prompt: exits with "no secret named X" for the first name that isn't stored, so a typo costs no touch.
/// No Touch ID (see synced).
func requireStored(_ names: [String], among all: Set<String>? = nil) {
    let all = all ?? syncedNames()
    for name in names where synced(name, among: all) == nil {
        endAttempt(ReadOutcome.refused, note: "no secret named \(name)", message: "touchenv: no secret named \(name)")
    }
}

/// Gives a stored secret a new value. Where it lives stays the same unless `sync` differs from `wasSynced`: then
/// the new item is added before the old one is deleted (synced or not is part of an item's identity, so the two
/// can coexist for that moment), and a failed add leaves the old one as it was. `keep`: attributes of the old item
/// to carry over (an SSH key's marker and public key line). Exits on a Keychain error.
func replaceSecret(_ name: String, _ data: Data, sync: Bool, wasSynced: Bool, keep: [String] = []) {
    var exact = query(name)
    exact[kSecAttrSynchronizable as String] = wasSynced
    if wasSynced == sync {
        let status = SecItemUpdate(exact as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status != errSecSuccess { die("touchenv: keychain error \(status)") }
        return
    }
    var extra: [String: Any] = [:]
    if !keep.isEmpty {
        var q = exact
        q[kSecReturnAttributes as String] = true
        var out: CFTypeRef?
        if SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let old = out as? [String: Any] {
            for key in keep { if let value = old[key] { extra[key] = value } }
        }
    }
    add(name, data, sync: sync, extra: extra)
    let status = SecItemDelete(exact as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
        die("touchenv: stored the new \(name) \(sync ? "in iCloud Keychain" : "on this Mac only"), but couldn't delete "
            + "the old one (keychain error \(status)); touchenv rm \(name) deletes both")
    }
}

func add(_ name: String, _ data: Data, sync: Bool, extra: [String: Any] = [:]) {
    var q = query(name)
    q.merge(extra) { _, new in new }
    q[kSecValueData as String] = data
    q[kSecAttrLabel as String] = "touchenv: \(name)"
    q.removeValue(forKey: kSecUseAuthenticationContext as String)
    if sync {
        // iCloud Keychain won't take an access control: touchenv's own prompt guards every read instead.
        q[kSecAttrSynchronizable as String] = true
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
    } else {
        q.removeValue(forKey: kSecAttrSynchronizable as String)
        // The system asks for Touch ID (or the Mac password) on every read, whoever reads.
        q[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, nil)!
    }
    let status = SecItemAdd(q as CFDictionary, nil)
    if status != errSecSuccess { die("touchenv: keychain error \(status)") }
}

/// The secret, or nil and why; never exits (the SSH agent keeps running).
func readSecret(_ name: String) -> (data: Data?, status: OSStatus) {
    var q = query(name)
    q[kSecReturnData as String] = true
    var out: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &out)
    return (status == errSecSuccess ? out as? Data : nil, status)
}

func read(_ name: String) -> Data {
    let (data, status) = readSecret(name)
    guard status == errSecSuccess, let data else {
        if status == errSecItemNotFound {
            endAttempt("refused", note: "no secret named \(name)", message: "touchenv: no secret named \(name)")
        }
        endAttempt("failed", note: "keychain error \(status)", message: "touchenv: keychain error \(status)")
    }
    return data
}

func readStdin() -> Data {
    if isatty(0) != 0 {
        // The prompt goes to the terminal, as getpass() did, not to a redirected stdout.
        let tty = open("/dev/tty", O_RDWR | O_CLOEXEC)
        defer { if tty >= 0 { close(tty) } }
        guard let data = readHiddenLine(tty >= 0 ? tty : 0, prompt: "Secret (not shown): ") else { die("touchenv: no input") }
        return data
    }
    return FileHandle.standardInput.readDataToEndOfFile()
}

func validName(_ name: String) -> Bool {
    name.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil
}

// MARK: 5-minute approvals and grants

let approvalLength: TimeInterval = 5 * 60
let maxGrantLength: TimeInterval = 24 * 60 * 60
let maxGrantUses = 500

/// "90d", "8h", "30m" or "1h30m" in seconds; nil for anything else.
func parseLength(_ text: String) -> TimeInterval? {
    var total = 0, digits = "", seen = ""
    for character in text {
        if ("0"..."9").contains(character), digits.count < 5 {
            digits.append(character)
        } else if "dhm".contains(character), !seen.contains(character), let n = Int(digits) {
            total += n * (character == "d" ? 86400 : character == "h" ? 3600 : 60)
            digits = ""
            seen.append(character)
        } else {
            return nil
        }
    }
    return digits.isEmpty && total > 0 ? TimeInterval(total) : nil
}

/// "8 hours", "1 hour 30 minutes".
func spokenLength(_ seconds: TimeInterval) -> String {
    let minutes = Int(seconds) / 60
    var parts: [String] = []
    if minutes >= 60 { parts.append("\(minutes / 60) hour\(minutes / 60 == 1 ? "" : "s")") }
    if minutes % 60 > 0 { parts.append("\(minutes % 60) minute\(minutes % 60 == 1 ? "" : "s")") }
    return parts.joined(separator: " ")
}

/// Time left as 4:59 or 7:59:59.
func clock(_ seconds: Int) -> String {
    seconds >= 3600 ? String(format: "%d:%02d:%02d", seconds / 3600, seconds / 60 % 60, seconds % 60)
                    : String(format: "%d:%02d", seconds / 60, seconds % 60)
}

func times(_ n: Int) -> String { n == 1 ? "1 time" : "\(n) times" }

/// The process and every process above it, each as pid and start time.
func lineage(_ first: pid_t) -> [(pid: pid_t, start: UInt64)] {
    var out: [(pid: pid_t, start: UInt64)] = []
    var pid = first
    for _ in 0..<64 {
        guard pid > 1, let start = startTime(pid) else { break }
        out.append((pid, start))
        guard let parent = parentPid(pid) else { break }
        pid = parent
    }
    return out
}

/// In the temp folder macOS gives each user (private to them), not $TMPDIR, which sandboxes point elsewhere.
func agentSocketPath() -> String {
    var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
    confstr(_CS_DARWIN_USER_TEMP_DIR, &buffer, buffer.count)
    return String(cString: buffer) + "touchenv-agent.sock"
}

func socketAddress(_ path: String) -> sockaddr_un {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &address.sun_path) { raw in
        let bytes = Array(path.utf8.prefix(raw.count - 1))
        raw.copyBytes(from: bytes + [0])
    }
    return address
}

/// Whether the process at the other end of the socket is touchenv, signed like this one. Defence in depth only: the
/// kernel describes whatever that pid runs now, so a process that connects and then execs touchenv passes. What
/// actually guards the socket is the sealing below.
func peerIsTouchenv(_ fd: Int32) -> Bool {
    var token = audit_token_t()
    var length = socklen_t(MemoryLayout<audit_token_t>.size)
    guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0 else { return false }
    let tokenData = withUnsafeBytes(of: &token) { Data($0) }
    var peer: SecCode?, me: SecCode?, myStatic: SecStaticCode?, requirement: SecRequirement?
    guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: tokenData] as CFDictionary, [], &peer) == errSecSuccess,
          SecCodeCopySelf([], &me) == errSecSuccess, let me,
          SecCodeCopyStaticCode(me, [], &myStatic) == errSecSuccess, let myStatic,
          SecCodeCopyDesignatedRequirement(myStatic, [], &requirement) == errSecSuccess, let peer else { return false }
    return SecCodeCheckValidity(peer, [], requirement) == errSecSuccess
}

func peerPid(_ fd: Int32) -> pid_t? {
    var pid = pid_t()
    var length = socklen_t(MemoryLayout<pid_t>.size)
    return getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0 ? pid : nil
}

// The background copy's socket: every message sealed.
//
// Each message on touchenv-agent.sock is AES-GCM sealed with a 32-byte key kept as a Keychain item in touchenv's
// access group (service "touchenv-agent-key", this device only, readable after first unlock, no Touch ID lock, so
// reading it never shows a prompt; made by whichever touchenv needs it first). Only the signed touchenv can read that
// item, so a process that merely passes the code-signature check (connect, then exec touchenv) can neither forge a
// request nor read a reply. A request carries the sender's pid and start time, a time and a random nonce, all
// sealed: the agent refuses one whose pid is not the socket's peer (a relay), whose time is off by more than a
// minute, or whose nonce it has seen. A reply is sealed to that request's nonce, so it can't be replayed to another
// client or reflected back as a request. On the wire: {"touchenv": 2, "box": base64(nonce | ciphertext | tag)}.

let agentKeyService = "touchenv-agent-key"
let agentWireVersion = 2
let agentRequestWindow: TimeInterval = 60

enum AgentWire {
    static let requestLabel = Data("touchenv-agent request \(agentWireVersion)".utf8)
    static let replyLabel = Data("touchenv-agent reply \(agentWireVersion)".utf8)

    static func envelope(_ box: Data) -> Data? {
        try? JSONSerialization.data(withJSONObject: ["touchenv": agentWireVersion, "box": box.base64EncodedString()])
    }

    /// The sealed box inside an envelope; nil for anything else (an old touchenv's plain JSON, garbage).
    static func box(_ data: Data) -> Data? {
        guard let outer = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              outer["touchenv"] as? Int == agentWireVersion, let text = outer["box"] as? String else { return nil }
        return Data(base64Encoded: text)
    }

    /// A request, sealed: the bytes to send and the nonce its reply will be sealed to.
    static func sealRequest(_ message: [String: Any], key: SymmetricKey, pid: pid_t, start: UInt64,
                            now: Date = Date()) -> (data: Data, nonce: Data)? {
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let inner: [String: Any] = ["m": message, "pid": Int(pid), "start": NSNumber(value: start),
                                    "time": now.timeIntervalSince1970, "nonce": nonce.base64EncodedString()]
        guard let plain = try? JSONSerialization.data(withJSONObject: inner),
              let sealed = try? AES.GCM.seal(plain, using: key, authenticating: requestLabel).combined,
              let data = envelope(sealed) else { return nil }
        return (data, nonce)
    }

    enum Refusal: Error, Equatable { case notSealed, forged, wrongPeer, stale, replayed }

    /// Opens a request from `peer` (pid and start time, as the kernel says), remembering its nonce in `seen`.
    static func openRequest(_ data: Data, key: SymmetricKey, peer: pid_t, peerStart: UInt64?, now: Date = Date(),
                            seen: inout [Data: Date]) -> Result<(message: [String: Any], nonce: Data), Refusal> {
        guard let box = box(data) else { return .failure(.notSealed) }
        guard let sealed = try? AES.GCM.SealedBox(combined: box),
              let plain = try? AES.GCM.open(sealed, using: key, authenticating: requestLabel),
              let inner = (try? JSONSerialization.jsonObject(with: plain)) as? [String: Any],
              let message = inner["m"] as? [String: Any], let pid = inner["pid"] as? Int,
              let start = (inner["start"] as? NSNumber)?.uint64Value, let time = inner["time"] as? Double,
              let nonceText = inner["nonce"] as? String, let nonce = Data(base64Encoded: nonceText), nonce.count == 16 else {
            return .failure(.forged)
        }
        guard pid == Int(peer), peerStart == start else { return .failure(.wrongPeer) }
        guard abs(now.timeIntervalSince1970 - time) <= agentRequestWindow else { return .failure(.stale) }
        seen = seen.filter { now.timeIntervalSince($0.value) <= 2 * agentRequestWindow }
        guard seen[nonce] == nil else { return .failure(.replayed) }
        seen[nonce] = now
        return .success((message, nonce))
    }

    static func sealReply(_ message: [String: Any], key: SymmetricKey, nonce: Data) -> Data? {
        guard let plain = try? JSONSerialization.data(withJSONObject: message),
              let sealed = try? AES.GCM.seal(plain, using: key, authenticating: replyLabel + nonce).combined else { return nil }
        return envelope(sealed)
    }

    static func openReply(_ data: Data, key: SymmetricKey, nonce: Data) -> [String: Any]? {
        guard let box = box(data), let sealed = try? AES.GCM.SealedBox(combined: box),
              let plain = try? AES.GCM.open(sealed, using: key, authenticating: replyLabel + nonce) else { return nil }
        return (try? JSONSerialization.jsonObject(with: plain)) as? [String: Any]
    }
}

private let agentKeyLock = NSLock()
private var agentKeyCache: SymmetricKey?

/// The key that seals the agent socket's messages, made on first use; nil if the Keychain won't give it (then
/// nothing is sent, and touchenv asks for Touch ID as if no agent ran). Never shows a prompt: the item has no access
/// control, and the query forbids any UI.
func agentKey() -> SymmetricKey? {
    agentKeyLock.lock()
    defer { agentKeyLock.unlock() }
    if let key = agentKeyCache { return key }
    let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: agentKeyService,
                               kSecAttrAccount as String: "agent", kSecUseDataProtectionKeychain as String: true,
                               kSecAttrSynchronizable as String: false]
    func lookUp() -> Data? {
        var q = base
        q[kSecReturnData as String] = true
        q[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        let quiet = LAContext()
        quiet.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = quiet
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data, data.count == 32 else { return nil }
        return data
    }
    var data = lookUp()
    if data == nil {
        var fresh = Data(count: 32)
        let made = fresh.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard made == errSecSuccess else { return nil }
        var q = base
        q[kSecValueData as String] = fresh
        q[kSecAttrLabel as String] = "touchenv: background agent key"
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        // Another touchenv made it at the same moment: use theirs.
        data = status == errSecSuccess ? fresh : status == errSecDuplicateItem ? lookUp() : nil
    }
    guard let data else { return nil }
    agentKeyCache = SymmetricKey(data: data)
    return agentKeyCache
}

/// One message each way: write it, then close the writing half.
func sendMessage(_ fd: Int32, _ message: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }
    sendData(fd, data)
}

func sendData(_ fd: Int32, _ data: Data) {
    data.withUnsafeBytes { raw in
        var offset = 0
        while offset < raw.count {
            let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
            if n <= 0 { break }
            offset += n
        }
    }
    shutdown(fd, SHUT_WR)
}

func receiveData(_ fd: Int32) -> Data {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 16384)
    while data.count < 4 << 20 {
        let n = read(fd, &buffer, buffer.count)
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { break }
        data.append(buffer, count: n)
    }
    return data
}

func receiveMessage(_ fd: Int32) -> [String: Any]? {
    (try? JSONSerialization.jsonObject(with: receiveData(fd))) as? [String: Any]
}

/// Neither end waits on a stalled peer for long.
func setSocketTimeouts(_ fd: Int32, seconds: Int) {
    var timeout = timeval(tv_sec: seconds, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
}

/// A connection to a running agent that passes the code-signature check, or nil.
func connectAgent() -> Int32? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    var address = socketAddress(agentSocketPath())
    var on: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    setSocketTimeouts(fd, seconds: 5)
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    guard connected == 0, peerIsTouchenv(fd) else { close(fd); return nil }
    return fd
}

/// Said once per process, when the agent running is a touchenv from before the update (it speaks unsealed JSON).
private var toldOldAgent = false

/// One sealed request, one sealed reply; nil when there is no agent, it is an older touchenv, or anything doesn't
/// open (then the caller asks for Touch ID as if no agent ran). `lock` alone still reaches an older agent, in its
/// own unsealed form: ending approvals gives nothing away, and leaves no stale agent behind an update.
func askAgent(_ message: [String: Any]) -> [String: Any]? {
    guard let key = agentKey(), let start = startTime(getpid()),
          let sealed = AgentWire.sealRequest(message, key: key, pid: getpid(), start: start),
          let fd = connectAgent() else { return nil }
    sendData(fd, sealed.data)
    let data = receiveData(fd)
    close(fd)
    if let reply = AgentWire.openReply(data, key: key, nonce: sealed.nonce) { return reply }
    // An agent from before an update closes without a word on a message it can't read; this one always answers.
    guard data.isEmpty else { return nil }
    if message["op"] as? String == "lock", let fd = connectAgent() {
        defer { close(fd) }
        sendMessage(fd, ["op": "lock"])
        return receiveMessage(fd)
    }
    if !toldOldAgent {
        toldOldAgent = true
        FileHandle.standardError.write(Data(("touchenv: the touchenv agent still running is from before an update, so its "
            + "approvals and grants can't be used; touchenv lock ends it\n").utf8))
    }
    return nil
}

/// Starts `touchenv agent` in its own session (so Ctrl-C in the terminal doesn't reach it) unless one runs already.
func startAgent() -> Bool {
    if let fd = connectAgent() { close(fd); return true }
    var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(getpid(), &path, UInt32(path.count)) > 0 else { return false }
    var attributes: posix_spawnattr_t?
    posix_spawnattr_init(&attributes)
    posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID))
    var actions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&actions)
    for fd: Int32 in 0...2 { posix_spawn_file_actions_addopen(&actions, fd, "/dev/null", fd == 0 ? O_RDONLY : O_WRONLY, 0) }
    let argv: [UnsafeMutablePointer<CChar>?] = [strdup(path), strdup("agent"), nil]
    var pid = pid_t()
    let status = posix_spawn(&pid, path, &actions, &attributes, argv, environ)
    argv.forEach { free($0) }
    posix_spawn_file_actions_destroy(&actions)
    posix_spawnattr_destroy(&attributes)
    guard status == 0 else { return false }
    for _ in 0..<40 {
        usleep(50_000)
        if let fd = connectAgent() { close(fd); return true }
    }
    return false
}

/// The background copy: keeps approved secrets in memory, per requester, each for 5 minutes from its own approval or
/// for a grant's length, then exits. Each connection is read and answered on a worker thread with short timeouts, so
/// a peer that stalls holds up only itself; the approvals and grants are touched on the main thread only.
final class Agent: NSObject {
    /// One secret under a 5-minute approval: its own end, and whether it came from touchenv's SSH agent, which makes
    /// it good for signatures only (never for touchenv run or get to hand out the key).
    struct Kept { var data: Data; var expires: Date; var signOnly: Bool }
    struct Approval {
        var start: UInt64; var who: String; var secrets: [String: Kept]
        var expires: Date { secrets.values.map(\.expires).max() ?? .distantPast }
    }
    /// From touchenv grant: covers the requester (pid, start) and every process below it.
    struct Grant { var pid: pid_t; var start: UInt64; var who: String; var secrets: [String: Data]; var expires: Date; var uses: Int }
    var approvals: [pid_t: Approval] = [:]
    var grants: [Grant] = []
    var listener: DispatchSourceRead?
    var statusItem: NSStatusItem!
    var notice: NSPanel?
    let born = Date()
    var standingPrograms: [String] = []
    var standingCheckedAt = Date.distantPast
    var key: SymmetricKey!
    /// Nonces of the requests opened in the last two minutes: none is taken twice.
    var seen: [Data: Date] = [:]
    var shownMenu: [String]?
    var connections = 0
    let maxConnections = 16
    let io = DispatchQueue(label: "touchenv.agent.io", attributes: .concurrent)

    /// The secrets of `names` an approval holds for a request, and when the first of them ends; nil unless it holds
    /// every one, unexpired, and, unless the request is for a signature, none of them for signing only.
    static func approved(_ approval: Approval, names: [String], signing: Bool, now: Date) -> (secrets: [String: Data], ends: Date)? {
        guard !names.isEmpty else { return nil }
        var out: [String: Data] = [:]
        var ends = Date.distantFuture
        for name in names {
            guard let kept = approval.secrets[name], kept.expires > now, signing || !kept.signOnly else { return nil }
            out[name] = kept.data
            ends = min(ends, kept.expires)
        }
        return (out, ends)
    }

    /// The approval with `secrets` added, each for 5 minutes from now: a new approval never lengthens an older one's.
    static func adding(_ secrets: [String: Data], signOnly: Bool, to approval: Approval, now: Date) -> Approval {
        var out = approval
        for (name, data) in secrets {
            out.secrets[name] = Kept(data: data, expires: now.addingTimeInterval(approvalLength), signOnly: signOnly)
        }
        return out
    }

    /// The approval's unexpired secrets, grouped by when they end and whether they only sign.
    static func groups(_ approval: Approval, now: Date) -> [(names: [String], expires: Date, signOnly: Bool)] {
        var out: [(names: [String], expires: Date, signOnly: Bool)] = []
        for (name, kept) in approval.secrets.sorted(by: { $0.key < $1.key }) where kept.expires > now {
            let end = Date(timeIntervalSince1970: kept.expires.timeIntervalSince1970.rounded(.up))
            if let i = out.firstIndex(where: { $0.expires == end && $0.signOnly == kept.signOnly }) {
                out[i].names.append(name)
            } else {
                out.append(([name], end, kept.signOnly))
            }
        }
        return out.sorted { $0.expires < $1.expires }
    }

    func run() -> Never {
        let path = agentSocketPath()
        if let fd = connectAgent() { close(fd); exit(0) }
        // Without the sealing key no request could be opened: no agent, and touchenv asks for Touch ID instead.
        guard let key = agentKey() else { exit(1) }
        self.key = key
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = socketAddress(path)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard fd >= 0, bound == 0, chmod(path, 0o600) == 0, listen(fd, 16) == 0 else { exit(1) }
        signal(SIGPIPE, SIG_IGN)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        source.setEventHandler { [unowned self] in
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            guard self.connections < self.maxConnections else { close(client); return }
            self.connections += 1
            self.io.async {
                self.serve(client)
                close(client)
                DispatchQueue.main.async { self.connections -= 1 }
            }
        }
        source.resume()
        listener = source

        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.image = NSImage(systemSymbolName: "lock.open.fill", accessibilityDescription: "touchenv")
        statusItem.button?.imagePosition = .imageLeading
        Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [unowned self] _ in self.tick() }
        app.run()
        exit(0)
    }

    /// One connection, on a worker thread: read, open, answer on the main thread, seal, send.
    func serve(_ fd: Int32) {
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        setSocketTimeouts(fd, seconds: 2)
        let data = receiveData(fd)
        // The peer as the kernel sees it now, after it wrote: the pid sealed in the request must be this one.
        guard !data.isEmpty else { return }
        // Never an empty answer from here on: touchenv takes silence for an agent from before an update.
        guard peerIsTouchenv(fd), let peer = peerPid(fd), var parent = parentPid(peer) else {
            sendMessage(fd, ["ok": false, "refused": "peer"])
            return
        }
        let peerStart = startTime(peer)
        let opened = DispatchQueue.main.sync {
            AgentWire.openRequest(data, key: key, peer: peer, peerStart: peerStart, seen: &seen)
        }
        let message: [String: Any], nonce: Data
        switch opened {
        case .success(let request):
            (message, nonce) = request
        case .failure(.notSealed):
            // A touchenv from before an update. Lock alone is honoured, as it gives nothing away; nothing else is.
            if let plain = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], plain["op"] as? String == "lock" {
                sendMessage(fd, DispatchQueue.main.sync { lockAll() })
            } else {
                sendMessage(fd, ["ok": false])
            }
            return
        case .failure(let why):
            sendMessage(fd, ["ok": false, "refused": "\(why)"])
            return
        }
        // The agent works out the requester itself, from the kernel's process tree; it takes no one's word for it.
        // Except touchenv's SSH agent's (the request is sealed, so it is touchenv): it asks for the process at the other
        // end of its own socket, as the kernel told it (LOCAL_PEERPID), named by pid and start time.
        var who = requester(from: parent)
        let forSSH = message["for"] != nil
        if forSSH {
            guard let asker = message["for"] as? Int, let start = message["forStart"] as? Int, asker > 1,
                  startTime(pid_t(asker)).map({ Int($0) }) == start else {
                if let sealed = AgentWire.sealReply(["ok": false], key: key, nonce: nonce) { sendData(fd, sealed) }
                return
            }
            parent = pid_t(asker)
            who = requester(from: parent, through: sshTools)
        }
        let above = lineage(parent)
        let reply = DispatchQueue.main.sync { answer(message, who: who, above: above, forSSH: forSSH) }
        if let sealed = AgentWire.sealReply(reply, key: key, nonce: nonce) { sendData(fd, sealed) }
    }

    /// The reply to one opened request; on the main thread.
    func answer(_ message: [String: Any], who: Requester, above: [(pid: pid_t, start: UInt64)], forSSH: Bool) -> [String: Any] {
        let now = Date()
        let ssh = message["ssh"] as? String
        switch message["op"] as? String {
        case "grant":
            guard who.pid > 1, let encoded = message["secrets"] as? [String: String] else { break }
            var secrets: [String: Data] = [:]
            for (name, value) in encoded {
                guard let data = Data(base64Encoded: value) else { return ["ok": false] }
                secrets[name] = data
            }
            let old = approvals[who.pid].flatMap { $0.start == who.start ? $0 : nil }
                ?? Approval(start: who.start, who: who.name, secrets: [:])
            // From touchenv's SSH agent: good for signatures only.
            approvals[who.pid] = Agent.adding(secrets, signOnly: forSSH || message["signOnly"] as? Bool == true, to: old, now: now)
            DispatchQueue.main.async { self.tick() }
            return ["ok": true]
        case "allow":
            guard who.pid > 1, let encoded = message["secrets"] as? [String: String], !encoded.isEmpty,
                  let seconds = message["seconds"] as? Double, seconds >= 60,
                  let uses = message["uses"] as? Int, uses >= 1 else { break }
            var secrets: [String: Data] = [:]
            for (name, value) in encoded { secrets[name] = Data(base64Encoded: value) }
            // A new grant to the same requester for the same secrets replaces the old one.
            grants.removeAll { $0.pid == who.pid && $0.start == who.start && Set($0.secrets.keys) == Set(secrets.keys) }
            grants.append(Grant(pid: who.pid, start: who.start, who: who.name, secrets: secrets,
                                expires: now.addingTimeInterval(min(seconds, maxGrantLength)),
                                uses: min(uses, maxGrantUses)))
            DispatchQueue.main.async { self.tick() }
            return ["ok": true, "who": who.name]
        case "get":
            guard let names = message["names"] as? [String], !names.isEmpty else { break }
            let intent = message["intent"] as? String
            let signing = forSSH && message["sign"] as? Bool == true
            if let approval = approvals[who.pid], approval.start == who.start,
               let found = Agent.approved(approval, names: names, signing: signing, now: now) {
                let left = Int(found.ends.timeIntervalSince(now).rounded(.up))
                showNotice(who: approval.who, names: names, intent: intent, left: "approved for \(clock(left)) more", ssh: ssh)
                return ["ok": true, "secrets": found.secrets.mapValues { $0.base64EncodedString() }, "via": "5-minute"]
            }
            // A grant: the asking process must sit below the requester the grant was given to.
            guard let index = Agent.coveringGrant(grants, names: names, above: above, now: now) else { break }
            grants[index].uses -= 1
            let grant = grants[index]
            var out: [String: String] = [:]
            for name in names { out[name] = grant.secrets[name]!.base64EncodedString() }
            let left = Int(grant.expires.timeIntervalSince(now).rounded(.up))
            showNotice(who: who.name, names: names, intent: intent,
                       left: grant.uses == 0 ? "that was the last use granted"
                                             : "granted for \(clock(left)) more, \(times(grant.uses)) left", ssh: ssh)
            return ["ok": true, "secrets": out, "via": "grant"]
        case "list":
            // What is on, for touchenv grant --list: names, who, time and uses left; never a value.
            var on: [[String: Any]] = []
            for approval in approvals.values {
                for group in Agent.groups(approval, now: now) {
                    on.append(["who": approval.who, "names": group.names, "kind": group.signOnly ? "5-minute-sign" : "5-minute",
                               "left": Int(group.expires.timeIntervalSince(now).rounded(.up))])
                }
            }
            for grant in grants where grant.expires > now && grant.uses > 0 {
                on.append(["who": grant.who, "names": grant.secrets.keys.sorted(), "kind": "grant", "uses": grant.uses,
                           "left": Int(grant.expires.timeIntervalSince(now).rounded(.up))])
            }
            return ["ok": true, "on": on]
        case "lock":
            return lockAll()
        default: break
        }
        return ["ok": false]
    }

    func lockAll() -> [String: Any] {
        let ended = grants.map { ($0.who, $0.secrets.keys.sorted()) }
        approvals.removeAll()
        grants.removeAll()
        DispatchQueue.main.async { self.tick() }
        return ["ok": true, "ended": ended.map { ["who": $0.0, "names": $0.1] }]
    }

    /// The grant that covers a process (`above`: it and its ancestors) for every one of `names`, if any.
    static func coveringGrant(_ grants: [Grant], names: [String], above: [(pid: pid_t, start: UInt64)], now: Date) -> Int? {
        grants.firstIndex { grant in
            grant.expires > now && grant.uses > 0 && names.allSatisfy({ grant.secrets[$0] != nil })
                && above.contains { $0.pid == grant.pid && $0.start == grant.start }
        }
    }

    /// "until 14:05:30".
    static func until(_ date: Date) -> String {
        "until " + DateFormatter.localizedString(from: date, dateStyle: .none, timeStyle: .medium)
    }

    /// The menu's lines: "-" a separator, "!" before Lock Now. Ends are shown as times, so the lines change only when
    /// what is on changes.
    func menuLines(now: Date) -> [String] {
        var lines: [String] = []
        for approval in approvals.values.sorted(by: { $0.who < $1.who }) {
            for group in Agent.groups(approval, now: now) {
                let names = group.names.joined(separator: ", ")
                lines.append("\(approval.who) can \(group.signOnly ? "sign with" : "read") \(names) without asking, "
                             + Agent.until(group.expires))
            }
        }
        for grant in grants.sorted(by: { $0.who < $1.who }) {
            let names = grant.secrets.keys.sorted().joined(separator: ", ")
            lines.append("\(grant.who) and what it runs can read \(names) without asking: \(times(grant.uses)), "
                         + Agent.until(grant.expires))
        }
        if !standingPrograms.isEmpty {
            let count = standingPrograms.count
            lines += ["-", "\(count) standing grant\(count == 1 ? "" : "s") (not ended by Lock Now): "
                      + standingPrograms.joined(separator: ", "), "touchenv grant --list · touchenv lock --all ends them"]
        }
        return lines + ["-", "!Lock Now"]
    }

    /// Drops what expired or whose requester ended; quits when nothing is left. The menu is rebuilt only when its
    /// lines change; the time left in the menu bar, every second.
    func tick() {
        let now = Date()
        approvals = approvals.compactMapValues { approval in
            var approval = approval
            approval.secrets = approval.secrets.filter { $0.value.expires > now }
            return approval.secrets.isEmpty ? nil : approval
        }.filter { pid, approval in startTime(pid) == approval.start }
        grants = grants.filter { $0.expires > now && $0.uses > 0 && startTime($0.pid) == $0.start }
        guard let last = (approvals.values.map(\.expires) + grants.map(\.expires)).max() else {
            // Empty: quit, except in the first seconds, while whoever started the agent is still sending its approval,
            // and while the notice of the last use is still on screen.
            if notice == nil, now.timeIntervalSince(born) > 10 || statusItem.button?.title.isEmpty == false {
                unlink(agentSocketPath())
                exit(0)
            }
            return
        }
        let left = Int(last.timeIntervalSince(now).rounded(.up))
        statusItem.button?.title = " " + clock(left)
        // Standing grants live in the Keychain, not here; looked up every 30 seconds, names only.
        if now.timeIntervalSince(standingCheckedAt) > 30 {
            standingPrograms = standingStore.list().map { tilde($0.program) }
            standingCheckedAt = now
        }
        let lines = menuLines(now: now)
        guard lines != shownMenu else { return }
        shownMenu = lines
        let menu = NSMenu()
        for line in lines {
            if line == "-" {
                menu.addItem(.separator())
            } else if line.hasPrefix("!") {
                let lock = NSMenuItem(title: String(line.dropFirst()), action: #selector(lockNow), keyEquivalent: "")
                lock.target = self
                menu.addItem(lock)
            } else {
                let item = NSMenuItem(title: line, action: nil, keyEquivalent: "")
                item.isEnabled = false
                menu.addItem(item)
            }
        }
        statusItem.menu = menu
    }

    @objc func lockNow() {
        for grant in grants {
            logAccess(AccessEntry(event: "revoke", secrets: grant.secrets.keys.sorted(), outcome: "lock", who: grant.who,
                                  note: "timed grant ended by Lock Now in the menu bar"))
        }
        approvals.removeAll()
        grants.removeAll()
        tick()
    }

    /// A short notice at the top right each time an approval is used, so it never happens unseen.
    func showNotice(who: String, names: [String], intent: String?, left: String, ssh: String? = nil) {
        notice?.orderOut(nil)
        var lines = [ssh.map { "\(who) used \(names.joined(separator: ", ")) to \($0)" } ?? "\(who) read \(names.joined(separator: ", "))"]
        if let intent { lines.append("INTENT: \(intent)") }
        lines.append("No Touch ID asked: \(left). Lock in the menu bar.")
        let stack = NSStackView(views: lines.enumerated().map { index, line in
            let field = NSTextField(wrappingLabelWithString: line)
            field.font = index == 0 ? .boldSystemFont(ofSize: 13) : .systemFont(ofSize: 12)
            field.textColor = index == 0 ? .labelColor : .secondaryLabelColor
            field.preferredMaxLayoutWidth = 280
            return field
        })
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.edgeInsets = NSEdgeInsets(top: 12, left: 14, bottom: 12, right: 14)
        let background = NSVisualEffectView()
        background.material = .hudWindow
        background.state = .active
        background.wantsLayer = true
        background.layer?.cornerRadius = 12
        background.addSubview(stack)
        stack.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([stack.topAnchor.constraint(equalTo: background.topAnchor),
                                     stack.bottomAnchor.constraint(equalTo: background.bottomAnchor),
                                     stack.leadingAnchor.constraint(equalTo: background.leadingAnchor),
                                     stack.trailingAnchor.constraint(equalTo: background.trailingAnchor),
                                     stack.widthAnchor.constraint(equalToConstant: 308)])
        let panel = NSPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.contentView = background
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = true
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary]
        let size = background.fittingSize
        let screen = NSScreen.main?.visibleFrame ?? .zero
        panel.setFrame(NSRect(x: screen.maxX - size.width - 12, y: screen.maxY - size.height - 12,
                              width: size.width, height: size.height), display: true)
        panel.orderFrontRegardless()
        notice = panel
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self, weak panel] in
            panel?.orderOut(nil)
            if self?.notice === panel { self?.notice = nil }
        }
    }
}

// MARK: The access log

// Every read of a secret by get and run, and every grant, revoke, lock, set, rm, export and import, is one line in
// ~/Library/Logs/touchenv-access-YYYY-MM.log (one file per month, 0600, in a folder only you can write): tab-separated
// time, event, secret names, outcome, who asked, the calling program's path, intent, note. Never a value, never part
// of one, never a length. Lines older than two years are removed (whole months, and the oldest month's file pruned
// line by line), checked at most once a day when touchenv writes; all files together stay under accessLogCap, the
// oldest lines going first, with one line saying so. The SSH agent keeps its own log (touchenv-ssh-agent.log).
// Any program running as you can edit these files: the log is a record for you, not evidence against malware.

struct AccessEntry: Equatable {
    var time = accessLogNow()
    var event: String
    var secrets: [String] = []
    var outcome: String
    var who = ""
    var program = ""
    var intent = ""
    var note = ""
}

/// The outcomes of a read, as written in the log.
enum ReadOutcome {
    static let touchID = "touch-id"          // approved with Touch ID or the Mac's password
    static let fiveMinute = "5-minute"       // a "Don't ask again for 5 minutes" approval
    static let grant = "grant"               // a timed grant (touchenv grant --for … --uses …)
    static let standing = "standing-grant"   // a standing grant (touchenv grant --always …)
    static let refused = "refused"           // with the reason in the note
    static let cancelled = "cancelled"       // at the prompt
    static let failed = "failed"             // a Keychain error, or no way to ask
    static let passwordCLI = "password-cli"  // the Mac password typed in the terminal (synced secrets only)
}

let accessLogRetention: TimeInterval = 730 * 86400
var accessLogCap = 64 << 20                 // bytes, all monthly files together
var accessLogNow: () -> Date = { Date() }
let accessLogPrefix = "touchenv-access-"
func accessLogDir() -> String { homePath + "/Library/Logs" }

let logTimeFormatter: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.timeZone = .current
    f.formatOptions = [.withInternetDateTime]
    return f
}()
var logCalendar: Calendar = {
    var c = Calendar(identifier: .gregorian)
    c.timeZone = .current
    return c
}()

func accessLogFile(for date: Date) -> String {
    let c = logCalendar.dateComponents([.year, .month], from: date)
    return accessLogDir() + "/" + accessLogPrefix + String(format: "%04d-%02d.log", c.year!, c.month!)
}

/// The month a log file covers, from its name.
func accessLogMonth(_ file: String) -> (start: Date, end: Date)? {
    guard file.hasPrefix(accessLogPrefix), file.hasSuffix(".log") else { return nil }
    let parts = file.dropFirst(accessLogPrefix.count).dropLast(4).split(separator: "-")
    guard parts.count == 2, parts[0].count == 4, parts[1].count == 2, let year = Int(parts[0]), let month = Int(parts[1]),
          (1...12).contains(month), let start = logCalendar.date(from: DateComponents(year: year, month: month, day: 1)),
          let end = logCalendar.date(byAdding: .month, value: 1, to: start) else { return nil }
    return (start, end)
}

/// A field of a log line: no control or format characters (so no tab or newline to add or split a line, no escape
/// sequence to restyle a terminal, no bidi override to disguise one), at most `limit` characters.
func logField(_ raw: String, limit: Int = 200) -> String {
    var scalars = String.UnicodeScalarView()
    for scalar in raw.unicodeScalars {
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate, .privateUse, .unassigned:
            scalars.append(" ")
        default:
            scalars.append(scalar)
        }
    }
    var text = String(scalars).trimmingCharacters(in: .whitespaces)
    if text.count > limit { text = String(text.prefix(limit - 1)) + "…" }
    return text.isEmpty ? "-" : text
}

func accessLine(_ e: AccessEntry) -> String {
    let names = e.secrets.filter(validName).joined(separator: ",")
    return [logTimeFormatter.string(from: e.time), logField(e.event, limit: 20), names.isEmpty ? "-" : names,
            logField(e.outcome, limit: 30), logField(e.who, limit: 80), logField(e.program, limit: 400),
            logField(e.intent), logField(e.note, limit: 400)].joined(separator: "\t")
}

func parseAccessLine<S: StringProtocol>(_ line: S) -> AccessEntry? {
    let f = String(line).split(separator: Character("\t"), omittingEmptySubsequences: false).map { String($0) }
    guard f.count == 8, let time = logTimeFormatter.date(from: f[0]) else { return nil }
    func v(_ s: String) -> String { s == "-" ? "" : s }
    return AccessEntry(time: time, event: f[1], secrets: f[2] == "-" ? [] : f[2].split(separator: ",").map(String.init),
                       outcome: f[3], who: v(f[4]), program: v(f[5]), intent: v(f[6]), note: v(f[7]))
}

/// Why touchenv won't write the log there, or nil. Makes ~/Library/Logs (0700) when there is none.
func accessLogFolderProblem() -> String? {
    let dir = accessLogDir()
    var st = stat()
    if lstat(dir, &st) != 0 {
        _ = try? FileManager.default.createDirectory(atPath: (dir as NSString).deletingLastPathComponent,
                                                     withIntermediateDirectories: true)
        guard mkdir(dir, 0o700) == 0 || errno == EEXIST, lstat(dir, &st) == 0 else { return "can't make \(dir)" }
    }
    guard st.st_mode & S_IFMT == S_IFDIR, st.st_uid == getuid(), st.st_mode & 0o022 == 0 else {
        return "\(tilde(dir)) is not a folder only you can write"
    }
    return nil
}

/// Opens a file of the log folder: no symbolic link, yours, 0600.
func openLogFile(_ path: String, _ flags: Int32) -> Int32? {
    let fd = open(path, flags | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { return nil }
    var st = stat()
    guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_uid == getuid() else { close(fd); return nil }
    if st.st_mode & 0o777 != 0o600 { fchmod(fd, 0o600) }
    return fd
}

/// Runs `body` holding the log's lock, so pruning never races an append.
func withAccessLogLock<T>(_ body: () -> T) -> T {
    guard let fd = openLogFile(accessLogDir() + "/touchenv-access.lock", O_RDWR | O_CREAT) else { return body() }
    defer { close(fd) }
    flock(fd, LOCK_EX)
    return body()
}

func appendLogLine(_ line: String, to path: String) {
    guard let fd = openLogFile(path, O_WRONLY | O_APPEND | O_CREAT) else { return }
    _ = writeFull(fd, Array((line + "\n").utf8))
    close(fd)
}

func fileSize(_ path: String) -> Int { (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int ?? 0 }

/// Replaces a log file's lines with `lines`, through a private temp file and a rename.
func rewriteLogFile(_ path: String, _ lines: [Substring]) {
    let temp = path + ".new"
    unlink(temp)
    guard let fd = openLogFile(temp, O_WRONLY | O_CREAT | O_EXCL) else { return }
    let text = lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
    let ok = writeFull(fd, Array(text.utf8))
    close(fd)
    if ok { rename(temp, path) } else { unlink(temp) }
}

func logLines(_ path: String) -> [Substring] {
    guard let data = FileManager.default.contents(atPath: path) else { return [] }
    return String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true)
}

/// Removes lines older than two years and, over the cap, the oldest lines, with one line saying how many went.
/// Call holding the lock.
func pruneAccessLog(now: Date) {
    let dir = accessLogDir()
    let cutoff = now.addingTimeInterval(-accessLogRetention)
    var files = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [])
        .filter { accessLogMonth($0) != nil }.sorted()
    for file in files {
        let (start, end) = accessLogMonth(file)!
        let path = dir + "/" + file
        if end <= cutoff {
            unlink(path)
        } else if start < cutoff {
            let lines = logLines(path)
            let kept = lines.filter { parseAccessLine($0).map { $0.time >= cutoff } ?? true }
            if kept.count != lines.count { rewriteLogFile(path, kept) }
        }
    }
    files = files.filter { FileManager.default.fileExists(atPath: dir + "/" + $0) }
    var total = files.reduce(0) { $0 + fileSize(dir + "/" + $1) }
    var dropped = 0
    while total > accessLogCap, files.count > 1 {
        let path = dir + "/" + files.removeFirst()
        dropped += logLines(path).count
        total -= fileSize(path)
        unlink(path)
    }
    if total > accessLogCap, let last = files.last {
        // One month holds more than the cap: keep its newest lines, up to half the cap.
        let path = dir + "/" + last
        let lines = logLines(path)
        var size = 0, keep = lines.count
        while keep > 0, size + lines[keep - 1].utf8.count + 1 <= accessLogCap / 2 {
            size += lines[keep - 1].utf8.count + 1
            keep -= 1
        }
        dropped += keep
        rewriteLogFile(path, Array(lines[keep...]))
    }
    if dropped > 0 {
        appendLogLine(accessLine(AccessEntry(time: now, event: "log", outcome: "dropped",
                                             note: "\(dropped) oldest entries dropped: the log passed its \(accessLogCap >> 20) MB cap")),
                      to: accessLogFile(for: now))
    }
}

var accessLogWarned = false

/// Appends one entry; prunes first when a day has passed since the last pruning, or when this month's file is
/// past half the cap. Never fails the command: a log that can't be written is said once on stderr.
func logAccess(_ entry: AccessEntry) {
    if let problem = accessLogFolderProblem() {
        if !accessLogWarned {
            accessLogWarned = true
            FileHandle.standardError.write("touchenv: not logging this read: \(problem)\n".data(using: .utf8)!)
        }
        return
    }
    withAccessLogLock {
        let marker = accessLogDir() + "/touchenv-access.pruned"
        let last = FileManager.default.contents(atPath: marker).flatMap {
            logTimeFormatter.date(from: String(decoding: $0, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let file = accessLogFile(for: entry.time)
        if last.map({ entry.time.timeIntervalSince($0) > 86400 || entry.time < $0 }) ?? true || fileSize(file) > accessLogCap / 2 {
            pruneAccessLog(now: entry.time)
            if let fd = openLogFile(marker, O_WRONLY | O_CREAT | O_TRUNC) {
                _ = writeFull(fd, Array(logTimeFormatter.string(from: entry.time).utf8))
                close(fd)
            }
        }
        appendLogLine(accessLine(entry), to: file)
    }
}

/// Every entry in every monthly file, oldest first.
func readAccessLog() -> [AccessEntry] {
    let dir = accessLogDir()
    let files = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).filter { accessLogMonth($0) != nil }.sorted()
    let entries = files.flatMap { logLines(dir + "/" + $0).compactMap(parseAccessLine) }
    return entries.enumerated().sorted { ($0.element.time, $0.offset) < ($1.element.time, $1.offset) }.map(\.element)
}

let logUsage = """
usage: touchenv log [--since 24h|7d] [--summary] [NAME ...]

Prints touchenv's access log, newest last: every read of a secret (by touchenv get and run) with who asked, the
calling program, the intent and the outcome (touch-id, 5-minute, grant, standing-grant, refused, cancelled,
failed), and every grant, revoke, lock, set, rm, export and import. Never a value. Needs no Touch ID.
  --since 7d    only the last 7 days (d, h, m)
  --summary     per secret: reads per outcome, and which programs ask for it most
  NAME ...      only lines about these secrets
The log is in ~/Library/Logs/touchenv-access-YYYY-MM.log. Entries are kept two years (730 days), then removed;
all files together stay under 64 MB, the oldest entries going first, with a line saying so.
"""

/// What touchenv log prints.
func accessReport(_ entries: [AccessEntry], since: Date?, names: [String], summary: Bool) -> [String] {
    let shown = entries.filter { e in
        (since.map { e.time >= $0 } ?? true) && (names.isEmpty || e.secrets.contains { names.contains($0) })
    }
    let display = DateFormatter()
    display.dateFormat = "yyyy-MM-dd HH:mm:ss"
    display.timeZone = logCalendar.timeZone
    func asker(_ e: AccessEntry) -> String {
        let who = e.who.isEmpty ? "?" : logField(e.who, limit: 80)
        return e.program.isEmpty ? who : "\(who) (\(tilde(logField(e.program, limit: 400))))"
    }
    guard summary else {
        return shown.map { e in
            var line = "\(display.string(from: e.time))  \(logField(e.event, limit: 20))"
            if !e.secrets.isEmpty { line += "  \(e.secrets.joined(separator: ","))" }
            line += "  \(logField(e.outcome, limit: 30))  \(asker(e))"
            if !e.intent.isEmpty { line += "  intent: \(logField(e.intent))" }
            if !e.note.isEmpty { line += "  (\(logField(e.note, limit: 400)))" }
            return line
        }
    }
    var out: [String] = []
    let reads = shown.filter { $0.event == "read" }
    let secrets = Set(reads.flatMap(\.secrets)).filter { names.isEmpty || names.contains($0) }.sorted()
    for name in secrets {
        let mine = reads.filter { $0.secrets.contains(name) }
        var outcomes: [String: Int] = [:], askers: [String: Int] = [:]
        for e in mine {
            outcomes[e.outcome, default: 0] += 1
            askers[asker(e), default: 0] += 1
        }
        let byOutcome = outcomes.sorted { ($1.value, $0.key) < ($0.value, $1.key) }.map { "\($0.key) \($0.value)" }
        out.append("\(name): \(mine.count) read\(mine.count == 1 ? "" : "s"): \(byOutcome.joined(separator: ", "))")
        for (who, n) in askers.sorted(by: { ($1.value, $0.key) < ($0.value, $1.key) }) {
            out.append(String(format: "  %5d  ", n) + who)
        }
    }
    if out.isEmpty { out.append("no reads logged\(since == nil ? "" : " in that time")") }
    return out
}

// The read (or set, rm, grant…) under way, so that whatever ends it, the prompt cancelled or a Keychain error,
// writes its one line.
struct AccessAttempt { var event: String; var secrets: [String]; var who: String; var program: String; var intent: String }
var currentAttempt: AccessAttempt?

func beginAttempt(_ event: String, _ names: [String], who: Requester, intent: String?, caller: Caller?? = nil) {
    let program = caller.map { callingProgram(who, caller: $0) } ?? callingProgram(who)
    currentAttempt = AccessAttempt(event: event, secrets: names, who: who.name, program: program,
                                   intent: intent ?? "")
}

func logAttempt(_ outcome: String, note: String = "") {
    guard let a = currentAttempt else { return }
    currentAttempt = nil
    logAccess(AccessEntry(event: a.event, secrets: a.secrets, outcome: outcome, who: a.who, program: a.program,
                          intent: a.intent, note: note))
}

func endAttempt(_ outcome: String, note: String = "", message: String, code: Int32 = 1) -> Never {
    logAttempt(outcome, note: note)
    die(message, code)
}

// MARK: Standing grants

// touchenv grant --always --for-program PROGRAM NAME…: one Touch ID, then that one program reads those secrets with
// touchenv get or run without asking, until revoked (or a --for / --uses limit set then runs out), across restarts
// and while the screen is locked. The record and a copy of each secret are one Keychain item (service
// "touchenv-standing", account = the program's real path) in touchenv's own keychain access group: only touchenv,
// signed with its team's entitlement, can make, read or change it; no file another program could write. The item
// has no userPresence (that is the point) and is AfterFirstUnlockThisDeviceOnly: never synced, readable once you have
// logged in since the Mac started, also when the screen is locked.
//
// Who counts as the program, checked on every read against touchenv's parent process (the one that ran it):
//  - a signed program or app: the process satisfies the designated requirement recorded when the grant was made
//    (team ID + identifier for a Developer ID program; the exact build's hash for an ad hoc one), checked with
//    SecCodeCheckValidity on the running process, wherever the file lies.
//  - a script: the parent is Apple's own shell (/bin/sh, bash, zsh, dash, ksh, csh, tcsh; its signature checked)
//    whose arguments name the script file (no -c, no -s), resolved from the shell's folder to the recorded real
//    path; that file still has the SHA-256 recorded; and it and every folder above it can be changed only by you
//    (or root: a root-owned sticky folder like /tmp is fine).
// Not checked against the app above it: unattended runs come from launchd or a scheduler, not the terminal you
// made the grant in. What it does not stop: anything running as you can run the program and read what it prints.

let standingService = "touchenv-standing"
let interpreterPaths: Set<String> = ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/ksh", "/bin/csh", "/bin/tcsh"]
let maxStandingLength: TimeInterval = 3650 * 86400
let maxStandingUses = 1_000_000

struct StandingGrant: Codable, Equatable {
    var program: String           // real path: the script, the program's executable or the .app
    var kind: String              // "script" or "signed"
    var sha256: String?           // a script's contents when the grant was made
    var requirement: String?      // a signed program's designated requirement
    var signer: String?           // for people: "team ABCDE12345, com.example.tool" or "ad hoc"
    var names: [String]
    var created: Date
    var expires: Date?
    var usesLeft: Int?
    var lastUsed: Date?
    var reads: Int = 0
    var madeBy: String = ""
}

func encodeStanding(_ grant: StandingGrant) -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .secondsSince1970
    encoder.outputFormatting = .sortedKeys
    return try! encoder.encode(grant)
}

func decodeStanding(_ data: Data) -> StandingGrant? {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .secondsSince1970
    return try? decoder.decode(StandingGrant.self, from: data)
}

func encodeValues(_ values: [String: Data]) -> Data {
    try! JSONSerialization.data(withJSONObject: values.mapValues { $0.base64EncodedString() })
}

func decodeValues(_ data: Data) -> [String: Data]? {
    guard let raw = (try? JSONSerialization.jsonObject(with: data)) as? [String: String] else { return nil }
    var out: [String: Data] = [:]
    for (name, value) in raw {
        guard let decoded = Data(base64Encoded: value) else { return nil }
        out[name] = decoded
    }
    return out
}

protocol StandingStore: AnyObject {
    /// The records, without the secrets.
    func list() -> [StandingGrant]
    func values(_ program: String) -> [String: Data]?
    /// Makes or replaces the grant for grant.program.
    func put(_ grant: StandingGrant, values: [String: Data]) -> OSStatus
    /// Changes the record (counts, last use) only.
    func update(_ grant: StandingGrant) -> OSStatus
    func remove(_ program: String) -> OSStatus
}

final class KeychainStandingStore: StandingStore {
    func base(_ program: String?) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: standingService,
                                kSecUseDataProtectionKeychain as String: true, kSecAttrSynchronizable as String: false]
        if let program { q[kSecAttrAccount as String] = program }
        return q
    }

    func list() -> [StandingGrant] {
        var q = base(nil)
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitAll
        q[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let found = out as? [[String: Any]] else { return [] }
        return found.compactMap { item in
            guard let program = item[kSecAttrAccount as String] as? String, let data = item[kSecAttrGeneric as String] as? Data,
                  let grant = decodeStanding(data), grant.program == program else { return nil }
            return grant
        }.sorted { $0.program < $1.program }
    }

    func values(_ program: String) -> [String: Data]? {
        var q = base(program)
        q[kSecReturnData as String] = true
        q[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return decodeValues(data)
    }

    func put(_ grant: StandingGrant, values: [String: Data]) -> OSStatus {
        SecItemDelete(base(grant.program) as CFDictionary)
        var q = base(grant.program)
        q[kSecAttrGeneric as String] = encodeStanding(grant)
        q[kSecValueData as String] = encodeValues(values)
        q[kSecAttrLabel as String] = "touchenv standing grant: \(grant.program)"
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(q as CFDictionary, nil)
    }

    func update(_ grant: StandingGrant) -> OSStatus {
        SecItemUpdate(base(grant.program) as CFDictionary, [kSecAttrGeneric as String: encodeStanding(grant)] as CFDictionary)
    }

    func remove(_ program: String) -> OSStatus { SecItemDelete(base(program) as CFDictionary) }
}

var standingStore: StandingStore = KeychainStandingStore()

func sha256Hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

func realPath(_ path: String) -> String? {
    guard let resolved = realpath(path, nil) else { return nil }
    defer { free(resolved) }
    return String(cString: resolved)
}

func expandTilde(_ path: String) -> String {
    path == "~" ? homePath : path.hasPrefix("~/") ? homePath + path.dropFirst(1) : path
}

/// Why a script at this real path might not be what was granted, or nil: it and every folder above it must be a
/// regular file and folders (no symbolic link), owned by you or root, not writable by group or others (a folder
/// owned by root with the sticky bit, like /tmp, is fine: others can't rename or replace what is yours in it).
func pathSafetyProblem(_ path: String) -> String? {
    guard path.hasPrefix("/") else { return "\(path) is not a full path" }
    var prefixes = ["/"]
    var current = ""
    for part in path.split(separator: "/") {
        current += "/" + part
        prefixes.append(current)
    }
    let me = getuid()
    for (i, p) in prefixes.enumerated() {
        var st = stat()
        guard lstat(p, &st) == 0 else { return "\(tilde(p)) can't be looked at" }
        let type = st.st_mode & S_IFMT
        if type == S_IFLNK { return "\(tilde(p)) is a symbolic link" }
        guard st.st_uid == me || st.st_uid == 0 else { return "\(tilde(p)) belongs to another user" }
        if i == prefixes.count - 1 {
            guard type == S_IFREG else { return "\(tilde(p)) is not a regular file" }
            if st.st_mode & 0o022 != 0 { return "\(tilde(p)) can be changed by other users" }
        } else {
            guard type == S_IFDIR else { return "\(tilde(p)) is not a folder" }
            if st.st_mode & 0o022 != 0 && !(st.st_mode & S_ISVTX != 0 && st.st_uid == 0) {
                return "the folder \(tilde(p)) can be changed by other users"
            }
        }
    }
    return nil
}

struct IdentityProblem: Error, CustomStringConvertible { let description: String; init(_ d: String) { description = d } }

/// What `#!/usr/bin/env NAME` runs with this PATH: the real path of the first executable file NAME in it, the way
/// env looks (an empty or relative entry is taken from `cwd`; no PATH means /usr/bin:/bin). nil when there is none.
func envInterpreter(_ name: String, path: String?, cwd: String = FileManager.default.currentDirectoryPath) -> String? {
    guard !name.isEmpty, !name.contains("/") else { return nil }
    for entry in (path ?? "/usr/bin:/bin").split(separator: ":", omittingEmptySubsequences: false) {
        let folder = entry.isEmpty ? cwd : entry.hasPrefix("/") ? String(entry) : cwd + "/" + entry
        let candidate = folder + "/" + name
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: candidate, isDirectory: &isDirectory), !isDirectory.boolValue,
           access(candidate, X_OK) == 0 {
            return realPath(candidate) ?? candidate
        }
    }
    return nil
}

/// Programs that run whatever code they are handed (a script, -c, -e): a standing grant to one of them reaches every
/// script it runs. By file name, ignoring a version (python3.12, perl5.34).
let codeRunners: Set<String> = ["python", "pythonw", "node", "nodejs", "deno", "bun", "ruby", "irb", "perl", "php",
                                "lua", "luajit", "osascript", "jxa", "java", "jshell", "swift", "tclsh", "wish", "expect",
                                "pwsh", "powershell", "rscript", "r", "julia", "elixir", "erl", "escript", "ghci",
                                "runghc", "awk", "gawk", "nawk", "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
                                "nu", "xonsh", "env", "xargs", "npx", "npm", "pnpm", "yarn", "uv", "uvx", "pipx", "make"]

/// Whether a program (by path) runs whatever code it is given; see codeRunners.
func runsAnyCode(_ path: String) -> Bool {
    var name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
    if name.hasSuffix(".app") { return false }
    while let last = name.last, last.isNumber || last == "." || last == "-" { name.removeLast() }
    return codeRunners.contains(name)
}

/// What a standing grant for this path would be bound to: a script's real path and SHA-256, or a signed program's
/// designated requirement. The secrets, times and counts are left for the caller to fill in.
func identifyProgram(_ given: String) -> Result<StandingGrant, IdentityProblem> {
    let expanded = expandTilde(given)
    guard let real = realPath(expanded.hasPrefix("/") ? expanded : FileManager.default.currentDirectoryPath + "/" + expanded) else {
        return .failure(IdentityProblem("no such file: \(given)"))
    }
    var isDir: ObjCBool = false
    FileManager.default.fileExists(atPath: real, isDirectory: &isDir)
    var template = StandingGrant(program: real, kind: "signed", names: [], created: Date())
    if !isDir.boolValue {
        guard let handle = FileHandle(forReadingAtPath: real) else { return .failure(IdentityProblem("can't read \(given)")) }
        let head = handle.readData(ofLength: 512)
        try? handle.close()
        if head.starts(with: Data("#!".utf8)) {
            let firstLine = String(decoding: head.prefix { $0 != 0x0A }.dropFirst(2), as: UTF8.self)
            var words = firstLine.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            if words.first == "/usr/bin/env", words.count > 1 {
                let name = words[1]
                words = ["/bin/" + name]
                if interpreterPaths.contains("/bin/" + name) {
                    // What env will run is the first one on PATH: a Homebrew bash, say, is not the Mac's own shell, so
                    // the grant would never match and unattended runs would wait for Touch ID instead.
                    switch envInterpreter(name, path: ProcessInfo.processInfo.environment["PATH"]) {
                    case .some(let found) where interpreterPaths.contains(found):
                        break
                    case .some(let found):
                        return .failure(IdentityProblem(
                            "\(given) starts with #!/usr/bin/env \(name), which runs \(tilde(found)) here (the first \(name) "
                            + "on your PATH), not the Mac's own /bin/\(name); standing grants trust only the shells in /bin, "
                            + "so it would never match. Change its first line to #!/bin/\(name)"))
                    case .none:
                        return .failure(IdentityProblem("\(given) starts with #!/usr/bin/env \(name), and there is no \(name) on your PATH"))
                    }
                }
            }
            guard let interpreter = words.first, interpreterPaths.contains(interpreter) else {
                return .failure(IdentityProblem("\(given) is a script for \(words.first ?? "nothing"); standing grants take "
                                                + "shell scripts (#!/bin/sh, bash, zsh, dash, ksh, csh) or signed programs"))
            }
            if let problem = pathSafetyProblem(real) { return .failure(IdentityProblem(problem)) }
            guard let contents = FileManager.default.contents(atPath: real) else { return .failure(IdentityProblem("can't read \(given)")) }
            template.kind = "script"
            template.sha256 = sha256Hex(contents)
            return .success(template)
        }
    } else if !real.hasSuffix(".app") {
        return .failure(IdentityProblem("\(given) is a folder, not a program, script or .app"))
    }
    var staticCode: SecStaticCode?
    var requirement: SecRequirement?
    var text: CFString?
    var info: CFDictionary?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: real) as CFURL, [], &staticCode) == errSecSuccess, let staticCode,
          SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess else {
        return .failure(IdentityProblem("\(given) is neither a shell script nor a validly signed program"))
    }
    guard SecCodeCopyDesignatedRequirement(staticCode, [], &requirement) == errSecSuccess, let requirement,
          SecRequirementCopyString(requirement, [], &text) == errSecSuccess, let text else {
        return .failure(IdentityProblem("can't read \(given)'s signature"))
    }
    SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
    let details = info as? [String: Any] ?? [:]
    let identifier = details[kSecCodeInfoIdentifier as String] as? String ?? "?"
    if let team = details[kSecCodeInfoTeamIdentifier as String] as? String {
        template.signer = "team \(team), \(identifier)"
    } else if (text as String).contains("anchor apple") && !(text as String).contains("anchor apple generic") {
        template.signer = "Apple, \(identifier)"
    } else {
        template.signer = "ad hoc, \(identifier): this exact build only"
    }
    template.requirement = text as String
    return .success(template)
}

/// The process that ran touchenv, as the kernel tells it. (Not its environment: macOS hides that from other
/// processes, so a shell started with BASH_ENV or exported BASH_FUNC_… functions can't be told apart. docs/security.md.)
struct Caller { var pid: pid_t; var start: UInt64; var executable: String; var arguments: [String]; var cwd: String }

func processPath(_ pid: pid_t) -> String? {
    var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
    return String(cString: path)
}

func processCwd(_ pid: pid_t) -> String? {
    var info = proc_vnodepathinfo()
    let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, size) == size else { return nil }
    return withUnsafeBytes(of: &info.pvi_cdir.vip_path) { raw in
        String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
    }
}

func callerInfo(_ pid: pid_t) -> Caller? {
    guard pid > 1, let start = startTime(pid), let executable = processPath(pid) else { return nil }
    return Caller(pid: pid, start: start, executable: executable, arguments: processArguments(pid), cwd: processCwd(pid) ?? "")
}

/// The script a shell was started on, from its arguments: the first one after the options. nil when it was given
/// commands instead (-c, -s, stdin) or an option that takes a file of its own (--rcfile, --init-file).
func scriptArgument(_ args: [String]) -> String? {
    let longOptions: Set<String> = ["--login", "--noprofile", "--norc", "--posix", "--noediting", "--verbose"]
    var i = 1
    while i < args.count {
        let a = args[i]
        if a == "--" || a == "-" { i += 1; break }
        if a.hasPrefix("--") {
            guard longOptions.contains(a) else { return nil }
            i += 1
            continue
        }
        guard (a.hasPrefix("-") || a.hasPrefix("+")), a.count > 1 else { break }
        let letters = a.dropFirst()
        if letters.contains("c") || letters.contains("s") { return nil }
        i += letters.contains("o") || letters.contains("O") ? 2 : 1
    }
    return i < args.count ? args[i] : nil
}

/// The real path of the script the caller (a shell) runs, if it is one.
func interpretedScript(_ caller: Caller) -> String? {
    guard interpreterPaths.contains(caller.executable), let argument = scriptArgument(caller.arguments) else { return nil }
    if argument.hasPrefix("/") { return realPath(argument) }
    guard caller.cwd.hasPrefix("/") else { return nil }
    return realPath(caller.cwd + "/" + argument)
}

/// The calling program's path for the log: the script when a shell runs one, else the asking app's executable.
func callingProgram(_ who: Requester) -> String { callingProgram(who, caller: callerInfo(getppid())) }

/// The same, with the caller already looked up (callerInfo(getppid())).
func callingProgram(_ who: Requester, caller: Caller?) -> String {
    if let caller, let script = interpretedScript(caller) { return script }
    return who.pid > 1 ? processPath(who.pid) ?? "" : ""
}

/// Whether a running process satisfies a code requirement (its signature checked by the Security framework).
func processSatisfies(_ pid: pid_t, _ requirementText: String) -> Bool {
    var code: SecCode?
    var requirement: SecRequirement?
    guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess,
          let code, SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
          let requirement else { return false }
    return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
}

struct CodeChecks {
    var applePlatform: (pid_t) -> Bool
    var satisfies: (pid_t, String) -> Bool
}
let realCodeChecks = CodeChecks(applePlatform: { processSatisfies($0, "anchor apple") }, satisfies: processSatisfies)

enum StandingDecision: Equatable {
    case none
    case allowed(StandingGrant)
    /// The caller is the granted program, but not as it was: refused, no prompt.
    case refused(program: String, reason: String)
    /// The grant ran out: logged, then touchenv asks as usual.
    case ended(program: String, reason: String)
}

func standingDecision(_ grants: [StandingGrant], names: [String], caller: Caller, checks: CodeChecks, now: Date) -> StandingDecision {
    let script = interpretedScript(caller)
    let executable = realPath(caller.executable)
    var outcome = StandingDecision.none
    for grant in grants where !names.isEmpty && names.allSatisfy(grant.names.contains) {
        var reason: String?
        if grant.kind == "script" {
            guard script == grant.program else { continue }
            if !checks.applePlatform(caller.pid) {
                reason = "\(caller.executable) is not the system's own shell"
            } else if let problem = pathSafetyProblem(grant.program) {
                reason = problem
            } else if FileManager.default.contents(atPath: grant.program).map(sha256Hex) != grant.sha256 {
                reason = "\(tilde(grant.program)) changed since the standing grant was made (its SHA-256 differs)"
            }
        } else if !(grant.requirement.map { checks.satisfies(caller.pid, $0) } ?? false) {
            guard let executable, executable == grant.program || executable.hasPrefix(grant.program + "/") else { continue }
            reason = "\(tilde(grant.program)) is not signed as it was when the standing grant was made"
        }
        if let reason {
            if outcome == .none { outcome = .refused(program: grant.program, reason: reason) }
            continue
        }
        if let expires = grant.expires, expires <= now {
            if outcome == .none { outcome = .ended(program: grant.program, reason: "the standing grant expired") }
            continue
        }
        if let uses = grant.usesLeft, uses <= 0 {
            if outcome == .none { outcome = .ended(program: grant.program, reason: "the standing grant's uses ran out") }
            continue
        }
        return .allowed(grant)
    }
    return outcome
}

enum StandingRead { case none, secrets([String: Data]), refused(String) }

/// Runs `body` holding the standing grants' lock, so two reads never both take a grant's last use.
func withStandingLock<T>(_ body: () -> T) -> T {
    guard ensurePrivateDir(supportDir()),
          case let fd = open(supportDir() + "/standing.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600), fd >= 0 else {
        return body()
    }
    defer { close(fd) }
    flock(fd, LOCK_EX)
    return body()
}

/// get and run ask this first. The secrets when a standing grant covers the caller for all of `names`; a refusal
/// (to exit on, with no prompt) when the caller is a granted program that changed; otherwise .none, to ask as usual.
/// `stillThere` checks, after the checks, that the caller is still the process they were made on.
func standingRead(names: [String], caller: Caller?, who: String, intent: String?, store: StandingStore = standingStore,
                  checks: CodeChecks = realCodeChecks, now: Date = Date(), stillThere: (Caller) -> Bool) -> StandingRead {
    guard let caller else { return .none }
    let grants = store.list()
    if grants.isEmpty { return .none }
    func log(_ outcome: String, _ program: String, _ note: String = "") {
        logAccess(AccessEntry(time: now, event: "read", secrets: names, outcome: outcome, who: who, program: program,
                              intent: intent ?? "", note: note))
    }
    switch standingDecision(grants, names: names, caller: caller, checks: checks, now: now) {
    case .none:
        return .none
    case .ended(let program, let reason):
        log(ReadOutcome.refused, program, "standing grant not used: \(reason); asking instead")
        return .none
    case .refused(let program, let reason):
        log(ReadOutcome.refused, program, reason)
        return .refused(reason)
    case .allowed(let found):
        return withStandingLock {
            // Again under the lock: another read may have taken the last use, or a revoke happened.
            guard var grant = store.list().first(where: { $0.program == found.program }), grant.sha256 == found.sha256,
                  grant.requirement == found.requirement, grant.usesLeft.map({ $0 > 0 }) ?? true else {
                log(ReadOutcome.refused, found.program, "the standing grant changed or ran out meanwhile")
                return .refused("the standing grant changed or ran out meanwhile")
            }
            guard stillThere(caller) else {
                log(ReadOutcome.refused, grant.program, "the calling process went away during the checks")
                return .refused("the calling process went away during the checks")
            }
            guard let values = store.values(grant.program), names.allSatisfy({ values[$0] != nil }) else {
                log(ReadOutcome.failed, grant.program, "the standing grant's copy can't be read")
                return .refused("the standing grant's copy of the secret can't be read")
            }
            grant.reads += 1
            grant.lastUsed = now
            if let uses = grant.usesLeft { grant.usesLeft = uses - 1 }
            _ = store.update(grant)
            log(ReadOutcome.standing, grant.program, grant.usesLeft.map { "\($0) uses left" } ?? "")
            var out: [String: Data] = [:]
            for name in names { out[name] = values[name] }
            return .secrets(out)
        }
    }
}

/// The caller is still the process the checks were made on, and still touchenv's parent.
func callerStillThere(_ caller: Caller) -> Bool { startTime(caller.pid) == caller.start && getppid() == caller.pid }

/// Matches what someone typed after --revoke to the grants: the real path, the path as given, or ~/….
func standingMatching(_ given: String, in grants: [StandingGrant]) -> [StandingGrant] {
    let expanded = expandTilde(given)
    let real = realPath(expanded.hasPrefix("/") ? expanded : FileManager.default.currentDirectoryPath + "/" + expanded)
    return grants.filter { $0.program == expanded || $0.program == real || tilde($0.program) == given }
}

/// Ends standing grants: the ones matching `program`, or all with nil. Logged. Returns those ended.
@discardableResult
func revokeStanding(_ program: String?, who: String, how: String, store: StandingStore = standingStore) -> [StandingGrant] {
    let grants = store.list()
    let ending = program.map { standingMatching($0, in: grants) } ?? grants
    for grant in ending where store.remove(grant.program) == errSecSuccess {
        logAccess(AccessEntry(event: "revoke", secrets: grant.names, outcome: "standing", who: who, program: grant.program,
                              note: how))
    }
    let left = Set(store.list().map(\.program))
    return ending.filter { !left.contains($0.program) }
}

/// After set or rm: the copies standing grants hold of `name` take the new value, or lose it (nil). A grant left
/// with no secret ends. Returns how many grants were changed.
@discardableResult
func standingSecretChanged(_ name: String, to data: Data?, who: String, store: StandingStore = standingStore) -> Int {
    var changed = 0
    for var grant in store.list() where grant.names.contains(name) {
        guard var values = store.values(grant.program) else { continue }
        if let data {
            values[name] = data
        } else {
            values[name] = nil
            grant.names.removeAll { $0 == name }
        }
        if grant.names.isEmpty {
            revokeStanding(grant.program, who: who, how: "its last secret was deleted", store: store)
        } else if store.put(grant, values: values) == errSecSuccess {
            changed += 1
        }
    }
    return changed
}

/// One standing grant, for touchenv grant --list.
func describeStanding(_ g: StandingGrant, now: Date = Date()) -> [String] {
    let day = DateFormatter()
    day.dateFormat = "yyyy-MM-dd HH:mm"
    let identity = g.kind == "script" ? "script, SHA-256 \(g.sha256.map { String($0.prefix(12)) } ?? "?")…"
                                      : "signed: \(g.signer ?? "?")"
    var limits: [String] = []
    if let expires = g.expires { limits.append(expires > now ? "until \(day.string(from: expires))" : "expired") }
    if let uses = g.usesLeft { limits.append("\(times(uses)) left") }
    return ["  \(tilde(g.program))  (\(identity))",
            "    reads \(g.names.joined(separator: ", ")) · made \(day.string(from: g.created))"
            + (g.madeBy.isEmpty ? "" : " from \(g.madeBy)")
            + " · last used \(g.lastUsed.map { day.string(from: $0) } ?? "never") · \(g.reads) read\(g.reads == 1 ? "" : "s")"
            + " · " + (limits.isEmpty ? "no time or use limit" : limits.joined(separator: ", "))]
}

/// What touchenv lock says about standing grants (and ends them with --all).
func lockStanding(all: Bool, who: String, store: StandingStore = standingStore) -> String? {
    if all {
        let ended = revokeStanding(nil, who: who, how: "touchenv lock --all", store: store)
        return ended.isEmpty ? nil : "ended \(ended.count) standing grant\(ended.count == 1 ? "" : "s"): "
            + ended.map { tilde($0.program) }.joined(separator: ", ")
    }
    let left = store.list()
    guard !left.isEmpty else { return nil }
    return "\(left.count) standing grant\(left.count == 1 ? "" : "s") still on ("
        + left.map { tilde($0.program) }.joined(separator: ", ")
        + "): touchenv grant --list shows them; touchenv grant --revoke PROGRAM or touchenv lock --all ends them"
}

// MARK: The Mac password, typed in the terminal (iCloud-synced secrets only)

// get, run and grant --password: the account password of the user running touchenv, typed at a no-echo prompt on
// the controlling terminal (/dev/tty), approves instead of Touch ID. Only for secrets synced through iCloud Keychain:
// those carry no access control (iCloud won't take one), so touchenv's own check is the gate either way, Touch ID or
// password. Local secrets carry userPresence, which only Touch ID or the system's own password window can satisfy
// (LocalAuthentication has no public way to hand it a typed account password), so --password refuses them.
// The password: read into a buffer touchenv allocates, never an argument, the environment or stdin; checked with
// OpenDirectory (ODRecord.verifyPassword on the current user's record), which takes an NSString: that one copy
// can't be erased, and lives until it is freed. touchenv's own buffer is wiped (memset_s) as soon as the check is
// done. Wrong passwords are counted in a Keychain item in touchenv's access group (no other program can reset it):
// each failure doubles the wait before the next try (1 s, 2 s, 4 s … 1 hour), across runs; success clears it.
// The account's own lockout policy, if one is set, counts these failures too.

enum PasswordCheck: Equatable { case ok, wrong, error(String) }

struct PasswordThrottle: Codable, Equatable {
    var failures = 0
    var notBefore = Date.distantPast
}

protocol ThrottleStore: AnyObject {
    /// nil when the count can't be read: then no password is checked at all.
    func load() -> PasswordThrottle?
    func save(_ throttle: PasswordThrottle) -> Bool
}

final class KeychainThrottleStore: ThrottleStore {
    let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                               kSecAttrService as String: "touchenv-password-throttle",
                               kSecAttrAccount as String: "wrong-passwords",
                               kSecUseDataProtectionKeychain as String: true, kSecAttrSynchronizable as String: false]
    func load() -> PasswordThrottle? {
        var q = base
        q[kSecReturnData as String] = true
        q[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return PasswordThrottle() }
        guard status == errSecSuccess, let data = out as? Data else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(PasswordThrottle.self, from: data)
    }
    func save(_ throttle: PasswordThrottle) -> Bool {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let data = try! encoder.encode(throttle)
        let status = SecItemUpdate(base as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var q = base
            q[kSecValueData as String] = data
            q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            q[kSecAttrLabel as String] = "touchenv: wrong Mac passwords typed in the terminal"
            return SecItemAdd(q as CFDictionary, nil) == errSecSuccess
        }
        return status == errSecSuccess
    }
}

let passwordTries = 3
var throttleUnit: TimeInterval = 1          // tests make it shorter
var throttleStore: ThrottleStore = KeychainThrottleStore()
var passwordVerifier: (UnsafeBufferPointer<UInt8>) -> PasswordCheck = verifyAccountPassword
var syncedLookup: (String) -> Bool? = { synced($0) }
var ttyPath = "/dev/tty"
/// Tests check the buffer after wiping, before it is freed.
var passwordWiped: ((UnsafeMutablePointer<UInt8>, Int) -> Void)?

/// The wait after `failures` wrong passwords in a row: 1, 2, 4 … units, an hour at most.
func throttleDelay(_ failures: Int) -> TimeInterval {
    failures <= 0 ? 0 : min(pow(2, Double(min(failures, 30) - 1)), 3600) * throttleUnit
}

func currentUserName() -> String? {
    guard let entry = getpwuid(getuid()) else { return nil }
    return String(cString: entry.pointee.pw_name)
}

/// Whether `password` is the account password of the user running touchenv, asked of OpenDirectory.
func verifyAccountPassword(_ password: UnsafeBufferPointer<UInt8>) -> PasswordCheck {
    guard let name = currentUserName(), let bytes = password.baseAddress else { return .error("can't tell which account this is") }
    // The one copy touchenv can't wipe: OpenDirectory takes the password as a string object.
    guard let text = NSString(bytes: bytes, length: password.count, encoding: String.Encoding.utf8.rawValue) else { return .wrong }
    do {
        let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeAuthentication))
        let record = try node.record(withRecordType: kODRecordTypeUsers, name: name, attributes: nil)
        try record.verifyPassword(text as String)
        return .ok
    } catch let error as NSError {
        return error.code == 5000 ? .wrong : .error(error.localizedDescription)   // 5000: kODErrorCredentialsInvalid
    }
}

/// Terminal text: no control characters (who asks comes from process names, which a program chooses).
func terminalText(_ raw: String) -> String {
    String(String.UnicodeScalarView(raw.unicodeScalars.map {
        switch $0.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator: return " "
        default: return $0
        }
    }))
}

func writeTTY(_ fd: Int32, _ text: String) { _ = writeFull(fd, Array(text.utf8)) }

// What the signal handler needs to put the terminal back: plain globals, no captures.
var ttySavedState = termios()
var ttyEchoFd: Int32 = -1
func ttySignalRestore(_ signal: Int32) {
    if ttyEchoFd >= 0 { tcsetattr(ttyEchoFd, TCSANOW, &ttySavedState) }
    Darwin.signal(signal, SIG_DFL)
    raise(signal)
}

/// Reads one line from the terminal with echo off, and hands it to `body` in a buffer that is wiped afterwards.
/// Echo comes back on every way out: the end, Ctrl-C, a kill, a hang-up (Ctrl-Z is ignored while it waits).
/// `body` gets nil at end of input.
func withTypedPassword<T>(_ fd: Int32, prompt: String, _ body: (UnsafeBufferPointer<UInt8>?) -> T) -> T {
    let capacity = 1024
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
    buffer.initialize(repeating: 0, count: capacity)
    defer {
        memset_s(buffer, capacity, 0, capacity)
        passwordWiped?(buffer, capacity)
        buffer.deallocate()
    }
    writeTTY(fd, prompt)
    var saved = termios()
    let isTerminal = tcgetattr(fd, &saved) == 0
    var handlers: [(Int32, sig_t?)] = []
    if isTerminal {
        ttySavedState = saved
        ttyEchoFd = fd
        for s in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] { handlers.append((s, signal(s, ttySignalRestore))) }
        handlers.append((SIGTSTP, signal(SIGTSTP, SIG_IGN)))
        var quiet = saved
        quiet.c_lflag &= ~tcflag_t(ECHO | ECHOE | ECHOK | ECHONL)
        tcsetattr(fd, TCSAFLUSH, &quiet)   // also drops anything typed before the prompt
    }
    var count = 0, ended = false
    while count < capacity - 1 {
        let n = read(fd, buffer + count, 1)
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { ended = true; break }
        if buffer[count] == 0x0A || buffer[count] == 0x0D { buffer[count] = 0; break }
        count += 1
    }
    if isTerminal {
        tcsetattr(fd, TCSANOW, &saved)
        ttyEchoFd = -1
        for (s, old) in handlers { signal(s, old) }
    }
    writeTTY(fd, "\n")
    return body(ended && count == 0 ? nil : UnsafeBufferPointer(start: buffer, count: count))
}

/// A secret typed (or pasted) at the terminal for touchenv set: echo off, read a byte at a time with the terminal's
/// own line editing off, because getpass() stops at 128 characters and the terminal's line buffer at 1024, and either
/// would store a cut API key without a word. Backspace and Ctrl-U still edit, Ctrl-D on an empty line ends the input,
/// Ctrl-C stops it; the terminal comes back as it was every way out. nil at end of input; exits when the line is
/// longer than `limit` bytes.
func readHiddenLine(_ fd: Int32, prompt: String, limit: Int = 65536) -> Data? {
    writeTTY(fd, prompt)
    var saved = termios()
    let isTerminal = tcgetattr(fd, &saved) == 0
    var handlers: [(Int32, sig_t?)] = []
    if isTerminal {
        ttySavedState = saved
        ttyEchoFd = fd
        for s in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] { handlers.append((s, signal(s, ttySignalRestore))) }
        handlers.append((SIGTSTP, signal(SIGTSTP, SIG_IGN)))
        var raw = saved
        raw.c_lflag &= ~tcflag_t(ECHO | ECHOE | ECHOK | ECHONL | ICANON | IEXTEN)
        withUnsafeMutableBytes(of: &raw.c_cc) { $0[Int(VMIN)] = 1; $0[Int(VTIME)] = 0 }
        tcsetattr(fd, TCSAFLUSH, &raw)   // also drops anything typed before the prompt
    }
    var bytes: [UInt8] = []
    var ended = false, tooLong = false
    var byte: UInt8 = 0
    while true {
        let n = read(fd, &byte, 1)
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { ended = true; break }
        if byte == 0x0A || byte == 0x0D { break }
        if isTerminal {
            if byte == 0x7F || byte == 0x08 {   // backspace: one whole UTF-8 character
                while let last = bytes.popLast(), last & 0xC0 == 0x80 {}
                continue
            }
            if byte == 0x15 { wipe(&bytes); bytes = []; continue }   // Ctrl-U
            if byte == 0x04 {   // Ctrl-D
                if bytes.isEmpty { ended = true; break }
                continue
            }
        }
        if bytes.count >= limit { tooLong = true; continue }   // read on to the end of the line, then say so
        bytes.append(byte)
    }
    byte = 0
    if isTerminal {
        tcsetattr(fd, TCSANOW, &saved)
        ttyEchoFd = -1
        for (s, old) in handlers { signal(s, old) }
    }
    writeTTY(fd, "\n")
    defer { wipe(&bytes) }
    if tooLong { die("touchenv: that is longer than \(limit) bytes; for a file, use: touchenv set NAME < FILE") }
    return ended && bytes.isEmpty ? nil : Data(bytes)
}

func withThrottleLock<T>(_ body: () -> T) -> T {
    guard ensurePrivateDir(supportDir()),
          case let fd = open(supportDir() + "/password.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600), fd >= 0 else {
        return body()
    }
    defer { close(fd) }
    flock(fd, LOCK_EX)
    return body()
}

/// Approves the attempt under way (currentAttempt) with the Mac password typed in the terminal, or ends touchenv
/// with the reason, logged. Refused before any prompt when a secret isn't synced, when there is no terminal, or while
/// earlier wrong passwords still make it wait. `summary`: what is being approved, shown before the prompt.
func approveWithPassword(names: [String], summary: [String]) {
    func refuse(_ note: String, _ message: String, _ outcome: String = ReadOutcome.refused) -> Never {
        endAttempt(outcome, note: note, message: message)
    }
    if getuid() == 0 { refuse("run as root", "touchenv: --password checks your own Mac password; not as root") }
    var missing: [String] = [], local: [String] = []
    for name in names {
        switch syncedLookup(name) {
        case nil: missing.append(name)
        case false?: local.append(name)
        case true?: break
        }
    }
    if let name = missing.first { refuse("no secret named \(name)", "touchenv: no secret named \(name)") }
    if !local.isEmpty {
        let list = local.joined(separator: ", ")
        refuse("local secret: \(list)",
               "touchenv: --password is for secrets synced through iCloud Keychain only. \(list) \(local.count == 1 ? "is" : "are") "
               + "kept on this Mac behind Touch ID, which only Touch ID or the system's password window can open: "
               + "ask again without --password.")
    }
    let fd = open(ttyPath, O_RDWR | O_NOCTTY | O_CLOEXEC)
    guard fd >= 0, isatty(fd) != 0 else {
        refuse("no terminal", "touchenv: --password needs a terminal to type the password in; it is never taken from "
               + "an argument, the environment or a pipe")
    }
    defer { close(fd) }
    guard let user = currentUserName() else { refuse("no account name", "touchenv: can't tell which account this is", ReadOutcome.failed) }
    writeTTY(fd, summary.map { terminalText($0) + "\n" }.joined())
    for attempt in 1...passwordTries {
        guard let before = withThrottleLock({ throttleStore.load() }) else {
            refuse("can't read the count of wrong passwords", "touchenv: can't read the count of wrong passwords; not checking one",
                   ReadOutcome.failed)
        }
        let wait = before.notBefore.timeIntervalSinceNow
        if wait > 0 {
            if attempt == 1 || wait > 30 * throttleUnit {
                refuse("too many wrong passwords", "touchenv: too many wrong passwords; try again in \(Int(wait.rounded(.up))) s")
            }
            Thread.sleep(forTimeInterval: wait)
        }
        let result: PasswordCheck? = withTypedPassword(fd, prompt: "Mac password for \(user) (not shown): ") { typed in
            guard let typed else { return nil }
            return withThrottleLock {
                // Again under the lock, right before checking: another touchenv may have failed meanwhile.
                guard let now = throttleStore.load() else { return .error("can't read the count of wrong passwords") }
                if now.notBefore > Date() { return .error("too many wrong passwords") }
                let check = passwordVerifier(typed)
                switch check {
                case .ok:
                    if !throttleStore.save(PasswordThrottle()) { return .error("can't clear the count of wrong passwords") }
                case .wrong:
                    let failures = now.failures + 1
                    if !throttleStore.save(PasswordThrottle(failures: failures, notBefore: Date().addingTimeInterval(throttleDelay(failures)))) {
                        return .error("can't count the wrong password")
                    }
                case .error:
                    break
                }
                return check
            }
        }
        switch result {
        case nil:
            refuse("no password typed", "touchenv: no password typed; not approved", ReadOutcome.cancelled)
        case .ok?:
            tcflush(fd, TCIFLUSH)   // nothing typed ahead reaches what runs next
            return
        case .wrong?:
            if attempt == passwordTries {
                refuse("wrong password (try \(attempt) of \(passwordTries))", "touchenv: wrong password; not approved")
            }
            writeTTY(fd, "Wrong password.\n")
            if let a = currentAttempt {
                logAccess(AccessEntry(event: a.event, secrets: a.secrets, outcome: ReadOutcome.refused, who: a.who,
                                      program: a.program, intent: a.intent, note: "wrong password (try \(attempt) of \(passwordTries))"))
            }
        case .error(let why)?:
            if why == "too many wrong passwords" {
                refuse(why, "touchenv: too many wrong passwords; try again later")
            }
            refuse("password check failed: \(why)", "touchenv: couldn't check the password (\(why)); not approved", ReadOutcome.failed)
        }
    }
}

/// get and run with --password: approve, then read every secret. No 5-minute approval follows.
func passwordRead(names: [String], summary: [String], read: (String) -> Data) -> [String: Data] {
    approveWithPassword(names: names, summary: summary)
    var out: [String: Data] = [:]
    for name in names { out[name] = read(name) }
    logAttempt(ReadOutcome.passwordCLI)
    return out
}

// MARK: Moving to another Mac

let importService = "touchenv-import"
let importLifetime: TimeInterval = 60 * 60
let fileMagic = Data([0x54, 0x45, 0x4E, 0x56, 0x01])   // "TENV" 1
let headerLength = fileMagic.count + 33 + 65             // magic | receiving key, compressed | ephemeral key, x9.63

/// The receiving key's public half as text: "tenv1:" and the compressed point in base64url.
func recipientText(_ key: P256.KeyAgreement.PublicKey) -> String {
    "tenv1:" + key.compressedRepresentation.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func parseRecipient(_ text: String) -> P256.KeyAgreement.PublicKey? {
    let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard text.hasPrefix("tenv1:") else { return nil }
    var b64 = String(text.dropFirst(6)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while b64.count % 4 != 0 { b64 += "=" }
    guard let data = Data(base64Encoded: b64) else { return nil }
    return try? P256.KeyAgreement.PublicKey(compressedRepresentation: data)
}

/// Twelve characters both Macs show, so the old one exports only to the Mac in front of you.
func checkCode(_ key: P256.KeyAgreement.PublicKey) -> String {
    let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    var out: [Character] = [], acc = 0, bits = 0
    for byte in SHA256.hash(data: key.compressedRepresentation) where out.count < 12 {
        acc = (acc << 8) | Int(byte)
        bits += 8
        while bits >= 5 && out.count < 12 {
            bits -= 5
            out.append(alphabet[(acc >> bits) & 31])
        }
        acc &= (1 << bits) - 1
    }
    return stride(from: 0, to: 12, by: 4).map { String(out[$0..<$0 + 4]) }.joined(separator: "-")
}

enum ReceivingKey {
    case enclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
    case software(P256.KeyAgreement.PrivateKey)

    var publicKey: P256.KeyAgreement.PublicKey {
        switch self {
        case .enclave(let key): return key.publicKey
        case .software(let key): return key.publicKey
        }
    }

    func sharedSecret(with other: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        switch self {
        case .enclave(let key): return try key.sharedSecretFromKeyAgreement(with: other)
        case .software(let key): return try key.sharedSecretFromKeyAgreement(with: other)
        }
    }
}

func receivingQuery() -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: importService,
     kSecAttrAccount as String: "pending", kSecUseDataProtectionKeychain as String: true]
}

/// A new receiving key, replacing any earlier one: in the Secure Enclave when the Mac has one (the keychain then holds
/// only a handle that works on this Mac), otherwise the key itself, this device only.
func newReceivingKey() -> ReceivingKey {
    SecItemDelete(receivingQuery() as CFDictionary)
    let key: ReceivingKey
    let blob: Data
    if SecureEnclave.isAvailable, let enclaveKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey() {
        key = .enclave(enclaveKey)
        blob = Data("se:".utf8) + enclaveKey.dataRepresentation
    } else {
        let softwareKey = P256.KeyAgreement.PrivateKey()
        key = .software(softwareKey)
        blob = Data("sw:".utf8) + softwareKey.rawRepresentation
    }
    var q = receivingQuery()
    q[kSecValueData as String] = blob
    q[kSecAttrLabel as String] = "touchenv: key for one import"
    q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let status = SecItemAdd(q as CFDictionary, nil)
    if status != errSecSuccess { die("touchenv: keychain error \(status)") }
    return key
}

func waitingReceivingKey() -> (key: ReceivingKey, created: Date)? {
    var q = receivingQuery()
    q[kSecReturnData as String] = true
    q[kSecReturnAttributes as String] = true
    var out: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let item = out as? [String: Any],
          let blob = item[kSecValueData as String] as? Data else { return nil }
    let created = item[kSecAttrCreationDate as String] as? Date ?? .distantPast
    let body = Data(blob.dropFirst(3))
    switch String(decoding: blob.prefix(3), as: UTF8.self) {
    case "se:":
        guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: body) else { return nil }
        return (.enclave(key), created)
    case "sw:":
        guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: body) else { return nil }
        return (.software(key), created)
    default: return nil
    }
}

func transferKey(_ secret: SharedSecret, header: Data) -> SymmetricKey {
    secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: header, sharedInfo: Data("touchenv export 1".utf8),
                                   outputByteCount: 32)
}

// MARK: SSH keys: the formats
//
// Everything that parses comes from outside (a key file, a client on the agent socket), so every length is checked
// against what is left before anything is allocated, and nothing may follow the last field.

/// Programs between an SSH client and whoever started it: walked past to find who asks, named in the prompt as "via".
let sshTools: Set<String> = ["ssh", "scp", "sftp", "rsync", "git", "ssh-keygen", "ssh-add"]
let sshKeyMarker = "touchenv ssh key"   // kSecAttrDescription of the items `touchenv ssh add` stores
let sshAgentMaxMessage = 256 * 1024     // as OpenSSH's ssh-agent
let sshDefaultLoad: TimeInterval = 60 * 60

struct SSHFormatError: Error, CustomStringConvertible { let description: String; init(_ d: String) { description = d } }

/// Overwrites secret bytes before they are let go. Best effort: copies Swift or the frameworks made are not reached.
func wipe(_ bytes: inout [UInt8]) {
    let count = bytes.count
    if count > 0 { bytes.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, count, 0, count) } }
    bytes.removeAll()
}

struct SSHReader {
    let bytes: [UInt8]
    var at = 0
    init(_ bytes: [UInt8]) { self.bytes = bytes }
    var left: Int { bytes.count - at }
    var done: Bool { at == bytes.count }

    mutating func u8() throws -> UInt8 {
        guard left >= 1 else { throw SSHFormatError("truncated") }
        at += 1
        return bytes[at - 1]
    }
    mutating func u32() throws -> UInt32 {
        guard left >= 4 else { throw SSHFormatError("truncated") }
        defer { at += 4 }
        return bytes[at..<at + 4].reduce(0) { $0 << 8 | UInt32($1) }
    }
    mutating func raw(_ n: Int) throws -> [UInt8] {
        guard n >= 0, left >= n else { throw SSHFormatError("truncated") }
        defer { at += n }
        return Array(bytes[at..<at + n])
    }
    /// A length-prefixed string; the length is trusted only as far as the bytes that are really there.
    mutating func string(max: Int = sshAgentMaxMessage) throws -> [UInt8] {
        let n = Int(try u32())
        guard n <= max else { throw SSHFormatError("field too long") }
        return try raw(n)
    }
    mutating func text(max: Int = 1024) throws -> String {
        guard let s = String(bytes: try string(max: max), encoding: .utf8) else { throw SSHFormatError("not UTF-8") }
        return s
    }
    mutating func bool() throws -> Bool {
        switch try u8() { case 0: return false; case 1: return true; default: throw SSHFormatError("bad boolean") }
    }
    /// An mpint that must be positive: its magnitude, no leading zero.
    mutating func mpint(maxBytes: Int) throws -> [UInt8] {
        let field = try string(max: maxBytes + 1)
        if let first = field.first, first & 0x80 != 0 { throw SSHFormatError("negative number") }
        if field.count >= 2, field[0] == 0, field[1] & 0x80 == 0 { throw SSHFormatError("badly encoded number") }
        let magnitude = Array(field.drop { $0 == 0 })
        guard !magnitude.isEmpty, magnitude.count <= maxBytes else { throw SSHFormatError("number out of range") }
        return magnitude
    }
    func end() throws { if !done { throw SSHFormatError("trailing bytes") } }
}

struct SSHWriter {
    var bytes: [UInt8] = []
    mutating func u8(_ v: UInt8) { bytes.append(v) }
    mutating func u32(_ v: UInt32) { bytes += [UInt8(v >> 24), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)] }
    mutating func string(_ s: [UInt8]) { u32(UInt32(s.count)); bytes += s }
    mutating func string(_ s: String) { string(Array(s.utf8)) }
    mutating func mpint(_ magnitude: [UInt8]) {
        let m = Array(magnitude.drop { $0 == 0 })
        string(m.first.map { $0 & 0x80 != 0 } == true ? [0] + m : m)
    }
}

enum SSHKeyKind: CaseIterable {
    case ed25519, ecdsa256, ecdsa384, ecdsa521, rsa

    var typeName: String {
        switch self {
        case .ed25519: return "ssh-ed25519"
        case .ecdsa256: return "ecdsa-sha2-nistp256"
        case .ecdsa384: return "ecdsa-sha2-nistp384"
        case .ecdsa521: return "ecdsa-sha2-nistp521"
        case .rsa: return "ssh-rsa"
        }
    }
    var curve: String { String(typeName.suffix(8)) }               // nistp256…
    var scalarSize: Int { [.ecdsa256: 32, .ecdsa384: 48, .ecdsa521: 66][self] ?? 0 }
    var pointSize: Int { 1 + 2 * scalarSize }
    var label: String { self == .ed25519 ? "ED25519" : self == .rsa ? "RSA" : "ECDSA" }
    static func named(_ type: String) -> SSHKeyKind? { allCases.first { $0.typeName == type } }
}

/// What touchenv can't sign with, by the name OpenSSH gives it, for a clear refusal.
func unsupportedKeyReason(_ type: String) -> String {
    if type.hasPrefix("sk-") { return "a security-key (FIDO) key: its private half lives on the token, there is nothing to store" }
    if type.contains("-cert-") { return "a certificate: add the key it certifies instead" }
    if type == "ssh-dss" { return "a DSA key, which OpenSSH no longer accepts" }
    return "a \(type) key, which touchenv can't sign with"
}

struct SSHPublicKey: Equatable {
    let kind: SSHKeyKind
    let blob: [UInt8]
    let bits: Int

    /// Checks a public key blob: the type touchenv signs with, every field the right size, nothing after.
    init(blob: [UInt8]) throws {
        var r = SSHReader(blob)
        let type = try r.text(max: 64)
        guard let kind = SSHKeyKind.named(type) else { throw SSHFormatError(unsupportedKeyReason(type)) }
        switch kind {
        case .ed25519:
            guard try r.string(max: 32).count == 32 else { throw SSHFormatError("bad Ed25519 key") }
            bits = 256
        case .ecdsa256, .ecdsa384, .ecdsa521:
            guard try r.text(max: 16) == kind.curve else { throw SSHFormatError("curve doesn't match the key type") }
            let q = try r.string(max: kind.pointSize)
            guard q.count == kind.pointSize, q[0] == 4, publicPoint(kind, q) else { throw SSHFormatError("bad ECDSA point") }
            bits = kind == .ecdsa521 ? 521 : kind.scalarSize * 8
        case .rsa:
            let e = try r.mpint(maxBytes: 8), n = try r.mpint(maxBytes: 2048)
            bits = (n.count - 1) * 8 + (8 - n[0].leadingZeroBitCount)
            guard bits >= 1024, e.last! & 1 == 1 else { throw SSHFormatError("RSA key too small or malformed") }
        }
        try r.end()
        self.kind = kind
        self.blob = blob
    }

    var fingerprint: String {
        "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
    func line(comment: String) -> String { "\(kind.typeName) \(Data(blob).base64EncodedString()) \(comment)" }

    /// The parts after the type: Ed25519's 32 bytes, an ECDSA point, RSA's (e, n).
    var fields: (ed: [UInt8], point: [UInt8], e: [UInt8], n: [UInt8]) {
        var r = SSHReader(blob)
        _ = try? r.string()
        switch kind {
        case .ed25519: return ((try? r.string()) ?? [], [], [], [])
        case .rsa:
            let e = (try? r.mpint(maxBytes: 8)) ?? [], n = (try? r.mpint(maxBytes: 2048)) ?? []
            return ([], [], e, n)
        default:
            _ = try? r.string()
            return ([], (try? r.string()) ?? [], [], [])
        }
    }

    /// From an OpenSSH public key line ("ssh-ed25519 AAAA… comment").
    init?(line: String) {
        let parts = line.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2, let data = Data(base64Encoded: String(parts[1])),
              let key = try? SSHPublicKey(blob: [UInt8](data)), key.kind.typeName == parts[0] else { return nil }
        self = key
    }
}

func publicPoint(_ kind: SSHKeyKind, _ q: [UInt8]) -> Bool {
    switch kind {
    case .ecdsa256: return (try? P256.Signing.PublicKey(x963Representation: q)) != nil
    case .ecdsa384: return (try? P384.Signing.PublicKey(x963Representation: q)) != nil
    case .ecdsa521: return (try? P521.Signing.PublicKey(x963Representation: q)) != nil
    default: return false
    }
}

// MARK: SSH keys: RSA arithmetic and DER, for Security.framework
//
// SecKeyCreateWithData takes an RSA private key as PKCS#1, which carries d mod (p-1) and d mod (q-1); OpenSSH's
// format doesn't. Two remainders are all the big-number arithmetic needed.

/// a mod m, both big-endian magnitudes, m > 0: shift-and-subtract, one bit at a time.
func bigMod(_ a: [UInt8], _ m: [UInt8]) -> [UInt8] {
    let width = (m.count + 3) / 4 + 1
    func limbs(_ x: [UInt8]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: width)
        for (i, byte) in x.reversed().enumerated() { out[i / 4] |= UInt32(byte) << (8 * UInt32(i % 4)) }
        return out
    }
    let mod = limbs(m)
    var r = [UInt32](repeating: 0, count: width)
    for byte in a {
        for bit in stride(from: 7, through: 0, by: -1) {
            var carry = UInt32(byte >> UInt8(bit) & 1)
            for i in 0..<width { let v = r[i]; r[i] = v << 1 | carry; carry = v >> 31 }
            var geq = true
            for i in stride(from: width - 1, through: 0, by: -1) where r[i] != mod[i] { geq = r[i] > mod[i]; break }
            if geq {
                var borrow: UInt64 = 0
                for i in 0..<width {
                    let d = UInt64(r[i]) &- UInt64(mod[i]) &- borrow
                    r[i] = UInt32(truncatingIfNeeded: d)
                    borrow = d >> 63
                }
            }
        }
    }
    var out: [UInt8] = []
    for limb in r.reversed() { out += [UInt8(limb >> 24), UInt8(limb >> 16 & 0xff), UInt8(limb >> 8 & 0xff), UInt8(limb & 0xff)] }
    for i in 0..<r.count { r[i] = 0 }
    return Array(out.drop { $0 == 0 })
}

func derLength(_ n: Int) -> [UInt8] {
    if n < 128 { return [UInt8(n)] }
    var bytes: [UInt8] = []
    var v = n
    while v > 0 { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
    return [0x80 | UInt8(bytes.count)] + bytes
}
func derInteger(_ magnitude: [UInt8]) -> [UInt8] {
    var m = Array(magnitude.drop { $0 == 0 })
    if m.isEmpty || m[0] & 0x80 != 0 { m.insert(0, at: 0) }
    return [0x02] + derLength(m.count) + m
}
func derSequence(_ parts: [[UInt8]]) -> [UInt8] {
    let body = parts.flatMap { $0 }
    return [0x30] + derLength(body.count) + body
}

func rsaPublicKey(n: [UInt8], e: [UInt8]) -> SecKey? {
    let der = derSequence([derInteger(n), derInteger(e)])
    return SecKeyCreateWithData(Data(der) as CFData, [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                                                      kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, nil)
}

// MARK: SSH keys: private keys

/// An SSH private key in memory. The secret parts are wiped when it goes.
final class SSHPrivateKey {
    let publicKey: SSHPublicKey
    let comment: String
    /// The key as the agent protocol adds it (type and fields, the same bytes as in the file's private section).
    var record: [UInt8]
    var secret: [UInt8]                    // Ed25519 seed (32), ECDSA scalar (padded), or RSA d
    var p: [UInt8] = [], q: [UInt8] = [], iqmp: [UInt8] = []

    init(publicKey: SSHPublicKey, comment: String, record: [UInt8], secret: [UInt8]) {
        self.publicKey = publicKey
        self.comment = comment
        self.record = record
        self.secret = secret
    }
    deinit { wipe(&record); wipe(&secret); wipe(&p); wipe(&q); wipe(&iqmp) }

    /// An SSH signature blob over `data`. RSA: rsa-sha2-512 with flag 4, rsa-sha2-256 with flag 2; plain ssh-rsa
    /// (SHA-1) is refused, as OpenSSH itself has done by default since 8.8.
    func sign(_ data: [UInt8], flags: UInt32 = 0) throws -> [UInt8] {
        var out = SSHWriter()
        switch publicKey.kind {
        case .ed25519:
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: secret)
            out.string("ssh-ed25519")
            out.string([UInt8](try key.signature(for: Data(data))))
        case .ecdsa256, .ecdsa384, .ecdsa521:
            let raw: Data
            switch publicKey.kind {
            case .ecdsa256: raw = try P256.Signing.PrivateKey(rawRepresentation: secret).signature(for: Data(data)).rawRepresentation
            case .ecdsa384: raw = try P384.Signing.PrivateKey(rawRepresentation: secret).signature(for: Data(data)).rawRepresentation
            default: raw = try P521.Signing.PrivateKey(rawRepresentation: secret).signature(for: Data(data)).rawRepresentation
            }
            let half = raw.count / 2
            var inner = SSHWriter()
            inner.mpint([UInt8](raw.prefix(half)))
            inner.mpint([UInt8](raw.suffix(half)))
            out.string(publicKey.kind.typeName)
            out.string(inner.bytes)
        case .rsa:
            let (algorithm, name): (SecKeyAlgorithm, String)
            if flags & 4 != 0 { (algorithm, name) = (.rsaSignatureMessagePKCS1v15SHA512, "rsa-sha2-512") }
            else if flags & 2 != 0 { (algorithm, name) = (.rsaSignatureMessagePKCS1v15SHA256, "rsa-sha2-256") }
            else { throw SSHFormatError("ssh-rsa (SHA-1) signatures are refused; the server needs rsa-sha2-256 or -512") }
            guard let key = rsaSecKey() else { throw SSHFormatError("Security.framework refused the RSA key") }
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(key, algorithm, Data(data) as CFData, &error) as Data? else {
                throw SSHFormatError("RSA signing failed")
            }
            out.string(name)
            out.string([UInt8](signature))
        }
        return out.bytes
    }

    func rsaSecKey() -> SecKey? {
        let f = publicKey.fields
        var p1 = p, q1 = q
        p1[p1.count - 1] -= 1   // p and q are odd (checked on parsing): no borrow
        q1[q1.count - 1] -= 1
        var dp = bigMod(secret, p1), dq = bigMod(secret, q1)
        var der = derSequence([derInteger([0]), derInteger(f.n), derInteger(f.e), derInteger(secret), derInteger(p),
                               derInteger(q), derInteger(dp), derInteger(dq), derInteger(iqmp)])
        defer { wipe(&p1); wipe(&q1); wipe(&dp); wipe(&dq); wipe(&der) }
        return SecKeyCreateWithData(Data(der) as CFData, [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                                                          kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, nil)
    }

    /// Signs and verifies a random message: catches a private half that doesn't belong to the public one.
    func selfTest() -> Bool {
        let probe = (0..<32).map { _ in UInt8.random(in: 0...255) }
        guard let signature = try? sign(probe, flags: 2) else { return false }
        return verifySSHSignature(publicBlob: publicKey.blob, signature: signature, data: probe)
    }
}

/// Reads one key record (type, fields) from a private section, up to but not including its comment.
func readPrivateRecord(_ r: inout SSHReader) throws -> (SSHPublicKey, [UInt8], secret: [UInt8], rsa: [[UInt8]]) {
    let start = r.at
    let type = try r.text(max: 64)
    guard let kind = SSHKeyKind.named(type) else { throw SSHFormatError(unsupportedKeyReason(type)) }
    var pub = SSHWriter()
    pub.string(type)
    switch kind {
    case .ed25519:
        let pk = try r.string(max: 32), sk = try r.string(max: 64)
        guard pk.count == 32, sk.count == 64, Array(sk[32...]) == pk else { throw SSHFormatError("bad Ed25519 key") }
        pub.string(pk)
        let key = try SSHPublicKey(blob: pub.bytes)
        guard (try? Curve25519.Signing.PrivateKey(rawRepresentation: Array(sk[..<32])).publicKey.rawRepresentation)
                .map({ [UInt8]($0) == pk }) == true else { throw SSHFormatError("Ed25519 private and public halves differ") }
        return (key, Array(r.bytes[start..<r.at]), Array(sk[..<32]), [])
    case .ecdsa256, .ecdsa384, .ecdsa521:
        guard try r.text(max: 16) == kind.curve else { throw SSHFormatError("curve doesn't match the key type") }
        let q = try r.string(max: kind.pointSize)
        let d = try r.mpint(maxBytes: kind.scalarSize)
        pub.string(kind.curve)
        pub.string(q)
        let key = try SSHPublicKey(blob: pub.bytes)
        let scalar = [UInt8](repeating: 0, count: kind.scalarSize - d.count) + d
        let derived: Data?
        switch kind {
        case .ecdsa256: derived = try? P256.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
        case .ecdsa384: derived = try? P384.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
        default: derived = try? P521.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
        }
        guard derived.map({ [UInt8]($0) == q }) == true else { throw SSHFormatError("ECDSA private and public halves differ") }
        return (key, Array(r.bytes[start..<r.at]), scalar, [])
    case .rsa:
        let n = try r.mpint(maxBytes: 2048), e = try r.mpint(maxBytes: 8), d = try r.mpint(maxBytes: 2048)
        let iqmp = try r.mpint(maxBytes: 1024), p = try r.mpint(maxBytes: 1024), q = try r.mpint(maxBytes: 1024)
        guard p.last! & 1 == 1, q.last! & 1 == 1, p.count > 1, q.count > 1 else { throw SSHFormatError("bad RSA key") }
        pub.mpint(e)
        pub.mpint(n)
        let key = try SSHPublicKey(blob: pub.bytes)
        return (key, Array(r.bytes[start..<r.at]), d, [p, q, iqmp])
    }
}

/// The base64 inside "-----BEGIN OPENSSH PRIVATE KEY-----" … "-----END …", decoded into bytes that can be wiped.
func dearmor(_ text: [UInt8], label: String) -> [UInt8]? {
    let begin = Array("-----BEGIN \(label)-----".utf8), end = Array("-----END \(label)-----".utf8)
    func find(_ needle: [UInt8], from: Int) -> Int? {
        guard text.count >= needle.count, from <= text.count - needle.count else { return nil }
        return (from...(text.count - needle.count)).first { text[$0..<$0 + needle.count].elementsEqual(needle) }
    }
    guard let b = find(begin, from: 0), let e = find(end, from: b + begin.count) else { return nil }
    // Only whitespace around the armor.
    let blank: Set<UInt8> = [9, 10, 13, 32]
    guard text[..<b].allSatisfy(blank.contains), text[(e + end.count)...].allSatisfy(blank.contains) else { return nil }
    var out: [UInt8] = [], acc: UInt32 = 0, bits = 0, padding = 0
    for c in text[(b + begin.count)..<e] {
        let v: UInt32
        switch c {
        case 65...90: v = UInt32(c - 65)
        case 97...122: v = UInt32(c - 71)
        case 48...57: v = UInt32(c + 4)
        case 43: v = 62
        case 47: v = 63
        case 61: padding += 1; continue
        case 9, 10, 13, 32: continue
        default: return nil
        }
        if padding > 0 { return nil }
        acc = acc << 6 | v
        bits += 6
        if bits >= 8 { bits -= 8; out.append(UInt8(acc >> UInt32(bits) & 0xff)) }
    }
    acc = 0
    return padding <= 2 ? out : nil
}

enum SSHKeyFile {
    case openssh(SSHPrivateKey)
    /// Needs ssh-keygen to turn it into an unencrypted OpenSSH key; `passphrase`: whether it is encrypted.
    case convert(passphrase: Bool)
}

/// Reads a private key file's text. Unencrypted OpenSSH keys are parsed here; anything else ssh-keygen can read
/// (encrypted keys, the older PEM and PKCS#8 formats) comes back as .convert.
func parseSSHKeyFile(_ text: [UInt8], selfTest: Bool = true) throws -> SSHKeyFile {
    let s = String(decoding: text.prefix(200), as: UTF8.self)
    if s.contains("BEGIN SSH2 ENCRYPTED PRIVATE KEY") || s.contains("PuTTY-User-Key-File") {
        throw SSHFormatError("not an OpenSSH key file: convert it with ssh-keygen or PuTTYgen first")
    }
    if !s.contains("BEGIN OPENSSH PRIVATE KEY") {
        if s.contains("BEGIN DSA PRIVATE KEY") { throw SSHFormatError(unsupportedKeyReason("ssh-dss")) }
        let pem = ["BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY"]
        guard pem.contains(where: s.contains) else {
            if s.hasPrefix("ssh-") || s.hasPrefix("ecdsa-") { throw SSHFormatError("that is a public key (.pub); give the private key file") }
            throw SSHFormatError("not an SSH private key file")
        }
        let all = String(decoding: text, as: UTF8.self)
        return .convert(passphrase: all.contains("ENCRYPTED"))
    }
    guard var bytes = dearmor(text, label: "OPENSSH PRIVATE KEY") else { throw SSHFormatError("damaged key file") }
    defer { wipe(&bytes) }
    var r = SSHReader(bytes)
    guard try r.raw(15) == Array("openssh-key-v1\0".utf8) else { throw SSHFormatError("not an openssh-key-v1 file") }
    let cipher = try r.text(max: 64), kdf = try r.text(max: 64)
    let kdfOptions = try r.string(max: 1024)
    guard try r.u32() == 1 else { throw SSHFormatError("the file holds more than one key") }
    let publicBlob = try r.string(max: 4096)
    if cipher != "none" { return .convert(passphrase: true) }
    guard kdf == "none", kdfOptions.isEmpty else { throw SSHFormatError("unencrypted key with a KDF") }
    var section = try r.string(max: 65536)
    defer { wipe(&section) }
    try r.end()
    // The key's public type, for a clear refusal before the private section is read.
    var typeReader = SSHReader(publicBlob)
    let publicType = try typeReader.text(max: 64)
    guard SSHKeyKind.named(publicType) != nil else { throw SSHFormatError(unsupportedKeyReason(publicType)) }

    var p = SSHReader(section)
    let check1 = try p.u32(), check2 = try p.u32()
    guard check1 == check2 else { throw SSHFormatError("damaged key file (check bytes differ)") }
    var (key, record, secret, rsa) = try readPrivateRecord(&p)
    let comment = (try? p.text(max: 4096)) ?? ""
    // Padding 1, 2, 3… up to the block size (8 without a cipher).
    var expected: UInt8 = 1
    while !p.done {
        guard try p.u8() == expected, expected < 8 else { throw SSHFormatError("damaged key file (padding)") }
        expected += 1
    }
    guard key.blob == publicBlob else { throw SSHFormatError("the file's public and private keys differ") }
    let out = SSHPrivateKey(publicKey: key, comment: comment, record: record, secret: secret)
    if key.kind == .rsa { out.p = rsa[0]; out.q = rsa[1]; out.iqmp = rsa[2] }
    wipe(&record); wipe(&secret)
    for i in rsa.indices { wipe(&rsa[i]) }
    // A test signature once, when the key is added (ssh add); signing later checks the key against its public half.
    guard !selfTest || out.selfTest() else { throw SSHFormatError("the key fails a test signature") }
    return .openssh(out)
}

/// Verifies an SSH signature blob made by `publicBlob`'s key over `data`.
func verifySSHSignature(publicBlob: [UInt8], signature: [UInt8], data: [UInt8]) -> Bool {
    guard let key = try? SSHPublicKey(blob: publicBlob) else { return false }
    var r = SSHReader(signature)
    guard let algorithm = try? r.text(max: 64), let sig = try? r.string(max: 2048), r.done else { return false }
    let f = key.fields
    switch key.kind {
    case .ed25519:
        guard algorithm == "ssh-ed25519", let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: f.ed) else { return false }
        return pk.isValidSignature(Data(sig), for: Data(data))
    case .ecdsa256, .ecdsa384, .ecdsa521:
        var inner = SSHReader(sig)
        let size = key.kind.scalarSize
        guard algorithm == key.kind.typeName, let rr = try? inner.mpint(maxBytes: size), let ss = try? inner.mpint(maxBytes: size),
              inner.done else { return false }
        let raw = Data([UInt8](repeating: 0, count: size - rr.count) + rr + [UInt8](repeating: 0, count: size - ss.count) + ss)
        switch key.kind {
        case .ecdsa256:
            guard let pk = try? P256.Signing.PublicKey(x963Representation: f.point),
                  let s = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return pk.isValidSignature(s, for: Data(data))
        case .ecdsa384:
            guard let pk = try? P384.Signing.PublicKey(x963Representation: f.point),
                  let s = try? P384.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return pk.isValidSignature(s, for: Data(data))
        default:
            guard let pk = try? P521.Signing.PublicKey(x963Representation: f.point),
                  let s = try? P521.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return pk.isValidSignature(s, for: Data(data))
        }
    case .rsa:
        let algorithms: [String: SecKeyAlgorithm] = ["rsa-sha2-256": .rsaSignatureMessagePKCS1v15SHA256,
                                                     "rsa-sha2-512": .rsaSignatureMessagePKCS1v15SHA512]
        guard let alg = algorithms[algorithm], let pk = rsaPublicKey(n: f.n, e: f.e) else { return false }
        return SecKeyVerifySignature(pk, alg, Data(data) as CFData, Data(sig) as CFData, nil)
    }
}

// MARK: SSH keys: what a signature is for

struct SessionBind { let hostKey: [UInt8]; let sessionID: [UInt8]; let forwarding: Bool }

enum SignPurpose: Equatable {
    /// An ssh login (SSH_MSG_USERAUTH_REQUEST): the user, the session it belongs to, and for the hostbound method
    /// the server's key.
    case login(user: String, sessionID: [UInt8], hostKey: [UInt8]?)
    /// `ssh-keygen -Y sign` (git commit and tag signing uses namespace "git").
    case sshsig(namespace: String)
    case other
}

/// Reads what the client asks to sign. A login names the key it signs for: it must be the key asked for.
func signPurpose(_ data: [UInt8], key: [UInt8]) -> SignPurpose? {
    var r = SSHReader(data)
    if data.starts(with: Array("SSHSIG".utf8)) {
        _ = try? r.raw(6)
        guard let namespace = try? r.text(max: 256), (try? r.string(max: 256)) != nil,
              (try? r.text(max: 64)) != nil, (try? r.string(max: 128)) != nil, r.done else { return .other }
        return .sshsig(namespace: namespace)
    }
    guard let session = try? r.string(max: 64), !session.isEmpty, (try? r.u8()) == 50,
          let user = try? r.text(max: 256), (try? r.text(max: 64)) == "ssh-connection",
          let method = try? r.text(max: 64), method == "publickey" || method == "publickey-hostbound-v00@openssh.com",
          (try? r.bool()) == true, (try? r.text(max: 64)) != nil, let blob = try? r.string(max: 16384) else { return .other }
    var hostKey: [UInt8]?
    if method != "publickey" { guard let k = try? r.string(max: 16384) else { return .other }; hostKey = k }
    guard r.done else { return .other }
    return blob == key ? .login(user: user, sessionID: session, hostKey: hostKey) : nil
}

/// Where an ssh command line connects: its destination as typed, with -l and -p folded in. nil when not ssh-like.
func sshDestination(_ argv: [String]) -> (text: String, host: String, port: Int?)? {
    let withArgument = Set("bceilmopBDEFIJLOPQRSwW")
    var user: String?, port: Int?, i = 1
    while i < argv.count {
        let arg = argv[i]
        if arg == "--" { i += 1; break }
        guard arg.hasPrefix("-"), arg.count > 1 else { break }
        var letters = Array(arg.dropFirst())
        while let letter = letters.first {
            letters.removeFirst()
            guard withArgument.contains(letter) else { continue }
            let value = letters.isEmpty ? (i + 1 < argv.count ? argv[i + 1] : "") : String(letters)
            if letters.isEmpty { i += 1 }
            if letter == "l" { user = value }
            if letter == "p" { port = Int(value) }
            if letter == "o", value.lowercased().hasPrefix("port=") { port = Int(value.dropFirst(5)) }
            if letter == "o", value.lowercased().hasPrefix("user=") { user = String(value.dropFirst(5)) }
            letters = []
        }
        i += 1
    }
    guard i < argv.count else { return nil }
    var target = argv[i]
    if target.hasPrefix("ssh://") {
        target = String(target.dropFirst(6))
        if let colon = target.lastIndex(of: ":"), let p = Int(target[target.index(after: colon)...]) {
            port = p
            target = String(target[..<colon])
        }
    }
    if let at = target.lastIndex(of: "@") { user = String(target[..<at]); target = String(target[target.index(after: at)...]) }
    guard !target.isEmpty, target.count < 256 else { return nil }
    var text = user.map { "\($0)@\(target)" } ?? target
    if let port, port != 22 { text += " port \(port)" }
    return (text, target, port)
}

/// What known_hosts says about a server key: whether `host` is listed with it, and the plain names it is listed under.
/// Hashed entries (HashKnownHosts) are matched against `host` only; wildcard and negated patterns are skipped.
func knownHostNames(for hostKey: [UInt8], host: String?, port: Int?, files: [String]) -> (typed: Bool, names: [String]) {
    let wanted = host.map { h in port.map { p in p == 22 ? h : "[\(h)]:\(p)" } ?? h }
    var typed = false, names: [String] = []
    for file in files {
        guard let data = FileManager.default.contents(atPath: file), data.count < 8 << 20 else { continue }
        for line in String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count >= 3, !fields[0].hasPrefix("#"), !fields[0].hasPrefix("@"),
                  let key = Data(base64Encoded: String(fields[2])), [UInt8](key) == hostKey else { continue }
            for pattern in fields[0].split(separator: ",").map(String.init) {
                if pattern.hasPrefix("|1|") {
                    let parts = pattern.split(separator: "|")
                    guard parts.count == 3, let wanted, let salt = Data(base64Encoded: String(parts[1])),
                          let hash = Data(base64Encoded: String(parts[2])) else { continue }
                    let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(wanted.utf8), using: SymmetricKey(data: salt))
                    if Data(mac) == hash { typed = true }
                } else if !pattern.contains("*") && !pattern.contains("?") && !pattern.hasPrefix("!") {
                    if pattern.lowercased() == wanted?.lowercased() { typed = true }
                    if !names.contains(pattern) { names.append(pattern) }
                }
            }
        }
    }
    return (typed, names)
}

// MARK: SSH keys: the agent protocol

struct SSHIdentity { let name: String; let key: SSHPublicKey; let synced: Bool }

/// One sign request, as the prompt and the approvals see it.
struct SSHAsk {
    let identity: SSHIdentity
    let purpose: SignPurpose
    let binds: [SessionBind]
    let peer: pid_t, peerStart: UInt64
    let who: Requester
    let via: [String]                 // ssh, git…: the programs between the requester and the socket
    let remote: Bool                  // came through an sshd session: nobody may be at this Mac
    let destination: (text: String, host: String, port: Int?)?
    let commands: [String]            // the command lines of `via`, for "More detail"
    var knownHostFiles: [String]

    /// "sign in to git@github.com", "sign a git commit or tag"…
    var action: String {
        switch purpose {
        case .login: return "sign in to \(destination?.text ?? "a server")"
        case .sshsig(let ns): return ns == "git" ? "sign a git commit or tag" : ns == "file" ? "sign a file" : "make an SSH signature (\(ns))"
        case .other: return "sign data touchenv can't identify"
        }
    }

    /// What can be said about the server, honestly.
    var serverNote: String? {
        guard case .login = purpose else { return nil }
        guard let bind = binds.last, let key = try? SSHPublicKey(blob: bind.hostKey) else {
            return "Server: unknown (this ssh didn't tell the agent which server it reached)."
        }
        let forwarded = binds.contains { $0.forwarding } ? " Through agent forwarding (ssh -A)." : ""
        let known = knownHostNames(for: bind.hostKey, host: destination?.host, port: destination?.port, files: knownHostFiles)
        if known.typed, let host = destination?.host { return "Server: \(host), its key as in your known_hosts.\(forwarded)" }
        if let name = known.names.first { return "Server: known in your known_hosts as \(name).\(forwarded)" }
        return "Server key \(key.fingerprint), not in your known_hosts.\(forwarded)"
    }
}

enum SSHRefusal: Error { case refused(String) }

/// Speaks the ssh-agent protocol on one socket. Signing asks `covered` first (a grant or a 5-minute approval: the
/// key, no prompt), then `ask` (a prompt), one request at a time. Clients can't add, remove or lock keys.
final class SSHAgentServer {
    let identities: () -> [SSHIdentity]
    let covered: (SSHAsk) -> [UInt8]?
    let ask: (SSHAsk) -> Result<[UInt8], SSHRefusal>
    let log: (String) -> Void
    var knownHostFiles: [String]
    let maxWaiting = 4
    private let prompts = DispatchQueue(label: "touchenv.ssh.prompts")
    private let lock = NSLock()
    private var waiting = 0
    private(set) var open = 0
    private(set) var lastActivity = Date()

    init(identities: @escaping () -> [SSHIdentity], covered: @escaping (SSHAsk) -> [UInt8]?,
         ask: @escaping (SSHAsk) -> Result<[UInt8], SSHRefusal>, log: @escaping (String) -> Void = { _ in },
         knownHostFiles: [String]) {
        self.identities = identities
        self.covered = covered
        self.ask = ask
        self.log = log
        self.knownHostFiles = knownHostFiles
    }

    var idle: Bool { lock.lock(); defer { lock.unlock() }; return open == 0 && waiting == 0 }
    var idleSince: Date { lock.lock(); defer { lock.unlock() }; return lastActivity }

    /// Accepts connections until the listening socket fails; one thread each, at most 64 at once.
    func serve(_ listener: Int32) {
        while true {
            let fd = accept(listener, nil, nil)
            if fd < 0 { if errno == EINTR || errno == ECONNABORTED { continue }; return }
            var on: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            lock.lock()
            let full = open >= 64
            if !full { open += 1; lastActivity = Date() }
            lock.unlock()
            if full { close(fd); continue }
            Thread.detachNewThread { [self] in
                connection(fd)
                close(fd)
                lock.lock(); open -= 1; lastActivity = Date(); lock.unlock()
            }
        }
    }

    final class Connection {
        let fd: Int32
        let peer: pid_t
        let peerStart: UInt64
        var binds: [SessionBind] = []
        var tainted = false
        /// The keys, listed once per connection: ssh asks for them, then signs, on the same connection.
        var identities: [SSHIdentity]?
        init(fd: Int32, peer: pid_t) { self.fd = fd; self.peer = peer; peerStart = startTime(peer) ?? 0 }
    }

    func connection(_ fd: Int32) {
        // Whoever is at the other end, as the kernel says: the pid can't be made up.
        let state = Connection(fd: fd, peer: peerPid(fd) ?? 0)
        while var header = readFull(fd, 4) {
            let length = Int(header.reduce(UInt32(0)) { $0 << 8 | UInt32($1) })
            header.removeAll()
            guard length >= 1, length <= sshAgentMaxMessage, var body = readFull(fd, length) else { break }
            var reply = respond(body, state)
            wipe(&body)
            var framed = SSHWriter()
            framed.string(reply)
            wipe(&reply)
            guard writeFull(fd, framed.bytes) else { break }
        }
    }

    func knownIdentities(_ state: Connection) -> [SSHIdentity] {
        if let known = state.identities { return known }
        let all = identities()
        state.identities = all
        return all
    }

    static let failure: [UInt8] = [5]
    static let success: [UInt8] = [6]

    func respond(_ body: [UInt8], _ state: Connection) -> [UInt8] {
        var r = SSHReader(body)
        guard let type = try? r.u8() else { return Self.failure }
        switch type {
        case 11:   // SSH_AGENTC_REQUEST_IDENTITIES
            guard r.done else { return Self.failure }
            let all = knownIdentities(state)
            var out = SSHWriter()
            out.u8(12)
            out.u32(UInt32(all.count))
            for identity in all { out.string(identity.key.blob); out.string(identity.name) }
            return out.bytes
        case 13:   // SSH_AGENTC_SIGN_REQUEST
            guard let blob = try? r.string(max: 16384), let data = try? r.string(), let flags = try? r.u32(), r.done else {
                return Self.failure
            }
            return sign(blob: blob, data: data, flags: flags, state)
        case 27:   // SSH_AGENTC_EXTENSION
            guard let name = try? r.text(max: 256) else { return Self.failure }
            guard name == "session-bind@openssh.com" else { return Self.failure }
            guard let hostKey = try? r.string(max: 16384), let session = try? r.string(max: 64),
                  let signature = try? r.string(max: 16384), let forwarding = try? r.bool(), r.done,
                  !session.isEmpty, verifySSHSignature(publicBlob: hostKey, signature: signature, data: session) else {
                state.tainted = true
                log("refused: a session-bind that doesn't verify; this connection signs nothing more")
                return Self.failure
            }
            // As ssh-agent: a connection bound for a login can't be bound again, and only so many hops.
            if state.binds.count >= 16 || state.binds.last.map({ !$0.forwarding }) == true {
                state.tainted = true
                return Self.failure
            }
            if !state.binds.contains(where: { $0.sessionID == session }) {
                state.binds.append(SessionBind(hostKey: hostKey, sessionID: session, forwarding: forwarding))
            }
            return Self.success
        case 17, 18, 19, 20, 21, 22, 23, 25, 26:
            log("refused: a client asked to add, remove or lock keys; touchenv's agent does none of that")
            return Self.failure
        default:
            return Self.failure
        }
    }

    func describe(_ identity: SSHIdentity, _ purpose: SignPurpose, _ state: Connection) -> SSHAsk {
        // Walk up from the client through ssh, git and shells to the app that asked.
        var via: [String] = [], commands: [String] = [], remote = false
        var destination: (text: String, host: String, port: Int?)?
        var pid = state.peer
        for _ in 0..<32 {
            guard pid > 1, let name = executableName(pid) else { break }
            if ["sshd", "sshd-session", "sshd-auth"].contains(name) { remote = true }
            if sshTools.contains(name) {
                if !via.contains(name) { via.insert(name, at: 0) }
                let argv = processArguments(pid)
                if commands.count < 3, !argv.isEmpty { commands.insert(shortCommand(argv), at: 0) }
                if name == "ssh", destination == nil { destination = sshDestination(argv) }
            }
            guard let parent = parentPid(pid) else { break }
            pid = parent
        }
        return SSHAsk(identity: identity, purpose: purpose, binds: state.binds, peer: state.peer, peerStart: state.peerStart,
                      who: requester(from: state.peer, through: sshTools), via: via, remote: remote,
                      destination: destination, commands: commands, knownHostFiles: knownHostFiles)
    }

    func sign(blob: [UInt8], data: [UInt8], flags: UInt32, _ state: Connection) -> [UInt8] {
        guard !state.tainted, let identity = knownIdentities(state).first(where: { $0.key.blob == blob }) else { return Self.failure }
        guard let purpose = signPurpose(data, key: blob) else {
            log("refused \(identity.name): the login names a different key")
            return Self.failure
        }
        // A login must belong to the session ssh bound this connection to, and name that server's key.
        if case .login(_, let session, let hostKey) = purpose, let bind = state.binds.last {
            guard bind.sessionID == session, hostKey == nil || hostKey! == bind.hostKey else {
                log("refused \(identity.name): the login is for another session than the one ssh bound")
                return Self.failure
            }
        }
        if identity.key.kind == .rsa && flags & 6 == 0 {
            log("refused \(identity.name): ssh-rsa (SHA-1) signature asked for")
            return Self.failure
        }
        let request = describe(identity, purpose, state)
        var key: [UInt8]
        if let k = covered(request) {
            key = k
            log("signed with \(identity.name) for \(request.who.name): \(request.action) (grant or 5-minute approval)")
        } else {
            lock.lock()
            let busy = waiting >= maxWaiting
            if !busy { waiting += 1 }
            lock.unlock()
            if busy {
                log("refused \(identity.name) for \(request.who.name): too many requests already waiting")
                return Self.failure
            }
            // One prompt at a time: the others wait here, in order.
            let result: Result<[UInt8], SSHRefusal> = prompts.sync {
                if clientLeft(state.fd) { return .failure(.refused("the client left before it was its turn")) }
                if let k = covered(request) { return .success(k) }
                return ask(request)
            }
            lock.lock(); waiting -= 1; lastActivity = Date(); lock.unlock()
            switch result {
            case .success(let k): key = k
            case .failure(.refused(let why)):
                log("refused \(identity.name) for \(request.who.name): \(request.action): \(why)")
                return Self.failure
            }
        }
        defer { wipe(&key) }
        guard case .openssh(let privateKey)? = try? parseSSHKeyFile(key, selfTest: false), privateKey.publicKey.blob == blob,
              let signature = try? privateKey.sign(data, flags: flags) else {
            log("failed \(identity.name): the stored key doesn't parse or doesn't match its public half")
            return Self.failure
        }
        var out = SSHWriter()
        out.u8(14)
        out.string(signature)
        return out.bytes
    }
}

func readFull(_ fd: Int32, _ count: Int) -> [UInt8]? {
    var out = [UInt8](repeating: 0, count: count)
    var got = 0
    while got < count {
        let n = out.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress! + got, count - got) }
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { wipe(&out); return nil }
        got += n
    }
    return out
}

func writeFull(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
    var sent = 0
    while sent < bytes.count {
        let n = bytes.withUnsafeBytes { write(fd, $0.baseAddress! + sent, bytes.count - sent) }
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { return false }
        sent += n
    }
    return true
}

/// Whether the client closed its end (ssh killed, Ctrl-C) while its request waited for an earlier prompt.
func clientLeft(_ fd: Int32) -> Bool {
    var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
    guard poll(&p, 1, 0) > 0 else { return false }
    if p.revents & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 { return true }
    var byte: UInt8 = 0
    return recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT) == 0
}

/// A process's arguments (argv), from the kernel.
func processArguments(_ pid: pid_t) -> [String] {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4, size < 1 << 20 else { return [] }
    var buffer = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }
    let argc = Int(buffer.withUnsafeBytes { $0.load(as: Int32.self) })
    var i = 4
    while i < size && buffer[i] != 0 { i += 1 }
    while i < size && buffer[i] == 0 { i += 1 }
    var out: [String] = []
    while out.count < min(argc, 256) && i < size {
        var end = i
        while end < size && buffer[end] != 0 { end += 1 }
        out.append(String(decoding: buffer[i..<end], as: UTF8.self))
        i = end + 1
    }
    return out
}

// MARK: SSH keys: where things are kept

/// The user's home: tests point it elsewhere.
var homePath = NSHomeDirectory()
func supportDir() -> String { homePath + "/Library/Application Support/touchenv" }
func sshPublicDir() -> String { supportDir() + "/ssh" }
func sshAgentSocket() -> String { supportDir() + "/ssh-agent.sock" }
func sshAgentLabel() -> String { "touchenv.ssh-agent" }
func sshAgentPlist() -> String { homePath + "/Library/LaunchAgents/\(sshAgentLabel()).plist" }
func sshAgentLog() -> String { homePath + "/Library/Logs/touchenv-ssh-agent.log" }
func sshConfigPath() -> String { homePath + "/.ssh/config" }
/// How the socket is written in ~/.ssh/config: quoted, for the space in "Application Support".
let sshConfigSocket = "\"~/Library/Application Support/touchenv/ssh-agent.sock\""
let sshConfigMarker = "# touchenv SSH agent (added by touchenv; delete these three lines to stop using it)"
var sshConfigLines: [String] { [sshConfigMarker, "Host *", "    IdentityAgent \(sshConfigSocket)"] }

/// "~/…" for paths under the home folder, for messages.
func tilde(_ path: String) -> String { path.hasPrefix(homePath + "/") ? "~" + path.dropFirst(homePath.count) : path }

/// A path in single quotes for a shell command.
func shellQuoted(_ path: String) -> String {
    path.allSatisfy({ $0.isLetter || $0.isNumber || "/._-~+".contains($0) }) && !path.hasPrefix("~")
        ? path : "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// A path for a command to copy: ~/… unquoted when that is safe, otherwise the full path, quoted if need be.
func shellPath(_ path: String) -> String {
    let short = tilde(path)
    return short.hasPrefix("~/") && shellQuoted(String(short.dropFirst())) == String(short.dropFirst()) ? short : shellQuoted(path)
}

func ensurePrivateDir(_ path: String) -> Bool {
    (try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true,
                                              attributes: [.posixPermissions: 0o700])) != nil
        && chmod(path, 0o700) == 0
}

func publicKeyPath(_ name: String) -> String { sshPublicDir() + "/\(name).pub" }

/// Writes NAME.pub (not secret) so ssh's IdentityFile can name the key and so listing never needs Touch ID.
@discardableResult
func writePublicKey(_ identity: SSHIdentity) -> Bool {
    guard ensurePrivateDir(sshPublicDir()) else { return false }
    let text = identity.key.line(comment: identity.name) + "\n"
    if FileManager.default.contents(atPath: publicKeyPath(identity.name)) == Data(text.utf8) { return true }
    return FileManager.default.createFile(atPath: publicKeyPath(identity.name), contents: Data(text.utf8),
                                          attributes: [.posixPermissions: 0o644])
}

/// The SSH keys touchenv holds, with no Touch ID: synced items from their attributes (iCloud items carry no access
/// control), local ones from the .pub files `ssh add` wrote, each checked to still exist. Two listings, then one probe
/// per local key; touchenv's SSH agent asks once per connection.
func sshIdentities() -> [SSHIdentity] {
    let allSynced = syncedNames()
    var out: [String: SSHIdentity] = [:]
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                            kSecAttrSynchronizable as String: true, kSecUseDataProtectionKeychain as String: true,
                            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
                            kSecAttrDescription as String: sshKeyMarker,
                            kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
    var found: CFTypeRef?
    if SecItemCopyMatching(q as CFDictionary, &found) == errSecSuccess, let items = found as? [[String: Any]] {
        for item in items {
            guard let name = item[kSecAttrAccount as String] as? String, validName(name),
                  let line = item[kSecAttrComment as String] as? String, let key = SSHPublicKey(line: line) else { continue }
            out[name] = SSHIdentity(name: name, key: key, synced: true)
        }
    }
    let files = (try? FileManager.default.contentsOfDirectory(atPath: sshPublicDir())) ?? []
    for file in files where file.hasSuffix(".pub") {
        let name = String(file.dropLast(4))
        guard validName(name), out[name] == nil, let data = FileManager.default.contents(atPath: publicKeyPath(name)),
              data.count < 65536, let key = SSHPublicKey(line: String(decoding: data, as: UTF8.self)),
              !allSynced.contains(name), localItemExists(name) else { continue }
        out[name] = SSHIdentity(name: name, key: key, synced: false)
    }
    return out.values.sorted { $0.name < $1.name }
}

/// Whether a local (not synced) secret of that name exists. No Touch ID: such an item answers "interaction not
/// allowed" when it exists.
func localItemExists(_ name: String) -> Bool {
    let probe = LAContext()
    probe.interactionNotAllowed = true
    var q = query(name)
    q[kSecAttrSynchronizable as String] = false
    q[kSecUseAuthenticationContext as String] = probe
    return SecItemCopyMatching(q as CFDictionary, nil) != errSecItemNotFound
}

/// "SSH_ID_ED25519" from "~/.ssh/id_ed25519".
func sshName(fromPath path: String) -> String {
    var base = URL(fileURLWithPath: path).lastPathComponent
    for ext in [".pem", ".key"] where base.lowercased().hasSuffix(ext) { base = String(base.dropLast(ext.count)) }
    let upper = String(base.uppercased().map { ($0.isASCII && ($0.isLetter || $0.isNumber)) ? $0 : "_" })
    return upper.hasPrefix("SSH_") ? upper : "SSH_" + upper
}

func sshAppendLog(_ line: String) {
    let path = sshAgentLog()
    _ = ensurePrivateDir((path as NSString).deletingLastPathComponent)
    if let size = (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int, size > 256 * 1024 {
        try? FileManager.default.removeItem(atPath: path + ".old")
        try? FileManager.default.moveItem(atPath: path, toPath: path + ".old")
    }
    let stamp = ISO8601DateFormatter().string(from: Date())
    let fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
    guard fd >= 0 else { return }
    _ = writeFull(fd, Array("\(stamp) \(line)\n".utf8))
    close(fd)
}

// MARK: SSH keys: turning other key files into OpenSSH's

/// Runs `/usr/bin/ssh-keygen -p -N ""` on a private copy of the key in a 0700 folder, which it rewrites as an
/// unencrypted OpenSSH key; returns that text and removes the folder, whatever happens. The passphrase (if any) goes
/// to ssh-keygen through SSH_ASKPASS: a two-line script in that folder that copies it from an inherited pipe (fd 3),
/// so it is never in an argument, the environment or a file. Only the decrypted copy touches the disk, briefly.
func convertWithSSHKeygen(_ original: [UInt8], passphrase: [UInt8]) throws -> [UInt8] {
    var template = Array((FileManager.default.temporaryDirectory.path + "/" + tempDirName("ssh") + "XXXXXX").utf8CString)
    guard let made = mkdtemp(&template) else { throw SSHFormatError("can't make a private temp folder") }
    let dir = String(cString: made)
    // Ctrl-C, a hang-up, TERM or QUIT while the decrypted copy is on disk: ssh-keygen is stopped and the copy deleted.
    registerTemp(folder: dir, files: [dir + "/key", dir + "/askpass"])
    var previous: [(Int32, sig_t?)] = []
    for s in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] { previous.append((s, signal(s, cleanUpAndExit))) }
    defer {
        removeTempDir(dir)   // overwrites the copy before it goes
        for (s, old) in previous { signal(s, old) }
        tempChild = 0
        tempFiles.forEach { free($0) }
        tempFiles = []
        free(tempFolder)
        tempFolder = nil
    }
    guard chmod(dir, 0o700) == 0 else { throw SSHFormatError("can't make a private temp folder") }
    let keyFd = open(dir + "/key", O_WRONLY | O_CREAT | O_EXCL, 0o600)
    guard keyFd >= 0, writeFull(keyFd, original) else { throw SSHFormatError("can't write the private copy") }
    close(keyFd)
    let script = "#!/bin/sh\nexec /bin/cat <&3\n"
    guard FileManager.default.createFile(atPath: dir + "/askpass", contents: Data(script.utf8),
                                         attributes: [.posixPermissions: 0o700]) else { throw SSHFormatError("can't write askpass") }
    var secretPipe: [Int32] = [0, 0], errorPipe: [Int32] = [0, 0]
    guard pipe(&secretPipe) == 0, pipe(&errorPipe) == 0 else { throw SSHFormatError("pipe failed") }
    // Above the descriptors the child gets, so no dup2 maps a descriptor onto itself (which would keep close-on-exec).
    let passIn = fcntl(secretPipe[0], F_DUPFD_CLOEXEC, 10), errorOut = fcntl(errorPipe[1], F_DUPFD_CLOEXEC, 10)
    close(secretPipe[0])
    close(errorPipe[1])
    var attributes: posix_spawnattr_t?
    posix_spawnattr_init(&attributes)
    // A new session: no terminal for ssh-keygen to ask on; and no descriptor of ours leaks into it but these.
    posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT))
    var actions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&actions)
    posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
    posix_spawn_file_actions_adddup2(&actions, errorOut, 1)
    posix_spawn_file_actions_adddup2(&actions, errorOut, 2)
    posix_spawn_file_actions_adddup2(&actions, passIn, 3)
    let argumentList: [String] = ["/usr/bin/ssh-keygen", "-q", "-p", "-N", "", "-f", dir + "/key"]
    let environment: [String] = ["SSH_ASKPASS=\(dir)/askpass", "SSH_ASKPASS_REQUIRE=force", "PATH=/usr/bin:/bin"]
    let argv: [UnsafeMutablePointer<CChar>?] = argumentList.map { strdup($0) } + [nil]
    let env: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) } + [nil]
    var pid = pid_t()
    let spawned = posix_spawn(&pid, "/usr/bin/ssh-keygen", &actions, &attributes, argv, env)
    if spawned == 0 { tempChild = pid }
    argv.forEach { free($0) }
    env.forEach { free($0) }
    posix_spawn_file_actions_destroy(&actions)
    posix_spawnattr_destroy(&attributes)
    // Only the child holds these now: its exit closes the error pipe.
    close(passIn)
    close(errorOut)
    if spawned == 0 {
        signal(SIGPIPE, SIG_IGN)
        _ = writeFull(secretPipe[1], passphrase + [10])
    }
    close(secretPipe[1])
    var errors = Data()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while case let n = Darwin.read(errorPipe[0], &chunk, chunk.count), n > 0, errors.count < 65536 { errors.append(chunk, count: n) }
    close(errorPipe[0])
    guard spawned == 0 else { throw SSHFormatError("can't run /usr/bin/ssh-keygen") }
    var status: Int32 = 0
    while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
    tempChild = 0   // reaped: its pid may be reused
    let message = String(decoding: errors, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    guard status == 0 else {
        if message.contains("incorrect passphrase") || message.contains("Bad passphrase") {
            throw SSHFormatError("wrong passphrase")
        }
        throw SSHFormatError("ssh-keygen couldn't read it" + (message.isEmpty ? "" : ": " + message))
    }
    guard let data = FileManager.default.contents(atPath: dir + "/key") else { throw SSHFormatError("ssh-keygen wrote nothing") }
    return [UInt8](data)
}

// MARK: SSH keys: talking to ssh-agent (touchenv ssh load) and to touchenv's own agent

func connectUnix(_ path: String) -> Int32? {
    guard path.utf8.count < 104 else { return nil }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    var on: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    var timeout = timeval(tv_sec: 10, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var address = socketAddress(path)
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    guard connected == 0 else { close(fd); return nil }
    return fd
}

/// One request, one reply, in the agent protocol's framing.
func agentRequest(_ fd: Int32, _ body: [UInt8]) -> [UInt8]? {
    var framed = SSHWriter()
    framed.string(body)
    defer { wipe(&framed.bytes) }
    guard writeFull(fd, framed.bytes), let header = readFull(fd, 4) else { return nil }
    let length = Int(header.reduce(UInt32(0)) { $0 << 8 | UInt32($1) })
    guard length >= 1, length <= sshAgentMaxMessage else { return nil }
    return readFull(fd, length)
}

/// Whether the process behind a socket is signed by Apple now. Not enough on its own: before the agent has answered,
/// a launchd-held socket's peer is launchd itself, and a process can pass by exec'ing an Apple program after
/// accepting (a child it forked keeps the connection). See macSSHAgentProblem.
func peerIsApple(_ fd: Int32) -> Bool {
    var token = audit_token_t()
    var length = socklen_t(MemoryLayout<audit_token_t>.size)
    guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0 else { return false }
    let tokenData = withUnsafeBytes(of: &token) { Data($0) }
    var peer: SecCode?, requirement: SecRequirement?
    guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: tokenData] as CFDictionary, [], &peer) == errSecSuccess,
          let peer, SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess else { return false }
    return SecCodeCheckValidity(peer, [], requirement) == errSecSuccess
}

/// pid, program and plist of a job, from `launchctl print`'s top-level lines; nil when any is missing.
func parseLaunchdJob(_ text: String) -> (pid: pid_t, program: String, path: String)? {
    var fields: [String: String] = [:]
    for line in text.split(separator: "\n") where line.hasPrefix("\t") && !line.hasPrefix("\t\t") {
        let parts = line.dropFirst().components(separatedBy: " = ")
        if parts.count == 2 { fields[parts[0]] = parts[1] }
    }
    guard let pidText = fields["pid"], let pid = pid_t(pidText), pid > 1, let program = fields["program"],
          let path = fields["path"] else { return nil }
    return (pid, program, path)
}

let macSSHAgentPlist = "/System/Library/LaunchAgents/com.openssh.ssh-agent.plist"

/// Why the connection is not to macOS's own ssh-agent, or nil when it is. Call after the agent has answered a request
/// on this connection: the kernel then names the process that last used the other end (LOCAL_PEERPID). It must be
/// the process launchd started for com.openssh.ssh-agent from the system's own plist, running /usr/bin/ssh-agent and
/// signed by Apple. That process was exec'd by launchd, so no other code ever ran in it, and it hands no connection
/// on: unlike a code-signature check alone, a listener that execs ssh-agent after accepting (while a child keeps
/// the connection) is not that process. launchctl print's format isn't an API: if it changes, load refuses.
func macSSHAgentProblem(_ fd: Int32) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    process.arguments = ["print", "gui/\(getuid())/com.openssh.ssh-agent"]
    let out = Pipe()
    process.standardOutput = out
    process.standardError = FileHandle.nullDevice
    guard (try? process.run()) != nil else { return "launchctl didn't run" }
    let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    process.waitUntilExit()
    guard process.terminationStatus == 0, let job = parseLaunchdJob(text) else {
        return "launchd's com.openssh.ssh-agent isn't running"
    }
    guard job.path == macSSHAgentPlist, job.program == "/usr/bin/ssh-agent" else {
        return "launchd's com.openssh.ssh-agent isn't the system's own (\(job.path))"
    }
    guard let peer = peerPid(fd), peer == job.pid else { return "the socket isn't served by launchd's ssh-agent" }
    guard processPath(peer) == "/usr/bin/ssh-agent", peerIsApple(fd) else { return "the process behind it isn't Apple's ssh-agent" }
    return nil
}

/// SSH_AGENTC_ADD_ID_CONSTRAINED with a lifetime: the key as ssh-add -t would send it.
func addIdentityMessage(_ key: SSHPrivateKey, comment: String, seconds: UInt32) -> [UInt8] {
    var w = SSHWriter()
    w.u8(25)
    w.bytes += key.record
    w.string(comment)
    w.u8(1)            // SSH_AGENT_CONSTRAIN_LIFETIME
    w.u32(seconds)
    return w.bytes
}

// MARK: SSH keys: the agent install, and the next steps after ssh add

func sshAgentInstalled() -> Bool { FileManager.default.fileExists(atPath: sshAgentPlist()) }

func launchctl(_ args: [String]) -> Int32 {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    process.arguments = args
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    guard (try? process.run()) != nil else { return -1 }
    process.waitUntilExit()
    return process.terminationStatus
}

func sshAgentLoaded() -> Bool { launchctl(["print", "gui/\(getuid())/\(sshAgentLabel())"]) == 0 }

/// The touchenv binary inside touchenv.app (not the ~/.local/bin link): launchd must start the signed app.
func appExecutable() -> String? {
    var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(getpid(), &path, UInt32(path.count)) > 0 else { return nil }
    let p = String(cString: path)
    return p.hasSuffix(".app/Contents/MacOS/touchenv") ? p : nil
}

func sshAgentPlistText(executable: String) -> String {
    func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
    }
    return """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>Label</key><string>\(sshAgentLabel())</string>
      <key>ProgramArguments</key><array><string>\(esc(executable))</string><string>ssh</string><string>agent</string><string>serve</string></array>
      <key>Sockets</key><dict><key>SSH</key><dict>
        <key>SockPathName</key><string>\(esc(sshAgentSocket()))</string>
        <key>SockPathMode</key><integer>384</integer>
      </dict></dict>
      <key>LimitLoadToSessionType</key><string>Aqua</string>
      <key>ProcessType</key><string>Interactive</string>
    </dict></plist>

    """
}

/// Writes the LaunchAgent and loads it: launchd makes the socket now and at every login, and starts
/// `touchenv ssh agent serve` when ssh connects.
func installSSHAgent() throws {
    guard let executable = appExecutable() else {
        throw SSHFormatError("run the touchenv inside touchenv.app (the Homebrew or release install) to install the agent")
    }
    guard sshAgentSocket().utf8.count < 104 else { throw SSHFormatError("the socket path is too long for a Unix socket") }
    guard ensurePrivateDir(supportDir()) else { throw SSHFormatError("can't create \(tilde(supportDir()))") }
    try? FileManager.default.createDirectory(atPath: (sshAgentPlist() as NSString).deletingLastPathComponent,
                                             withIntermediateDirectories: true)
    _ = launchctl(["bootout", "gui/\(getuid())/\(sshAgentLabel())"])
    unlink(sshAgentSocket())
    guard FileManager.default.createFile(atPath: sshAgentPlist(), contents: Data(sshAgentPlistText(executable: executable).utf8),
                                         attributes: [.posixPermissions: 0o644]) else {
        throw SSHFormatError("can't write \(tilde(sshAgentPlist()))")
    }
    guard launchctl(["bootstrap", "gui/\(getuid())", sshAgentPlist()]) == 0 else {
        throw SSHFormatError("launchctl bootstrap failed; see: launchctl print gui/\(getuid())/\(sshAgentLabel())")
    }
}

/// Whether ~/.ssh/config already sends ssh to touchenv's socket, and whether it names another agent too.
func sshConfigState(_ text: String?) -> (pointsHere: Bool, otherAgent: Bool) {
    var here = false, other = false
    for raw in (text ?? "").split(whereSeparator: \.isNewline) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        guard line.lowercased().hasPrefix("identityagent") else { continue }
        if line.contains("touchenv/ssh-agent.sock") { here = true } else { other = true }
    }
    return (here, other)
}

/// Appends the three lines to ~/.ssh/config after copying it to config.touchenv-backup. Never rewrites what is there.
func addSSHConfigLines() throws -> String? {
    let path = sshConfigPath()
    let dir = (path as NSString).deletingLastPathComponent
    var backup: String?
    if FileManager.default.fileExists(atPath: path) {
        backup = path + ".touchenv-backup"
        try? FileManager.default.removeItem(atPath: backup!)
        try FileManager.default.copyItem(atPath: path, toPath: backup!)
    } else if !FileManager.default.fileExists(atPath: dir) {
        guard ensurePrivateDir(dir) else { throw SSHFormatError("can't create \(tilde(dir))") }
    }
    let existing = FileManager.default.contents(atPath: path) ?? Data()
    var text = existing.isEmpty || existing.last == 10 ? "" : "\n"
    if !existing.isEmpty { text += "\n" }
    text += sshConfigLines.joined(separator: "\n") + "\n"
    let fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
    guard fd >= 0, writeFull(fd, Array(text.utf8)) else { if fd >= 0 { close(fd) }; throw SSHFormatError("can't write \(tilde(path))") }
    close(fd)
    return backup
}

/// Removes exactly the lines addSSHConfigLines wrote (after a backup), nothing else. Whether they were there.
func removeSSHConfigLines() throws -> Bool {
    let path = sshConfigPath()
    guard let data = FileManager.default.contents(atPath: path) else { return false }
    let text = String(decoding: data, as: UTF8.self)
    let block = sshConfigLines.joined(separator: "\n") + "\n"
    guard let range = text.range(of: block) else { return false }
    var rest = text
    rest.removeSubrange(range)
    if rest.hasSuffix("\n\n") { rest.removeLast() }
    try? FileManager.default.removeItem(atPath: path + ".touchenv-backup")
    try FileManager.default.copyItem(atPath: path, toPath: path + ".touchenv-backup")
    try Data(rest.utf8).write(to: URL(fileURLWithPath: path), options: .atomic)
    chmod(path, 0o600)
    return true
}

/// Asks a yes/no question on the terminal; `yes` is the answer to Return alone.
func confirm(_ question: String, yes: Bool) -> Bool {
    FileHandle.standardOutput.write(Data("\(question) \(yes ? "[Y/n]" : "[y/N]") ".utf8))
    guard let line = readLine() else { return false }
    let answer = line.trimmingCharacters(in: .whitespaces).lowercased()
    return answer.isEmpty ? yes : answer == "y" || answer == "yes"
}

/// After `touchenv ssh add`: what to do next, in the order that keeps the old key file until the new way works.
/// `interactive`: offer to do the first two steps here. Reads nothing secret; changes nothing unless answered yes.
struct SSHSetupState { var agentInstalled: Bool; var configText: String? }

func sshNextSteps(name: String, keyPath: String, state: SSHSetupState, interactive: Bool,
                  install: () throws -> Void = installSSHAgent, addLines: () throws -> String? = addSSHConfigLines,
                  ask: (String, Bool) -> Bool = confirm, say: (String) -> Void = { print($0) }) {
    var installed = state.agentInstalled
    var config = sshConfigState(state.configText)
    if !installed && interactive && ask("Set up the touchenv SSH agent now?", true) {
        do { try install(); installed = true; say("installed the touchenv SSH agent (\(tilde(sshAgentPlist())))") }
        catch { say("touchenv: couldn't install the agent: \(error)") }
    }
    if installed && !config.pointsHere && interactive {
        let existing = state.configText != nil
        say("These lines would go at the end of \(tilde(sshConfigPath()))\(existing ? " (a copy goes to config.touchenv-backup first)" : ""):")
        sshConfigLines.forEach { say("    " + $0) }
        // Return alone says yes: the lines were just shown, a backup is made, and without them the agent does nothing.
        if ask("Add them to \(tilde(sshConfigPath()))?", true) {
            do {
                _ = try addLines()
                config.pointsHere = true
                say("added them to \(tilde(sshConfigPath()))")
            } catch { say("touchenv: couldn't edit \(tilde(sshConfigPath())): \(error)") }
        }
    }
    say("")
    var steps: [String] = []
    if installed && config.pointsHere {
        say("The touchenv SSH agent is set up and \(tilde(sshConfigPath())) points ssh at it.")
    } else {
        if !installed { steps.append("Install the touchenv SSH agent:  touchenv ssh agent install") }
        if !config.pointsHere {
            steps.append("Point ssh at it: add to \(tilde(sshConfigPath())) (or run touchenv ssh agent install --config):\n"
                         + "         Host *\n             IdentityAgent \(sshConfigSocket)")
        }
    }
    if config.otherAgent {
        steps.append("\(tilde(sshConfigPath())) names another IdentityAgent too: ssh uses the first that applies to a host.")
    }
    let socket = tilde(sshAgentSocket()).hasPrefix("~/") ? "~/\"\(tilde(sshAgentSocket()).dropFirst(2))\"" : shellQuoted(sshAgentSocket())
    steps.append("Try it:  ssh -T git@github.com   (or: SSH_AUTH_SOCK=\(socket) ssh-add -L)\n"
                 + "       A Touch ID prompt names the app that asks, \(name) and the server; nothing signs without your finger.")
    steps.append("Rather use the stock ssh-agent?  touchenv ssh load --for 8h \(name)")
    steps.append("When that works: \(tilde(keyPath)) is still on disk, untouched. Checks will flag it until you delete it:\n"
                 + "         rm \(shellPath(keyPath))")
    if !(installed && config.pointsHere) { say("Next:") }
    for (i, step) in steps.enumerated() { say(" \(i + 1). \(step)") }
}

// MARK: SSH keys: the agent process

func screenLocked() -> Bool {
    guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return true }
    if session["CGSSessionScreenIsLocked"] as? Bool == true { return true }
    return session[kCGSessionOnConsoleKey as String] as? Bool == false
}

/// The prompt for one sign request: who, which key (bold), what for, the server; the command lines under More detail.
func sshPromptText(_ a: SSHAsk) -> (title: String, notes: [String], detail: String?, reason: String) {
    let via = a.via.isEmpty ? "" : " (\(a.via.joined(separator: ", ")))"
    let title = "Allow \(a.who.name)\(via) to \(a.action) with \(strong(a.identity.name)) from \(a.identity.synced ? "iCloud Keychain" : "your Keychain")?"
    var notes: [String] = []
    if let server = a.serverNote { notes.append(server) }
    if case .login(let user, _, _) = a.purpose, a.destination == nil { notes.append("As user \(user).") }
    let detail = a.commands.isEmpty ? nil : a.commands.joined(separator: "\n")
    return (title, notes, detail, "let \(a.who.name) \(a.action) with the SSH key \(a.identity.name)")
}

func serveSSHAgent() -> Never {
    let fds = UnsafeMutablePointer<UnsafeMutablePointer<Int32>>.allocate(capacity: 1)
    var count = 0
    guard launch_activate_socket("SSH", fds, &count) == 0, count > 0 else {
        die("touchenv: ssh agent serve is started by launchd: touchenv ssh agent install")
    }
    let listeners = (0..<count).map { fds.pointee[$0] }
    free(fds.pointee)
    signal(SIGPIPE, SIG_IGN)
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let server = SSHAgentServer(
        identities: sshIdentities,
        covered: { a in
            guard let reply = askAgent(["op": "get", "names": [a.identity.name], "for": Int(a.peer),
                                        "forStart": Int(a.peerStart), "ssh": a.action, "sign": true]),
                  reply["ok"] as? Bool == true, let encoded = (reply["secrets"] as? [String: String])?[a.identity.name],
                  let data = Data(base64Encoded: encoded) else { return nil }
            return [UInt8](data)
        },
        ask: { a in
            if a.remote { return .failure(.refused("it came through an ssh session to this Mac, where nobody may be at the screen; a grant would cover it")) }
            if screenLocked() { return .failure(.refused("the screen is locked; a grant would cover it")) }
            let text = sshPromptText(a)
            let answered = DispatchSemaphore(value: 0)
            var approved = false, keep = false
            DispatchQueue.main.async {
                authenticateAsync(text.title, notes: text.notes, detail: text.detail, reason: text.reason, asker: a.who,
                                  offerSession: true, timeout: 60) { ok, k in
                    approved = ok
                    keep = k
                    answered.signal()
                }
            }
            if answered.wait(timeout: .now() + 120) == .timedOut { return .failure(.refused("no answer")) }
            guard approved else { return .failure(.refused("not approved")) }
            let (data, status) = readSecret(a.identity.name)
            guard let data else { return .failure(.refused("keychain error \(status)")) }
            if keep, startAgent() {
                _ = askAgent(["op": "grant", "secrets": [a.identity.name: data.base64EncodedString()],
                              "for": Int(a.peer), "forStart": Int(a.peerStart), "signOnly": true])
            }
            return .success([UInt8](data))
        },
        log: sshAppendLog,
        knownHostFiles: [homePath + "/.ssh/known_hosts", homePath + "/.ssh/known_hosts2", "/etc/ssh/ssh_known_hosts"])
    for fd in listeners { Thread.detachNewThread { server.serve(fd) } }
    // launchd keeps the socket; with nothing to do for 15 minutes, this process can go and be started again.
    Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in
        if server.idle && Date().timeIntervalSince(server.idleSince) > 15 * 60 && activePrompt == nil { exit(0) }
    }
    app.run()
    exit(0)
}

// MARK: Temp files (run NAME:file, ssh add's decrypted copy)

// A private temp folder is named touchenv-PID-START-… (touchenv-ssh-PID-START-… for ssh add), after the touchenv
// process that made it, so a later touchenv run can tell one left behind by a touchenv that is gone (killed with
// SIGKILL, a crash) and delete it.

func tempDirName(_ kind: String = "") -> String {
    "touchenv-\(kind.isEmpty ? "" : kind + "-")\(getpid())-\(startTime(getpid()) ?? 0)-"
}

/// The pid and start time in a temp folder's name, or nil when it is not one of those.
func tempDirOwner(_ name: String) -> (pid: pid_t, start: UInt64)? {
    guard name.hasPrefix("touchenv-") else { return nil }
    var rest = name.dropFirst("touchenv-".count)
    if rest.hasPrefix("ssh-") { rest = rest.dropFirst(4) }
    let parts = rest.split(separator: "-", maxSplits: 2, omittingEmptySubsequences: false)
    // A start time in microseconds after 2001: an older touchenv's touchenv-UUID can't pass for one.
    guard parts.count == 3, !parts[2].isEmpty, let pid = pid_t(parts[0]), pid > 0, let start = UInt64(parts[1]),
          start > 1_000_000_000_000_000 else {
        return nil
    }
    return (pid, start)
}

/// Overwrites the files in a temp folder with zeros, then deletes it.
func removeTempDir(_ path: String) {
    for file in (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? [] {
        var st = stat()
        guard lstat(path + "/" + file, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { continue }
        let fd = open(path + "/" + file, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd >= 0 { _ = writeFull(fd, [UInt8](repeating: 0, count: Int(st.st_size))); fsync(fd); close(fd) }
    }
    try? FileManager.default.removeItem(atPath: path)
}

/// Your temp folders in `dir` whose touchenv process is gone: `alive` says whether a pid with that start time runs.
func staleTempDirs(in dir: String, alive: (pid_t, UInt64) -> Bool = { startTime($0) == $1 }) -> [String] {
    ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).compactMap { name in
        guard let owner = tempDirOwner(name), !alive(owner.pid, owner.start) else { return nil }
        let path = dir + "/" + name
        var st = stat()
        guard lstat(path, &st) == 0, st.st_mode & S_IFMT == S_IFDIR, st.st_uid == getuid() else { return nil }
        return path
    }
}

func sweepStaleTempDirs() {
    for path in staleTempDirs(in: FileManager.default.temporaryDirectory.path) { removeTempDir(path) }
}

// What the signal handlers below need: plain globals, as C strings made beforehand.
var tempFiles: [UnsafeMutablePointer<CChar>] = []
var tempFolder: UnsafeMutablePointer<CChar>?
var tempChild: pid_t = 0
var tempSpawning = false
var tempPendingSignal: Int32 = 0

/// Registers a temp folder and the files that will be in it, for the signal handlers.
func registerTemp(folder: String, files: [String]) {
    tempFolder = strdup(folder)
    tempFiles = files.map { strdup($0) }
}

func removeRegisteredTemp() {
    for file in tempFiles { unlink(file) }
    if let folder = tempFolder { rmdir(folder) }
}

/// touchenv run while it waits for the command: a hang-up (the terminal closed), TERM or QUIT is passed on to the
/// command, and touchenv deletes the files once it has ended. Before the command started, the files go now and
/// touchenv ends by that signal.
func forwardOrCleanUp(_ signal: Int32) {
    if tempChild > 0 { kill(tempChild, signal); return }
    if tempSpawning { tempPendingSignal = signal; return }
    removeRegisteredTemp()
    Darwin.signal(signal, SIG_DFL)
    raise(signal)
}

/// ssh add while ssh-keygen works on the decrypted copy: stop it, delete the copy, end by that signal.
func cleanUpAndExit(_ signal: Int32) {
    if tempChild > 0 { kill(tempChild, SIGKILL) }
    removeRegisteredTemp()
    Darwin.signal(signal, SIG_DFL)
    raise(signal)
}

// MARK: Commands

/// One line, and no control characters: they could restyle the prompt (see strong).
func cleanIntent(_ raw: String) -> String? {
    let text = String(String.UnicodeScalarView(raw.replacingOccurrences(of: "\n", with: " ").unicodeScalars
        .filter { !CharacterSet.controlCharacters.contains($0) })).trimmingCharacters(in: .whitespaces)
    return text.isEmpty ? nil : (text.count > 200 ? String(text.prefix(199)) + "…" : text)
}

let grantUsage = """
usage: touchenv grant --for 8h --uses 20 NAME ...         a timed grant to this app and what it runs
       touchenv grant --always --for-program PROGRAM [--for 90d] [--uses N] NAME ...
                                                          a standing grant to one program
       touchenv grant --list · --revoke PROGRAM · --revoke-all
       --password before the limits: type your Mac password in the terminal instead of Touch ID (synced secrets only)
"""

let sshUsage = """
usage: touchenv ssh add [--sync] [NAME] KEYFILE · touchenv ssh ls · touchenv ssh rm NAME
       touchenv ssh load [--for 1h] NAME ... · touchenv ssh unload NAME ...
       touchenv ssh agent install [--config] · touchenv ssh agent uninstall [--config] · touchenv ssh agent status
"""

func sshCommand(_ arguments: [String], intent globalIntent: String?) -> Never {
    var rest = arguments
    guard let sub = rest.first else { die(sshUsage, 2) }
    rest.removeFirst()
    var intent = globalIntent, syncKey = false, loadFor: TimeInterval?, configFlag = false
    if sub == "agent", let action = rest.first, !action.hasPrefix("--") {
        rest.removeFirst()
        rest.insert(action, at: rest.firstIndex { !$0.hasPrefix("--") } ?? rest.count)   // options may come after it
    }
    while let option = rest.first, option.hasPrefix("--"), option != "--" {
        if option == "--sync", sub == "add" {
            syncKey = true
            rest.removeFirst()
        } else if option == "--for", sub == "load", rest.count > 1 {
            guard let length = parseLength(rest[1]), length <= maxGrantLength else {
                die("touchenv: --for takes a length like 30m, 8h or 1h30m, 24h at most", 2)
            }
            loadFor = length
            rest.removeFirst(2)
        } else if option == "--config", sub == "agent" {
            configFlag = true
            rest.removeFirst()
        } else if option == "--intent", rest.count > 1 {
            intent = cleanIntent(rest[1])
            rest.removeFirst(2)
        } else {
            die("touchenv: unknown option \(option)", 2)
        }
    }

    switch sub {
    case "add":
        guard (1...2).contains(rest.count), rest.count == 1 || validName(rest[0]) else {
            die("usage: touchenv ssh add [--sync] [NAME] KEYFILE  (NAME = env var style; from the file's name if left out)", 2)
        }
        let path = rest.last!
        let absolute = URL(fileURLWithPath: path).standardizedFileURL.path
        let name = rest.count == 2 ? rest[0] : sshName(fromPath: path)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: absolute, isDirectory: &isDirectory), !isDirectory.boolValue,
              let size = (try? FileManager.default.attributesOfItem(atPath: absolute))?[.size] as? Int,
              let data = FileManager.default.contents(atPath: absolute) else { die("touchenv: can't read \(path)") }
        guard size <= 65536 else { die("touchenv: \(path) is too big to be an SSH private key") }
        var text = [UInt8](data)
        var stored: [UInt8] = []
        let key: SSHPrivateKey
        do {
            switch try parseSSHKeyFile(text) {
            case .openssh(let parsed):
                key = parsed
                stored = text
            case .convert(let needsPassphrase):
                var passphrase: [UInt8] = []
                if needsPassphrase {
                    guard isatty(0) != 0 else {
                        die("touchenv: \(path) is protected by a passphrase: run this in a terminal to type it once")
                    }
                    var buffer = [CChar](repeating: 0, count: 1024)
                    guard readpassphrase("Passphrase for \(tilde(absolute)) (not shown): ", &buffer, buffer.count,
                                         Int32(RPP_REQUIRE_TTY)) != nil else { die("touchenv: no passphrase") }
                    passphrase = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
                    _ = memset_s(&buffer, buffer.count, 0, buffer.count)
                }
                var converted = try convertWithSSHKeygen(text, passphrase: passphrase)
                wipe(&passphrase)
                guard case .openssh(let parsed) = try parseSSHKeyFile(converted) else {
                    wipe(&converted)
                    throw SSHFormatError("ssh-keygen didn't give an unencrypted OpenSSH key")
                }
                key = parsed
                stored = converted
                wipe(&converted)
            }
        } catch { die("touchenv: \(path): \(error)") }
        wipe(&text)
        if synced(name) != nil {
            die("touchenv: there is already a secret named \(name): give another name (touchenv ssh add NAME \(path))")
        }
        let identity = SSHIdentity(name: name, key: key.publicKey, synced: syncKey)
        add(name, Data(stored), sync: syncKey, extra: [kSecAttrDescription as String: sshKeyMarker,
                                                       kSecAttrComment as String: key.publicKey.line(comment: name)])
        wipe(&stored)
        if !writePublicKey(identity) { print("touchenv: couldn't write \(tilde(publicKeyPath(name)))") }
        let k = key.publicKey
        print("stored \(name): \(k.kind.label) \(k.bits) \(k.fingerprint)\(key.comment.isEmpty ? "" : " \(key.comment)"), "
              + (syncKey ? "synced through iCloud Keychain" : "on this Mac only"))
        print("public key: \(tilde(publicKeyPath(name)))")
        let state = SSHSetupState(agentInstalled: sshAgentInstalled(),
                                  configText: try? String(contentsOfFile: sshConfigPath(), encoding: .utf8))
        sshNextSteps(name: name, keyPath: absolute, state: state, interactive: isatty(0) != 0 && isatty(1) != 0)
        exit(0)

    case "ls":
        guard rest.isEmpty else { die("usage: touchenv ssh ls", 2) }
        let all = sshIdentities()
        if all.isEmpty { print("no SSH keys in touchenv; add one: touchenv ssh add ~/.ssh/id_ed25519") }
        let width = all.map(\.name.count).max() ?? 0
        for identity in all {
            writePublicKey(identity)   // synced from another Mac: give it its .pub here too
            let k = identity.key
            print(identity.name.padding(toLength: width, withPad: " ", startingAt: 0)
                  + "  \(k.kind.label) \(k.bits)  \(k.fingerprint)  \(identity.synced ? "iCloud" : "this Mac")")
        }
        exit(0)

    case "rm":
        guard rest.count == 1, validName(rest[0]) else { die("usage: touchenv ssh rm NAME", 2) }
        let name = rest[0]
        guard sshIdentities().contains(where: { $0.name == name }) else {
            die(synced(name) == nil ? "touchenv: no SSH key named \(name)"
                : "touchenv: \(name) isn't an SSH key from touchenv ssh add (touchenv rm \(name) deletes any secret)")
        }
        requireIntent(intent, example: "touchenv ssh rm --intent \"<why>\" \(name)")
        let who = requester().name
        authenticate("Allow \(who) to delete the SSH key \(strong(name)) from \(place([name]))?", intent: intent,
                     reason: "let \(who) delete the SSH key \(name)")
        let status = SecItemDelete(query(name) as CFDictionary)
        if status != errSecSuccess { die("touchenv: keychain error \(status)") }
        unlink(publicKeyPath(name))
        print("deleted \(name). If it is loaded into ssh-agent too: ssh-add -D, or wait for its time to run out.")
        exit(0)

    case "load", "unload":
        guard !rest.isEmpty, rest.allSatisfy(validName) else {
            die(sub == "load" ? "usage: touchenv ssh load [--for 1h] NAME ...  (24h at most)" : "usage: touchenv ssh unload NAME ...", 2)
        }
        var names: [String] = []
        for name in rest where !names.contains(name) { names.append(name) }
        guard let socketPath = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"], !socketPath.isEmpty else {
            die("touchenv: SSH_AUTH_SOCK isn't set, so there is no ssh-agent to \(sub == "load" ? "load into" : "unload from")")
        }
        if URL(fileURLWithPath: socketPath).resolvingSymlinksInPath().path == URL(fileURLWithPath: sshAgentSocket()).resolvingSymlinksInPath().path {
            die("touchenv: SSH_AUTH_SOCK is touchenv's own agent, which never holds keys; ssh \(sub) is for the stock ssh-agent")
        }
        let identities = sshIdentities()
        var chosen: [SSHIdentity] = []
        for name in names {
            guard let identity = identities.first(where: { $0.name == name }) else {
                die("touchenv: no SSH key named \(name) (touchenv ssh ls lists them)")
            }
            chosen.append(identity)
        }
        guard let fd = connectUnix(socketPath) else { die("touchenv: can't reach ssh-agent at \(socketPath)") }
        defer { close(fd) }
        if sub == "unload" {
            for identity in chosen {
                var w = SSHWriter()
                w.u8(18)   // SSH_AGENTC_REMOVE_IDENTITY
                w.string(identity.key.blob)
                print(agentRequest(fd, w.bytes) == SSHAgentServer.success ? "unloaded \(identity.name)"
                                                                        : "\(identity.name) wasn't loaded")
            }
            exit(0)
        }
        // The key goes only to macOS's own ssh-agent, on this very connection: no ssh-add, no file, no argument. It
        // answers a harmless request first (the list of its keys), so the kernel can name the process that serves
        // this connection.
        var list = SSHWriter()
        list.u8(11)   // SSH_AGENTC_REQUEST_IDENTITIES
        guard agentRequest(fd, list.bytes)?.first == 12 else { die("touchenv: ssh-agent at \(socketPath) doesn't answer") }
        if let problem = macSSHAgentProblem(fd) {
            die("touchenv: \(socketPath) isn't macOS's own ssh-agent (\(problem)); touchenv ssh load hands keys to that one "
                + "only. An ssh-agent you started yourself can't be told apart from a program posing as one: use "
                + "touchenv's agent (touchenv ssh agent install) instead")
        }
        let length = loadFor ?? sshDefaultLoad
        requireIntent(intent, example: "touchenv ssh load --intent \"<why>\" --for 1h \(names.joined(separator: " "))")
        let who = requester().name
        let it = names.count == 1 ? "it" : "them"
        authenticate("Allow \(who) to load \(strong(names)) into ssh-agent for \(spokenLength(length))? Until then any program "
                     + "running as you can sign with \(it) without asking.", intent: intent,
                     reason: "let \(who) load \(names.joined(separator: ", ")) into ssh-agent for \(spokenLength(length))")
        for identity in chosen {
            var text = [UInt8](read(identity.name))
            defer { wipe(&text) }
            guard case .openssh(let key)? = try? parseSSHKeyFile(text, selfTest: false), key.publicKey == identity.key else {
                die("touchenv: \(identity.name) doesn't hold the SSH key its public half says")
            }
            var message = addIdentityMessage(key, comment: identity.name, seconds: UInt32(length))
            let reply = agentRequest(fd, message)
            wipe(&message)
            guard reply == SSHAgentServer.success else { die("touchenv: ssh-agent refused \(identity.name)") }
        }
        let until = DateFormatter.localizedString(from: Date().addingTimeInterval(length), dateStyle: .none, timeStyle: .short)
        print("loaded \(names.joined(separator: ", ")) into ssh-agent until \(until). "
              + "touchenv ssh unload \(names.joined(separator: " ")) takes \(it) out sooner.")
        exit(0)

    case "agent":
        let agentUsage = "usage: touchenv ssh agent install [--config] · touchenv ssh agent uninstall [--config] · touchenv ssh agent status"
        guard rest.count == 1 else { die(agentUsage, 2) }
        switch rest[0] {
        case "install":
            do { try installSSHAgent() } catch { die("touchenv: \(error)") }
            print("installed: launchd holds \(tilde(sshAgentSocket())) from now on, and at every login, and starts touchenv when ssh connects.")
            let config = sshConfigState(try? String(contentsOfFile: sshConfigPath(), encoding: .utf8))
            if config.pointsHere {
                print("\(tilde(sshConfigPath())) already points ssh at it.")
            } else if configFlag {
                do {
                    let backup = try addSSHConfigLines()
                    print("added to the end of \(tilde(sshConfigPath()))\(backup.map { " (the old one: \(tilde($0)))" } ?? ""):")
                    sshConfigLines.forEach { print("    " + $0) }
                } catch { die("touchenv: \(error)") }
            } else {
                print("Point ssh at it: add to \(tilde(sshConfigPath())) (or run this again with --config):")
                sshConfigLines.dropFirst().forEach { print("    " + $0) }
                print("To offer only one key to a host:\n    Host github.com\n        IdentityFile \"~/Library/Application Support/touchenv/ssh/NAME.pub\"\n        IdentitiesOnly yes")
            }
            if config.otherAgent { print("Note: \(tilde(sshConfigPath())) names another IdentityAgent too; ssh uses the first that applies.") }
        case "uninstall":
            _ = launchctl(["bootout", "gui/\(getuid())/\(sshAgentLabel())"])
            let had = sshAgentInstalled()
            try? FileManager.default.removeItem(atPath: sshAgentPlist())
            unlink(sshAgentSocket())
            print(had ? "uninstalled the touchenv SSH agent" : "the touchenv SSH agent wasn't installed")
            if configFlag {
                do {
                    print(try removeSSHConfigLines() ? "removed touchenv's lines from \(tilde(sshConfigPath())) (the old one: config.touchenv-backup)"
                                                    : "\(tilde(sshConfigPath())) has no lines from touchenv")
                } catch { die("touchenv: \(error)") }
            } else if sshConfigState(try? String(contentsOfFile: sshConfigPath(), encoding: .utf8)).pointsHere {
                print("\(tilde(sshConfigPath())) still names its socket: delete those lines, or run this again with --config.")
            }
            print("Your SSH keys stay in touchenv (touchenv ssh ls; touchenv ssh rm NAME).")
        case "status":
            let installed = sshAgentInstalled()
            print("agent: " + (installed ? (sshAgentLoaded() ? "installed and loaded (\(sshAgentLabel()))" : "installed, not loaded: touchenv ssh agent install")
                                         : "not installed: touchenv ssh agent install"))
            var answers = "not answering"
            if let fd = connectUnix(sshAgentSocket()) {
                if let reply = agentRequest(fd, [11]), reply.first == 12 { answers = "answering" }
                close(fd)
            }
            print("socket: \(tilde(sshAgentSocket())) (\(answers))")
            let config = sshConfigState(try? String(contentsOfFile: sshConfigPath(), encoding: .utf8))
            print("\(tilde(sshConfigPath())): " + (config.pointsHere ? "points ssh at it" : "doesn't name it (touchenv ssh agent install --config)")
                  + (config.otherAgent ? "; names another IdentityAgent too" : ""))
            let identities = sshIdentities()
            print("keys: " + (identities.isEmpty ? "none (touchenv ssh add KEYFILE)" : identities.map(\.name).joined(separator: ", ")))
            if let log = try? String(contentsOfFile: sshAgentLog(), encoding: .utf8) {
                let recent = log.split(separator: "\n").suffix(5)
                if !recent.isEmpty { print("recent (\(tilde(sshAgentLog()))):"); recent.forEach { print("  " + $0) } }
            }
        case "serve":
            serveSSHAgent()
        default:
            die(agentUsage, 2)
        }
        exit(0)

    default:
        die(sshUsage, 2)
    }
}

#if !TOUCHENV_TESTS

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else { die(usage, 2) }
args.removeFirst()
var intent: String?
var sync = false
var recipientArgument: String?
var begin = false, replace = false, localOnly = false
var grantLength: TimeInterval?
var grantLengthText = ""
var grantUses: Int?
var grantUsesText = ""
var always = false, forProgram: String?, listGrants = false, revokeProgram: String?, revokeAll = false
var lockAll = false
var usePassword = false
var logSince: TimeInterval?, logSummary = false
while let option = args.first, option.hasPrefix("--"), option != "--" {
    if option == "--sync", command == "set" {
        sync = true
        args.removeFirst()
    } else if option == "--to", command == "export", args.count > 1 {
        recipientArgument = args[1]
        args.removeFirst(2)
    } else if command == "import", ["--begin", "--replace", "--local"].contains(option) {
        if option == "--begin" { begin = true } else if option == "--replace" { replace = true } else { localOnly = true }
        args.removeFirst()
    } else if option == "--for", command == "grant", args.count > 1 {
        // Checked once all options are in: a standing grant (--always) allows longer.
        grantLength = parseLength(args[1]) ?? -1
        grantLengthText = args[1]
        args.removeFirst(2)
    } else if option == "--uses", command == "grant", args.count > 1 {
        grantUses = Int(args[1]) ?? -1
        grantUsesText = args[1]
        args.removeFirst(2)
    } else if command == "grant", ["--always", "--list", "--revoke-all"].contains(option) {
        if option == "--always" { always = true } else if option == "--list" { listGrants = true } else { revokeAll = true }
        args.removeFirst()
    } else if command == "grant", option == "--for-program" || option == "--revoke", args.count > 1 {
        if option == "--revoke" { revokeProgram = args[1] } else { forProgram = args[1] }
        args.removeFirst(2)
    } else if option == "--password", ["get", "run", "grant"].contains(command) {
        usePassword = true
        args.removeFirst()
    } else if option == "--all", command == "lock" {
        lockAll = true
        args.removeFirst()
    } else if option == "--since", command == "log", args.count > 1 {
        guard let length = parseLength(args[1]) else { die("touchenv: --since takes a length like 24h, 7d or 30m", 2) }
        logSince = length
        args.removeFirst(2)
    } else if option == "--summary", command == "log" {
        logSummary = true
        args.removeFirst()
    } else if option == "--help", command == "log" {
        print(logUsage)
        exit(0)
    } else if option == "--intent", args.count > 1 {
        intent = cleanIntent(args[1])
        args.removeFirst(2)
    } else {
        die("touchenv: unknown option \(option)", 2)
    }
}
if command == "grant" {
    let standing = always || forProgram != nil
    let maxLength = standing ? maxStandingLength : maxGrantLength
    let maxUses = standing ? maxStandingUses : maxGrantUses
    if let length = grantLength, length <= 0 || length > maxLength {
        die(standing ? "touchenv: --for takes a length like 90d, 12h or 30m, 3650d at most"
                     : "touchenv: --for takes a length like 30m, 8h or 1h30m, 24h at most", 2)
    }
    if let uses = grantUses, !(1...maxUses).contains(uses) {
        die("touchenv: --uses takes a number from 1 to \(maxUses)", 2)
    }
}

switch command {
case "set":
    guard args.count == 1, validName(args[0]) else { die("usage: touchenv set [--sync] NAME  (NAME = env var style)", 2) }
    let name = args[0]
    let data = readStdin()
    if data.isEmpty { die("touchenv: empty secret, nothing stored") }
    let asker = requester()
    if let wasSynced = synced(name) {
        beginAttempt("set", [name], who: asker, intent: intent)
        requireIntent(intent, example: "touchenv set --intent \"<why>\" \(sync ? "--sync " : "")\(name)", who: asker)
        let who = asker.name
        // Syncing on or off is said in so many words: without --sync, a synced secret leaves every other Mac.
        let (title, reason) = wasSynced == sync
            ? ("Allow \(who) to replace \(strong(name)) in \(sync ? "iCloud Keychain" : "your Keychain")?",
               "let \(who) replace the secret \(name)")
            : sync ? ("Allow \(who) to replace \(strong(name)) and start syncing it? It goes into iCloud Keychain, on "
                      + "your other Macs too, guarded by touchenv instead of macOS's own lock.",
                      "let \(who) replace the secret \(name) and start syncing it through iCloud Keychain")
                   : ("Allow \(who) to replace \(strong(name)) and stop syncing it? It is deleted from iCloud Keychain, "
                      + "and so from your other Macs, and kept on this Mac only. (set --sync keeps it synced.)",
                      "let \(who) replace the secret \(name) and stop syncing it: deleted from your other Macs")
        authenticate(title, intent: intent, reason: reason, asker: asker)
        replaceSecret(name, data, sync: sync, wasSynced: wasSynced,
                      keep: [kSecAttrDescription as String, kSecAttrComment as String])
        logAttempt("replaced", note: wasSynced == sync ? "" : sync ? "now synced" : "no longer synced")
        let copies = standingSecretChanged(name, to: data, who: who)
        if copies > 0 { print("updated the copy \(copies) standing grant\(copies == 1 ? "" : "s") hold\(copies == 1 ? "s" : "") of \(name)") }
        if wasSynced != sync {
            print("stored \(name) (\(data.count) bytes), " + (sync ? "now synced through iCloud Keychain to your other Macs"
                                                                    : "on this Mac only: no longer synced, deleted from iCloud Keychain"))
            exit(0)
        }
    } else {
        add(name, data, sync: sync)
        logAccess(AccessEntry(event: "set", secrets: [name], outcome: "stored", who: asker.name,
                              program: callingProgram(asker)))
    }
    print("stored \(name) (\(data.count) bytes)\(sync ? ", synced through iCloud Keychain" : "")")

case "sync", "unsync":
    // Moves secrets between this Mac only (macOS's own Touch ID lock) and iCloud Keychain without the value ever
    // leaving touchenv: no shell, file or pipe in between. Add first, then delete (replaceSecret).
    let toSync = command == "sync"
    guard !args.isEmpty, args.allSatisfy(validName) else { die("usage: touchenv \(command) NAME ...", 2) }
    var names: [String] = []
    for name in args where !names.contains(name) { names.append(name) }
    let asker = requester()
    beginAttempt(command, names, who: asker, intent: intent)
    requireIntent(intent, example: "touchenv \(command) --intent \"<why>\" \(names.joined(separator: " "))", who: asker)
    let syncedNow = syncedNames()
    requireStored(names, among: syncedNow)
    let moving = names.filter { synced($0, among: syncedNow) != toSync }
    for name in names where !moving.contains(name) {
        print("\(name) is already \(toSync ? "synced through iCloud Keychain" : "on this Mac only")")
    }
    if moving.isEmpty {
        currentAttempt = nil
        exit(0)
    }
    let who = asker.name
    let list = moving.map(strong).joined(separator: ", ")
    let plural = moving.count > 1
    let (title, reason) = toSync
        ? ("Allow \(who) to start syncing \(list)? \(plural ? "They go" : "It goes") into iCloud Keychain, on your other "
           + "Macs too, guarded by touchenv instead of macOS's own lock.",
           "let \(who) start syncing \(moving.joined(separator: ", ")) through iCloud Keychain")
        : ("Allow \(who) to stop syncing \(list)? \(plural ? "They are" : "It is") deleted from iCloud Keychain, and so "
           + "from your other Macs, and kept on this Mac only.",
           "let \(who) stop syncing \(moving.joined(separator: ", ")): deleted from your other Macs")
    authenticate(title, intent: intent, reason: reason, asker: asker)
    var moved: [String] = []
    for name in moving {
        var value = read(name)
        replaceSecret(name, value, sync: toSync, wasSynced: !toSync,
                      keep: [kSecAttrDescription as String, kSecAttrComment as String])
        value.resetBytes(in: 0..<value.count)
        moved.append(name)
        print(toSync ? "\(name): now synced through iCloud Keychain to your other Macs"
                     : "\(name): on this Mac only, deleted from iCloud Keychain")
    }
    if let a = currentAttempt { currentAttempt = AccessAttempt(event: a.event, secrets: moved, who: a.who,
                                                               program: a.program, intent: a.intent) }
    logAttempt(toSync ? "now synced" : "no longer synced")

case "get":
    guard args.count == 1 else { die("usage: touchenv get NAME", 2) }
    let asker = requester()
    let caller = callerInfo(getppid())
    beginAttempt("read", [args[0]], who: asker, intent: intent, caller: caller)
    requireIntent(intent, example: "touchenv get --intent \"<why>\" \(args[0])", who: asker)
    let who = asker.name
    switch standingRead(names: [args[0]], caller: caller, who: who, intent: intent, stillThere: callerStillThere) {
    case .secrets(let found):
        currentAttempt = nil
        FileHandle.standardOutput.write(found[args[0]]!)
        exit(0)
    case .refused(let reason):
        die("touchenv: refused: \(reason). To allow it again: touchenv grant --always --for-program PROGRAM \(args[0])")
    case .none:
        break
    }
    let syncedNow = syncedNames()
    requireStored([args[0]], among: syncedNow)
    if usePassword {
        // The prompt and everything else go to the terminal; stdout gets only the secret.
        var summary = ["touchenv: show \(who) \(args[0]) from iCloud Keychain in full?"]
        if let intent { summary.append("  Intent: \(intent)") }
        FileHandle.standardOutput.write(passwordRead(names: [args[0]], summary: summary, read: read)[args[0]]!)
        exit(0)
    }
    authenticate("Show \(who) \(strong(args[0])) from \(place([args[0]], among: syncedNow)) in full?", intent: intent,
                 reason: "show \(who) the secret \(args[0]) in full", asker: asker)
    let value = read(args[0])
    logAttempt(ReadOutcome.touchID)
    FileHandle.standardOutput.write(value)

case "rm":
    guard args.count == 1 else { die("usage: touchenv rm NAME", 2) }
    let asker = requester()
    beginAttempt("rm", [args[0]], who: asker, intent: intent)
    requireIntent(intent, example: "touchenv rm --intent \"<why>\" \(args[0])", who: asker)
    let who = asker.name
    let syncedNow = syncedNames()
    requireStored([args[0]], among: syncedNow)
    authenticate("Allow \(who) to delete \(strong(args[0])) from \(place([args[0]], among: syncedNow))?", intent: intent,
                 reason: "let \(who) delete the secret \(args[0])", asker: asker)
    let status = SecItemDelete(query(args[0]) as CFDictionary)
    if status == errSecItemNotFound {
        endAttempt(ReadOutcome.refused, note: "no secret named \(args[0])", message: "touchenv: no secret named \(args[0])")
    }
    if status != errSecSuccess { endAttempt(ReadOutcome.failed, note: "keychain error \(status)", message: "touchenv: keychain error \(status)") }
    logAttempt("deleted")
    let copies = standingSecretChanged(args[0], to: nil, who: who)
    print("deleted \(args[0])" + (copies > 0 ? "; \(copies) standing grant\(copies == 1 ? "" : "s") no longer read\(copies == 1 ? "s" : "") it" : ""))

case "ls":
    requireIntent(intent, example: "touchenv ls --intent \"<why>\"")
    let who = requester().name
    authenticate("Allow \(who) to see the names of your secrets?", intent: intent, reason: "show \(who) the names of your secrets")
    items().sorted { $0.key < $1.key }.forEach { print($0.value ? "\($0.key) (iCloud)" : $0.key) }

case "run":
    guard let split = args.firstIndex(of: "--"), split > 0, split < args.count - 1 else {
        die("usage: touchenv run NAME[:file] ... -- command args...", 2)
    }
    let specs = args[..<split].map { spec -> (name: String, file: Bool) in
        let parts = spec.split(separator: ":", maxSplits: 1).map(String.init)
        guard validName(parts[0]), parts.count == 1 || parts[1] == "file" else { die("touchenv: bad spec \(spec)", 2) }
        return (parts[0], parts.count == 2)
    }
    let argv = Array(args[(split + 1)...])
    if specs.contains(where: \.file) { sweepStaleTempDirs() }
    // Who asks and who ran touchenv, looked up once for the log, the checks and the prompt.
    let asker = requester()
    let caller = callerInfo(getppid())
    beginAttempt("read", specs.map(\.name), who: asker, intent: intent, caller: caller)
    requireIntent(intent, example: "touchenv run --intent \"<why>\" \(args[..<split].joined(separator: " ")) -- \(shortCommand(argv))",
                  who: asker)
    let names = specs.map(\.name).joined(separator: ", ")
    let who = asker.name
    let wanted = specs.map(\.name)
    signal(SIGPIPE, SIG_IGN)
    var secrets: [String: Data] = [:]
    // A standing grant for the program that ran touchenv.
    switch standingRead(names: wanted, caller: caller, who: who, intent: intent, stillThere: callerStillThere) {
    case .secrets(let found):
        currentAttempt = nil
        secrets = found
    case .refused(let reason):
        die("touchenv: refused: \(reason). To allow it again: touchenv grant --always --for-program PROGRAM \(wanted.joined(separator: " "))")
    case .none:
        break
    }
    // A "Don't ask again for 5 minutes" approval or a grant, if one covers this requester and every secret asked for.
    if secrets.isEmpty, let reply = askAgent(["op": "get", "names": wanted, "intent": intent ?? NSNull()]),
       reply["ok"] as? Bool == true, let encoded = reply["secrets"] as? [String: String] {
        for (name, value) in encoded { secrets[name] = Data(base64Encoded: value) }
        if wanted.allSatisfy({ secrets[$0] != nil }) {
            let via = reply["via"] as? String
            logAttempt(via == "grant" ? ReadOutcome.grant : via == "5-minute" ? ReadOutcome.fiveMinute : "5-minute-or-grant")
        }
    }
    var syncedNow: Set<String> = []
    if !wanted.allSatisfy({ secrets[$0] != nil }) {
        // A typo costs no touch: every name must be stored before anything asks.
        syncedNow = syncedNames()
        requireStored(wanted.filter { secrets[$0] == nil }, among: syncedNow)
    }
    if !wanted.allSatisfy({ secrets[$0] != nil }) && usePassword {
        // No "Don't ask again for 5 minutes" from a password: each --password run asks; grant --password covers a while.
        var summary = ["touchenv: give \(who) \(names) from iCloud Keychain for the command: \(shortCommand(argv))?"]
        if let intent { summary.append("  Intent: \(intent)") }
        secrets = passwordRead(names: wanted, summary: summary, read: read)
    }
    if !wanted.allSatisfy({ secrets[$0] != nil }) {
        // The whole command, cleaned; a very long one keeps its head and its end (where a payload would be).
        let keep = authenticate("Allow \(who) to read \(strong(wanted)) from \(place(wanted, among: syncedNow))?", intent: intent,
                                detail: elided(commandText(argv), limit: 4000),
                                reason: "give \(who) the secret\(specs.count > 1 ? "s" : "") \(names) for the command: \(shortCommand(argv))",
                                offerSession: true, asker: asker)
        for name in wanted where secrets[name] == nil { secrets[name] = read(name) }
        logAttempt(ReadOutcome.touchID, note: keep ? "\"Don't ask again for 5 minutes\" ticked" : "")
        if keep {
            let kept = startAgent() ? askAgent(["op": "grant", "secrets": secrets.mapValues { $0.base64EncodedString() }]) : nil
            if kept?["ok"] as? Bool != true {
                let why = asker.pid > 1 ? "" : " (touchenv can't tell which app is asking, so there is nothing to keep it for)"
                FileHandle.standardError.write("touchenv: couldn't keep the approval\(why); next time asks again\n".data(using: .utf8)!)
            }
        }
    }

    // Every check before any file is written: nothing to leave behind on a refusal.
    var env = ProcessInfo.processInfo.environment
    for spec in specs where !spec.file {
        guard let value = String(data: secrets[spec.name]!, encoding: .utf8) else {
            die("touchenv: \(spec.name) is not text; use \(spec.name):file")
        }
        env[spec.name] = value
    }
    var tempDir: String?
    let fileSpecs = specs.filter(\.file)
    if !fileSpecs.isEmpty {
        let dir = FileManager.default.temporaryDirectory.path + "/" + tempDirName() + UUID().uuidString
        registerTemp(folder: dir, files: fileSpecs.map { dir + "/" + $0.name })
        // From here a signal deletes the files: before the command starts, at once; after, once it has ended.
        for s in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] { signal(s, forwardOrCleanUp) }
        do {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { die("touchenv: \(error.localizedDescription)") }
        tempDir = dir
        for spec in fileSpecs {
            let path = dir + "/" + spec.name
            guard FileManager.default.createFile(atPath: path, contents: secrets[spec.name]!,
                                                 attributes: [.posixPermissions: 0o600]) else {
                removeTempDir(dir)
                die("touchenv: can't write \(path)")
            }
            env[spec.name] = path
        }
    } else {
        for s in [SIGTERM, SIGHUP, SIGQUIT] { signal(s, forwardOrCleanUp) }
    }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = argv
    process.environment = env
    // Ctrl-C reaches the command through the terminal's process group; touchenv waits and still cleans up. A hang-up
    // (the terminal closed), TERM or QUIT sent to touchenv is passed on to the command (forwardOrCleanUp).
    signal(SIGINT, SIG_IGN)
    tempSpawning = true
    do { try process.run() } catch {
        tempSpawning = false
        if let dir = tempDir { removeTempDir(dir) }
        die("touchenv: \(error.localizedDescription)")
    }
    tempChild = process.processIdentifier
    tempSpawning = false
    if tempPendingSignal != 0 { kill(tempChild, tempPendingSignal) }
    process.waitUntilExit()
    tempChild = 0
    if let dir = tempDir { removeTempDir(dir) }
    exit(process.terminationReason == .uncaughtSignal ? 128 + process.terminationStatus : process.terminationStatus)

case "grant" where listGrants:
    guard args.isEmpty, !always, forProgram == nil, revokeProgram == nil, !revokeAll else { die(grantUsage, 2) }
    let standing = standingStore.list()
    if standing.isEmpty { print("No standing grants.") }
    else {
        print("Standing grants (touchenv grant --revoke PROGRAM ends one; touchenv lock --all ends all):")
        for grant in standing { describeStanding(grant).forEach { print($0) } }
    }
    if let reply = askAgent(["op": "list"]), let on = reply["on"] as? [[String: Any]], !on.isEmpty {
        print("Timed grants and 5-minute approvals (touchenv lock ends them):")
        for item in on {
            let names = (item["names"] as? [String] ?? []).joined(separator: ", ")
            let left = clock(item["left"] as? Int ?? 0)
            if item["kind"] as? String == "grant" {
                print("  \(item["who"] as? String ?? "?") and what it runs: \(names) · \(times(item["uses"] as? Int ?? 0)), \(left) left")
            } else if item["kind"] as? String == "5-minute-sign" {
                print("  \(item["who"] as? String ?? "?"): \(names) · 5-minute approval for SSH signatures only, \(left) left")
            } else {
                print("  \(item["who"] as? String ?? "?"): \(names) · 5-minute approval, \(left) left")
            }
        }
    } else {
        print("No timed grants or 5-minute approvals.")
    }

case "grant" where revokeProgram != nil || revokeAll:
    guard args.isEmpty, !always, forProgram == nil, !(revokeAll && revokeProgram != nil) else { die(grantUsage, 2) }
    let ended = revokeStanding(revokeProgram, who: requester().name, how: revokeAll ? "touchenv grant --revoke-all" : "touchenv grant --revoke")
    if ended.isEmpty {
        if revokeAll { print("No standing grants.") } else { die("touchenv: no standing grant for \(revokeProgram!) (touchenv grant --list)") }
    }
    for grant in ended { print("ended the standing grant for \(tilde(grant.program)) (\(grant.names.joined(separator: ", ")))") }

case "grant" where always || forProgram != nil:
    guard always, let programArgument = forProgram, !args.isEmpty, args.allSatisfy(validName) else { die(grantUsage, 2) }
    var wanted: [String] = []
    for name in args where !wanted.contains(name) { wanted.append(name) }
    var grant: StandingGrant
    switch identifyProgram(programArgument) {
    case .success(let found): grant = found
    case .failure(let problem): die("touchenv: no standing grant: \(problem)")
    }
    let list = wanted.joined(separator: ", ")
    var example = "touchenv grant --intent \"<why>\" --always --for-program \(shellQuoted(programArgument))"
    if grantLength != nil { example += " --for \(grantLengthText)" }
    if grantUses != nil { example += " --uses \(grantUsesText)" }
    let asker = requester()
    currentAttempt = AccessAttempt(event: "grant", secrets: wanted, who: asker.name, program: grant.program, intent: intent ?? "")
    requireIntent(intent, example: example + " \(wanted.joined(separator: " "))", who: asker)
    let syncedNow = syncedNames()
    requireStored(wanted, among: syncedNow)
    var limits: [String] = []
    if let length = grantLength { limits.append("for \(Int(length / 86400) >= 2 ? "\(Int(length / 86400)) days" : spokenLength(length))") }
    if let uses = grantUses { limits.append("up to \(times(uses))") }
    let limitText = limits.isEmpty ? "from now on, until you revoke it" : limits.joined(separator: ", ")
    let identity = grant.kind == "script"
        ? "Script \(grant.program)\nSHA-256 \(grant.sha256 ?? "")\nIf the script changes, the grant stops working."
        : "Signed program \(grant.program)\nSigner: \(grant.signer ?? "?")\nRequirement: \(grant.requirement ?? "")"
    // A program that runs any code it is handed (python, node, a shell…) passes the secrets to every script it runs.
    let runsAnything = grant.kind == "signed" && runsAnyCode(grant.program)
    let programName = URL(fileURLWithPath: grant.program).lastPathComponent
    if runsAnything {
        FileHandle.standardError.write("""
            touchenv: warning: \(programName) runs whatever script or code it is given, so this grant reaches every \
            script it runs, not one tool. Prefer a grant to a shell script (bound to its contents) or to a signed \
            program that uses the secret itself.\n
            """.data(using: .utf8)!)
    }
    let question = "Allow \(strong(tilde(grant.program))) to read \(strong(wanted)) from \(place(wanted, among: syncedNow)) without asking, "
        + "\(limitText)? Also while the Mac is locked. Any program running as you could start it and get them through it."
        + (runsAnything ? " Warning: \(programName) runs any script it is given, so every script it runs gets them." : "")
    if usePassword {
        var summary = ["touchenv: " + question.filter { $0 != "\u{1}" && $0 != "\u{2}" }]
        if let intent { summary.append("  Intent: \(intent)") }
        summary += identity.split(separator: "\n").map { "  " + $0 }
        approveWithPassword(names: wanted, summary: summary)
    } else {
        authenticate(question, intent: intent, detail: identity,
                     reason: "let \(tilde(grant.program)) read \(list) without asking, \(limitText)", asker: asker)
    }
    var values: [String: Data] = [:]
    for name in wanted { values[name] = read(name) }
    let now = Date()
    grant.names = wanted
    grant.created = now
    grant.expires = grantLength.map { now.addingTimeInterval($0) }
    grant.usesLeft = grantUses
    grant.madeBy = asker.name
    let replaced = standingStore.list().first { $0.program == grant.program }
    let status = standingStore.put(grant, values: values)
    guard status == errSecSuccess else {
        endAttempt(ReadOutcome.failed, note: "keychain error \(status)", message: "touchenv: keychain error \(status); no standing grant made")
    }
    logAttempt("standing", note: [usePassword ? "approved with the Mac password typed in the terminal" : nil,
                                  limits.isEmpty ? "no limit" : limits.joined(separator: ", "),
                                  grant.kind == "script" ? "sha256 \(grant.sha256 ?? "")" : "signer \(grant.signer ?? "")",
                                  runsAnything ? "warned: \(programName) runs any script it is given" : nil,
                                  replaced.map { "replaces the grant for \($0.names.joined(separator: ","))" }]
                                  .compactMap { $0 }.joined(separator: "; "))
    print("""
        \(tilde(grant.program)) can now read \(list) with touchenv get or run without asking, \(limitText), also while the
        Mac is locked. Each read is logged (touchenv log). touchenv grant --revoke \(shellPath(grant.program)) ends it.
        \(grant.kind == "script" ? "Any change to the script ends it too: make the grant again after editing it." : "")
        """.trimmingCharacters(in: .whitespacesAndNewlines))

case "grant":
    guard let length = grantLength, let uses = grantUses, !args.isEmpty, args.allSatisfy(validName) else {
        die("usage: touchenv grant --for 8h --uses 20 NAME [NAME2 ...]  (both limits are required; 24h at most)", 2)
    }
    var wanted: [String] = []
    for name in args where !wanted.contains(name) { wanted.append(name) }
    let list = wanted.joined(separator: ", ")
    let who = requester()
    currentAttempt = AccessAttempt(event: "grant", secrets: wanted, who: who.name, program: callingProgram(who), intent: intent ?? "")
    requireIntent(intent, example: "touchenv grant --intent \"<why>\" --for \(grantLengthText) --uses \(uses) \(wanted.joined(separator: " "))")
    // The grant covers the requester and what it runs, so there must be one to name.
    guard who.pid > 1 else { die("touchenv: can't tell which app is asking, so there is nothing to grant to") }
    for name in wanted where synced(name) == nil { endAttempt(ReadOutcome.refused, note: "no secret named \(name)", message: "touchenv: no secret named \(name)") }
    let limits = "for \(spokenLength(length)), up to \(times(uses))"
    if usePassword {
        var summary = ["touchenv: allow \(who.name) and what it runs to read \(list) from iCloud Keychain without asking, "
                       + "\(limits)? It stays on while the Mac is locked."]
        if let intent { summary.append("  Intent: \(intent)") }
        approveWithPassword(names: wanted, summary: summary)
    } else {
        authenticate("Allow \(who.name) and what it runs to read \(strong(wanted)) from \(place(wanted)) without asking, \(limits)? "
                     + "It stays on while the Mac is locked.", intent: intent,
                     reason: "let \(who.name) and what it runs read \(list) without asking, \(limits), also while the Mac is locked")
    }
    var secrets: [String: String] = [:]
    for name in wanted { secrets[name] = read(name).base64EncodedString() }
    signal(SIGPIPE, SIG_IGN)
    guard startAgent(), let reply = askAgent(["op": "allow", "secrets": secrets, "seconds": length, "uses": uses]),
          reply["ok"] as? Bool == true else {
        endAttempt(ReadOutcome.failed, note: "couldn't start the grant", message: "touchenv: couldn't start the grant; nothing was allowed")
    }
    logAttempt("timed", note: "\(limits)" + (usePassword ? "; approved with the Mac password typed in the terminal" : ""))
    let until = DateFormatter.localizedString(from: Date().addingTimeInterval(length), dateStyle: .none, timeStyle: .short)
    print("\(reply["who"] as? String ?? who.name) and what it runs can read \(list) with touchenv run without asking: "
          + "\(times(uses)), until \(until), also while the Mac is locked. touchenv lock ends it.")

case "lock":
    guard args.isEmpty else { die("usage: touchenv lock [--all]", 2) }
    let who = requester().name
    if let reply = askAgent(["op": "lock"]) {
        for ended in reply["ended"] as? [[String: Any]] ?? [] {
            logAccess(AccessEntry(event: "revoke", secrets: ended["names"] as? [String] ?? [], outcome: "lock",
                                  who: ended["who"] as? String ?? "", note: "timed grant ended by touchenv lock, asked by \(who)"))
        }
        print("locked: every 5-minute approval and timed grant ended")
    } else {
        print("no 5-minute approval or timed grant to lock")
    }
    if let standing = lockStanding(all: lockAll, who: who) { print(standing) }

case "export":
    guard let recipientArgument, args.allSatisfy(validName) else {
        die("usage: touchenv export --to tenv1:… [NAME ...] > keys.tenv  (tenv1:… comes from touchenv import --begin on the new Mac)", 2)
    }
    guard let recipient = parseRecipient(recipientArgument) else {
        die("touchenv: \(recipientArgument) is not a tenv1:… key from touchenv import --begin", 2)
    }
    if isatty(1) != 0 { die("touchenv: send it to a file: touchenv export --to … > keys.tenv", 2) }
    requireIntent(intent, example: "touchenv export --intent \"<why>\" --to tenv1:… > keys.tenv")
    let code = checkCode(recipient)
    let who = requester().name
    let what = args.isEmpty ? "all your secrets" : args.joined(separator: ", ")
    // Never through a 5-minute approval: every export asks.
    authenticate("Allow \(who) to export \(args.isEmpty ? what : strong(args)) to the Mac showing \(strong(code))? Only if your new Mac shows that code.",
                 intent: intent, detail: shortCommand(CommandLine.arguments),
                 reason: "let \(who) export \(what) to the Mac showing \(code)")
    let all = items()
    let names = args.isEmpty ? all.keys.sorted() : args
    if names.isEmpty { die("touchenv: no secrets to export") }
    var entries: [[String: Any]] = []
    for name in names {
        guard let isSynced = all[name] else { die("touchenv: no secret named \(name)") }
        entries.append(["name": name, "sync": isSynced, "data": read(name).base64EncodedString()])
    }
    let payload = try! JSONSerialization.data(withJSONObject: ["from": Host.current().localizedName ?? "another Mac",
                                                               "secrets": entries])
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let header = fileMagic + recipient.compressedRepresentation + ephemeral.publicKey.x963Representation
    do {
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let box = try AES.GCM.seal(payload, using: transferKey(secret, header: header), authenticating: header)
        FileHandle.standardOutput.write(header + box.combined!)
    } catch { die("touchenv: \(error.localizedDescription)") }
    let count = "\(names.count) secret\(names.count == 1 ? "" : "s")"
    logAccess(AccessEntry(event: "export", secrets: names, outcome: "done", who: who, program: callingProgram(requester()),
                          intent: intent ?? "", note: "for the Mac showing \(code)"))
    FileHandle.standardError.write("""
        exported \(count) (\(names.joined(separator: ", "))) for the Mac showing \(code).
        Copy the file there and run: touchenv import <file>. Then delete the file here too.

        """.data(using: .utf8)!)

case "import":
    if begin {
        guard args.isEmpty else { die("usage: touchenv import --begin", 2) }
        let key = newReceivingKey()
        print("""
            Ready for one import, for the next hour. On the old Mac, run:

              touchenv export --to \(recipientText(key.publicKey)) > keys.tenv

            Approve there only if its Touch ID prompt shows \(checkCode(key.publicKey)).
            Then bring keys.tenv here and run: touchenv import keys.tenv
            """)
        exit(0)
    }
    guard args.count == 1 else { die("usage: touchenv import --begin · touchenv import [--replace] [--local] FILE", 2) }
    let path = args[0]
    requireIntent(intent, example: "touchenv import --intent \"<why>\" \(path)")
    guard let file = FileManager.default.contents(atPath: path) else { die("touchenv: can't read \(path)") }
    guard file.count > headerLength, file.prefix(fileMagic.count) == fileMagic else {
        die("touchenv: \(path) is not a file from touchenv export")
    }
    let header = file.subdata(in: 0..<headerLength)
    let recipientData = file.subdata(in: fileMagic.count..<fileMagic.count + 33)
    guard let waiting = waitingReceivingKey() else {
        die("touchenv: no import is waiting on this Mac: run touchenv import --begin, then export again with the new tenv1:…")
    }
    let key = waiting.key
    if Date().timeIntervalSince(waiting.created) > importLifetime {
        SecItemDelete(receivingQuery() as CFDictionary)
        die("touchenv: the import waiting here expired (an hour): run touchenv import --begin again")
    }
    guard recipientData == key.publicKey.compressedRepresentation else {
        let other = (try? P256.KeyAgreement.PublicKey(compressedRepresentation: recipientData)).map(checkCode) ?? "?"
        die("touchenv: \(path) was made for the code \(other); the import waiting here is \(checkCode(key.publicKey))")
    }
    let payload: Data
    do {
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: file.subdata(in: fileMagic.count + 33..<headerLength))
        let secret = try key.sharedSecret(with: ephemeral)
        let box = try AES.GCM.SealedBox(combined: file.subdata(in: headerLength..<file.count))
        payload = try AES.GCM.open(box, using: transferKey(secret, header: header), authenticating: header)
    } catch { die("touchenv: \(path) can't be opened: damaged, or not made for this Mac") }
    guard let json = (try? JSONSerialization.jsonObject(with: payload)) as? [String: Any],
          let entries = json["secrets"] as? [[String: Any]] else { die("touchenv: \(path) holds no secrets") }
    let from = json["from"] as? String ?? "another Mac"
    let incoming: [(name: String, data: Data, sync: Bool)] = entries.compactMap { entry in
        guard let name = entry["name"] as? String, validName(name), let encoded = entry["data"] as? String,
              let data = Data(base64Encoded: encoded) else { return nil }
        return (name, data, !localOnly && (entry["sync"] as? Bool ?? false))
    }
    if incoming.isEmpty { die("touchenv: \(path) holds no secrets") }
    let names = incoming.map(\.name)
    let syncedNow = syncedNames()
    var existingSync: [String: Bool] = [:]
    for name in names { existingSync[name] = synced(name, among: syncedNow) }
    let existing = Set(existingSync.keys)
    let who = requester().name
    var title = "Allow \(who) to add \(strong(names)) from \(from)?"
    if !existing.isEmpty {
        let list = existing.sorted().joined(separator: ", ")
        title += replace ? " Replaces your \(list)." : " Keeps your \(list)."
    }
    authenticate(title, intent: intent, reason: "let \(who) add secrets from \(from)")
    var stored = 0
    for secret in incoming {
        if let wasSynced = existingSync[secret.name] {
            guard replace else {
                print("skipped \(secret.name): already here (touchenv import --replace to overwrite)")
                continue
            }
            // The new value goes in before the old one is deleted, and standing grants' copies follow it.
            replaceSecret(secret.name, secret.data, sync: secret.sync, wasSynced: wasSynced)
            let copies = standingSecretChanged(secret.name, to: secret.data, who: who)
            if copies > 0 { print("updated the copy \(copies) standing grant\(copies == 1 ? "" : "s") hold\(copies == 1 ? "s" : "") of \(secret.name)") }
        } else {
            add(secret.name, secret.data, sync: secret.sync)
        }
        stored += 1
        print("stored \(secret.name) (\(secret.data.count) bytes)\(secret.sync ? ", synced through iCloud Keychain" : "")")
    }
    logAccess(AccessEntry(event: "import", secrets: incoming.map(\.name), outcome: "done", who: who,
                          program: callingProgram(requester()), intent: intent ?? "", note: "\(stored) stored, from \(from)"))
    // One import per receiving key, and the file has done its job.
    SecItemDelete(receivingQuery() as CFDictionary)
    do {
        try FileManager.default.removeItem(atPath: path)
        print("deleted \(path)")
    } catch {
        print("couldn't delete \(path) (\(error.localizedDescription)): delete it yourself")
    }
    print("\(stored) secret\(stored == 1 ? "" : "s") from \(from). Now delete keys.tenv on \(from) too, and empty its Trash.")

case "log":
    guard args.allSatisfy(validName) else { die(logUsage, 2) }
    let now = Date()
    for line in accessReport(readAccessLog(), since: logSince.map { now.addingTimeInterval(-$0) }, names: args, summary: logSummary) {
        print(line)
    }

case "agent":
    Agent().run()

case "ssh":
    sshCommand(args, intent: intent)

case "help", "-h", "--help":
    print(usage)

case "version", "--version":
    print(version)

default:
    die("touchenv: unknown command \(command)", 2)
}
#endif
