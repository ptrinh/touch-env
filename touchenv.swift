// touchenv — secrets in the macOS Keychain, every read behind Touch ID (or the Mac password).
//
//   touchenv [cmd] --intent TEXT ...   one line on why, shown in the prompt (set, get, rm, run)
//   touchenv set NAME          secret from stdin (typed with no echo, or piped: touchenv set NAME < file)
//   touchenv set --sync NAME   the same, synced to your other Macs through iCloud Keychain
//   touchenv get NAME          print the secret
//   touchenv run NAME[:file] [NAME2[:file] ...] -- command args...
//                              run the command with each secret in env var NAME (one Touch ID for all);
//                              ":file" puts it in a private temp file instead and NAME holds the path,
//                              the file is removed when the command ends
//   touchenv ls                list names, "(iCloud)" after synced ones (Touch ID: macOS guards even names; no values)
//   touchenv rm NAME           delete
//   touchenv grant --for 8h --uses 20 NAME [NAME2 ...]
//                              one Touch ID now; then the app that asked, and what it runs, reads those secrets
//                              with touchenv run without asking, until the time or the uses run out
//   touchenv lock              end every approval now (5-minute ones and grants)
//   touchenv import --begin    on a new Mac: make a one-time receiving key, print it as tenv1:… and a check code
//   touchenv export --to tenv1:… [NAME ...] > keys.tenv
//                              on the old Mac: every secret (or those named) encrypted to that key, one Touch ID
//   touchenv import keys.tenv  on the new Mac: store them (--replace overwrites, --local keeps none synced),
//                              then delete keys.tenv and the receiving key
//
// Items are generic passwords (service "touchenv") in the Data Protection keychain, in the keychain access group
// the signed touchenv.app holds (its only keychain-access-groups entitlement), with a userPresence access control:
// macOS itself asks for Touch ID (or the Mac password) on every read, this device only, never synced.
// Synced items (set --sync) can't carry that access control, so iCloud Keychain will take them: only the signed app
// can read them, and touchenv asks for Touch ID itself before every read.
// The Touch ID prompt is touchenv's own window with the sensor embedded (LAAuthenticationView): who asks (the nearest
// parent process that is not a shell), which secrets, the stated intent, and the command behind "More detail".
// Without Touch ID, or on "Use Password…", the macOS dialog asks instead.
// For run, the prompt offers "Don't ask again for 5 minutes" (only there: no flag, or an agent would always pass it).
// Ticked, touchenv starts a background copy of itself (touchenv agent) that keeps those secrets in memory for 5
// minutes and hands them to later touchenv runs from the same requester (same pid and start time). Both ends check
// that the other is touchenv signed like itself. A menu bar timer shows the approval; each use flashes a notice.
// grant: the same background copy keeps the named secrets for the length given (24 hours at most) and a number of
// uses (one per touchenv run). It covers the requester of the grant command and every process below it, checked from
// the kernel's process tree, and goes on while the screen is locked. It ends at the time, at the last use, on
// touchenv lock, when that requester quits, or at logout.
// export/import: the receiving key lives in the new Mac's Secure Enclave (a keychain item, this device only, when there
// is none) and is deleted after one import or an hour. The file: "TENV" 1 | receiving key (33 bytes) | ephemeral key
// (65) | AES-GCM over JSON, key from ECDH + HKDF-SHA256, the header authenticated. Export never uses a 5-minute
// approval, and its prompt shows the receiving key's check code: approve only if the new Mac shows the same.
// Build and sign with ./build.sh.

import AppKit
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import Security

let version = "1.5.0"
let service = "touchenv"
let usage = """
touchenv \(version) — secrets in the macOS Keychain, every read behind Touch ID

  touchenv set NAME                     store a secret (typed with no echo, or piped: touchenv set NAME < file)
  touchenv set --sync NAME              the same, synced to your other Macs through iCloud Keychain
  touchenv get NAME                     print it
  touchenv run NAME[:file] ... -- CMD   run CMD with each secret in env var NAME; with :file, NAME holds
                                        the path of a private temp file, removed when CMD ends
  touchenv ls                           list names; "(iCloud)" marks synced ones
  touchenv rm NAME                      delete
  touchenv grant --for 8h --uses 20 NAME ...
                                        one Touch ID now; then this app and what it runs read those secrets
                                        with touchenv run without asking, also while the Mac is locked, until
                                        the time (24h at most) or the uses run out
  touchenv lock                         end every approval now: 5-minute ones and grants

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
func requester(from first: pid_t = getppid()) -> Requester {
    let passThrough: Set<String> = ["sh", "zsh", "bash", "fish", "dash", "ksh", "tcsh", "env", "sudo", "login",
                                    "nohup", "time", "timeout", "xargs", "make", "script", "tmux", "screen"]
    // AI agents (by executable name, not the apps of the same name): they must say why (--intent).
    let agents: Set<String> = ["claude", "codex", "cursor-agent", "gemini", "aider", "goose", "opencode"]
    let known = ["claude": "Claude Code", "codex": "Codex", "cursor-agent": "Cursor", "Cursor": "Cursor",
                 "gemini": "Gemini CLI", "aider": "aider", "goose": "Goose", "opencode": "opencode",
                 "ghostty": "Ghostty", "Terminal": "Terminal", "iTerm2": "iTerm", "Code": "VS Code",
                 "Code Helper": "VS Code", "WezTerm": "WezTerm", "wezterm-gui": "WezTerm", "kitty": "kitty",
                 "alacritty": "Alacritty", "warp": "Warp", "stable": "Warp"]
    var pid = first
    for _ in 0..<32 {
        guard pid > 1, let name = executableName(pid) else { break }
        if !passThrough.contains(name.trimmingCharacters(in: CharacterSet(charactersIn: "-"))) {
            return Requester(pid: pid, start: startTime(pid) ?? 0, name: known[name] ?? name, isAgent: agents.contains(name),
                             exec: name)
        }
        guard let parent = parentPid(pid) else { break }
        pid = parent
    }
    return Requester(pid: 0, start: 0, name: "a process")
}

/// The badge on the Touch ID disc: the icon of whoever asks. For an AI agent that runs in a terminal, its maker's
/// app when this Mac has it (Claude Code shows Claude.app's icon, Codex shows Codex.app's or ChatGPT.app's);
/// otherwise the app the request came from: the AI app itself, the editor, or the terminal. Icons are read from
/// the apps installed here; touchenv ships no one's logo. Like the name in the prompt, it tells you who asks; it
/// proves nothing a program could not fake.
func requesterIcon() -> NSImage {
    let who = requester()
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

func shortCommand(_ argv: [String]) -> String {
    let joined = argv.map { $0.contains(" ") ? "'\($0)'" : $0 }.joined(separator: " ")
    return joined.count > 160 ? String(joined.prefix(157)) + "…" : joined
}

/// An AI agent must give a reason (--intent) for anything that asks for Touch ID or reads a secret, so the prompt
/// always says why. Refused before any prompt: the agent reads the error and asks again with one.
func requireIntent(_ intent: String?, example: String) {
    guard intent == nil else { return }
    let who = requester()
    if who.isAgent {
        die("touchenv: \(who.name) must say why, in a few words: \(example)\n"
            + "  (--intent goes right after the command; the reason is shown in the Touch ID prompt)", 2)
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

enum Outcome { case approved, denied, password }

/// touchenv's own window: the question, the intent, the command behind "More detail", and the Touch ID sensor
/// embedded, so macOS shows no dialog of its own. There is no Allow button: only a finger approves.
final class Prompt: NSObject {
    let panel = NSPanel(contentRect: .zero, styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
    let detailToggle = NSButton(title: "More detail ›", target: nil, action: nil)
    var detailField: NSTextField?
    var sessionBox: NSButton?
    var keepFor5Minutes: Bool { sessionBox?.state == .on }
    var chosen: Outcome?
    var outcome = Outcome.denied

    init(title: String, intent: String?, detail: String?, offerSession: Bool) {
        super.init()
        // Laid out like the macOS authentication dialog: icon top left, text left aligned, buttons stacked full width.
        let width: CGFloat = 228
        func label(_ text: String, _ font: NSFont, _ color: NSColor = .labelColor) -> NSTextField {
            let field = NSTextField(wrappingLabelWithString: text)
            field.font = font
            field.textColor = color
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
        let badge = NSImageView(image: requesterIcon())
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

        let heading = label("", .systemFont(ofSize: 13))
        heading.attributedStringValue = titleText(title)
        var views: [NSView] = [sensor, heading]
        if let intent {
            let line = label("", .systemFont(ofSize: 13))
            line.attributedStringValue = titleText("\(strong("INTENT:")) \(intent)")
            views.append(line)
        }
        else if detail != nil {
            // No reason given: say so, and show the command without a click.
            views.append(label("No reason given. Check the command:", .systemFont(ofSize: 13), .systemOrange))
        }
        if let detail {
            detailToggle.target = self
            detailToggle.action = #selector(toggleDetail)
            detailToggle.isBordered = false
            detailToggle.refusesFirstResponder = true
            detailToggle.contentTintColor = .linkColor
            detailToggle.font = .systemFont(ofSize: 11)
            let field = label(detail, .monospacedSystemFont(ofSize: 11, weight: .regular), .secondaryLabelColor)
            field.isSelectable = true
            field.isHidden = intent != nil
            detailToggle.title = field.isHidden ? "More detail ›" : "Less detail ‹"
            views += [detailToggle, field]
            detailField = field
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

    @objc func toggleDetail() {
        guard let field = detailField else { return }
        field.isHidden.toggle()
        detailToggle.title = field.isHidden ? "More detail ›" : "Less detail ‹"
        let frame = panel.frame
        let size = panel.frameRect(forContentRect: NSRect(origin: .zero, size: panel.contentView!.fittingSize)).size
        panel.setFrame(NSRect(x: frame.minX, y: frame.maxY - size.height, width: size.width, height: size.height),
                       display: true, animate: true)
    }

    @objc func usePassword() { chosen = .password; context.invalidate() }
    @objc func cancel() { chosen = .denied; context.invalidate() }

    func run(reason: String) -> Outcome {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        panel.center()
        app.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                let code = (error as? LAError)?.code
                if success { self.outcome = .approved }
                else if let chosen = self.chosen { self.outcome = chosen }
                else if code == .authenticationFailed || code == .biometryLockout || code == .userFallback {
                    self.outcome = .password
                }
                self.panel.orderOut(nil)
                app.stop(nil)
                app.postEvent(NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [],
                                                 timestamp: 0, windowNumber: 0, context: nil, subtype: 0,
                                                 data1: 0, data2: 0)!, atStart: true)
            }
        }
        app.run()
        return outcome
    }
}

/// Asks with touchenv's window; falls back to the macOS dialog (with `reason`) without Touch ID or on request.
/// Returns whether "Don't ask again for 5 minutes" was ticked (offered only with `offerSession`).
@discardableResult
func authenticate(_ title: String, intent: String?, detail: String? = nil, reason: String,
                  offerSession: Bool = false) -> Bool {
    var keep = false
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
        let prompt = Prompt(title: title, intent: intent, detail: detail, offerSession: offerSession)
        let outcome = prompt.run(reason: reason)
        keep = prompt.keepFor5Minutes
        switch outcome {
        case .approved: return keep
        case .denied: die("touchenv: not approved")
        case .password: context = LAContext()
        }
    }
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        die("touchenv: cannot ask for Touch ID: \(error?.localizedDescription ?? "unknown")")
    }
    let done = DispatchSemaphore(value: 0)
    var ok = false
    let full = intent.map { "\(reason) (intent: \($0))" } ?? reason
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: full) { success, _ in
        ok = success
        done.signal()
    }
    done.wait()
    if !ok { die("touchenv: not approved") }
    return keep
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
func synced(_ name: String) -> Bool? {
    if syncedNames().contains(name) { return true }
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
func place(_ names: [String]) -> String {
    let all = syncedNames()
    let sync = Set(names.map { all.contains($0) })
    return sync == [true] ? "iCloud Keychain" : sync == [false] ? "your Keychain" : "your Keychain and iCloud Keychain"
}

func add(_ name: String, _ data: Data, sync: Bool) {
    var q = query(name)
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

func read(_ name: String) -> Data {
    var q = query(name)
    q[kSecReturnData as String] = true
    var out: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &out)
    guard status == errSecSuccess, let data = out as? Data else {
        die(status == errSecItemNotFound ? "touchenv: no secret named \(name)" : "touchenv: keychain error \(status)")
    }
    return data
}

func readStdin() -> Data {
    if isatty(0) != 0 {
        guard let line = getpass("Secret (not shown): ") else { die("touchenv: no input") }
        return Data(String(cString: line).utf8)
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

/// "8h", "30m" or "1h30m" in seconds; nil for anything else.
func parseLength(_ text: String) -> TimeInterval? {
    var total = 0, digits = "", seen = ""
    for character in text {
        if ("0"..."9").contains(character), digits.count < 5 {
            digits.append(character)
        } else if character == "h" || character == "m", !seen.contains(character), let n = Int(digits) {
            total += n * (character == "h" ? 3600 : 60)
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

/// Whether the process at the other end of the socket is touchenv, signed like this one.
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

/// One JSON message each way: write it, then close the writing half.
func sendMessage(_ fd: Int32, _ message: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }
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

func receiveMessage(_ fd: Int32) -> [String: Any]? {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 16384)
    while data.count < 4 << 20 {
        let n = read(fd, &buffer, buffer.count)
        if n <= 0 { break }
        data.append(buffer, count: n)
    }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
}

/// A connection to a running agent that is really touchenv, or nil.
func connectAgent() -> Int32? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    var address = socketAddress(agentSocketPath())
    var on: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    guard connected == 0, peerIsTouchenv(fd) else { close(fd); return nil }
    return fd
}

func askAgent(_ message: [String: Any]) -> [String: Any]? {
    guard let fd = connectAgent() else { return nil }
    defer { close(fd) }
    sendMessage(fd, message)
    return receiveMessage(fd)
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

/// The background copy: keeps approved secrets in memory, per requester, for 5 minutes or for a grant's length,
/// then exits.
final class Agent: NSObject {
    struct Approval { var start: UInt64; var who: String; var secrets: [String: Data]; var expires: Date }
    /// From touchenv grant: covers the requester (pid, start) and every process below it.
    struct Grant { var pid: pid_t; var start: UInt64; var who: String; var secrets: [String: Data]; var expires: Date; var uses: Int }
    var approvals: [pid_t: Approval] = [:]
    var grants: [Grant] = []
    var listener: DispatchSourceRead?
    var statusItem: NSStatusItem!
    var notice: NSPanel?
    let born = Date()

    func run() -> Never {
        let path = agentSocketPath()
        if let fd = connectAgent() { close(fd); exit(0) }
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
            if client >= 0 { self.handle(client); close(client) }
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

    func handle(_ fd: Int32) {
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        guard peerIsTouchenv(fd), let peer = peerPid(fd), let parent = parentPid(peer),
              let message = receiveMessage(fd), let op = message["op"] as? String else { return }
        // The agent works out the requester itself, from the kernel's process tree; it takes no one's word for it.
        let who = requester(from: parent)
        switch op {
        case "grant":
            guard who.pid > 1, let encoded = message["secrets"] as? [String: String] else { break }
            var approval = approvals[who.pid].flatMap { $0.start == who.start ? $0 : nil }
                ?? Approval(start: who.start, who: who.name, secrets: [:], expires: .distantPast)
            for (name, value) in encoded { approval.secrets[name] = Data(base64Encoded: value) }
            approval.expires = Date().addingTimeInterval(approvalLength)
            approvals[who.pid] = approval
            sendMessage(fd, ["ok": true])
            tick()
            return
        case "allow":
            guard who.pid > 1, let encoded = message["secrets"] as? [String: String], !encoded.isEmpty,
                  let seconds = message["seconds"] as? Double, seconds >= 60,
                  let uses = message["uses"] as? Int, uses >= 1 else { break }
            var secrets: [String: Data] = [:]
            for (name, value) in encoded { secrets[name] = Data(base64Encoded: value) }
            // A new grant to the same requester for the same secrets replaces the old one.
            grants.removeAll { $0.pid == who.pid && $0.start == who.start && Set($0.secrets.keys) == Set(secrets.keys) }
            grants.append(Grant(pid: who.pid, start: who.start, who: who.name, secrets: secrets,
                                expires: Date().addingTimeInterval(min(seconds, maxGrantLength)),
                                uses: min(uses, maxGrantUses)))
            sendMessage(fd, ["ok": true, "who": who.name])
            tick()
            return
        case "get":
            guard let names = message["names"] as? [String], !names.isEmpty else { break }
            let now = Date()
            let intent = message["intent"] as? String
            if let approval = approvals[who.pid], approval.start == who.start, approval.expires > now,
               names.allSatisfy({ approval.secrets[$0] != nil }) {
                var out: [String: String] = [:]
                for name in names { out[name] = approval.secrets[name]!.base64EncodedString() }
                sendMessage(fd, ["ok": true, "secrets": out])
                let left = Int(approval.expires.timeIntervalSince(now).rounded(.up))
                showNotice(who: approval.who, names: names, intent: intent, left: "approved for \(clock(left)) more")
                return
            }
            // A grant: the asking process must sit below the requester the grant was given to.
            let above = lineage(parent)
            guard let index = grants.firstIndex(where: { grant in
                grant.expires > now && grant.uses > 0 && names.allSatisfy({ grant.secrets[$0] != nil })
                    && above.contains { $0.pid == grant.pid && $0.start == grant.start }
            }) else { break }
            grants[index].uses -= 1
            let grant = grants[index]
            var out: [String: String] = [:]
            for name in names { out[name] = grant.secrets[name]!.base64EncodedString() }
            sendMessage(fd, ["ok": true, "secrets": out])
            let left = Int(grant.expires.timeIntervalSince(now).rounded(.up))
            showNotice(who: who.name, names: names, intent: intent,
                       left: grant.uses == 0 ? "that was the last use granted"
                                             : "granted for \(clock(left)) more, \(times(grant.uses)) left")
            return
        case "lock":
            approvals.removeAll()
            grants.removeAll()
            sendMessage(fd, ["ok": true])
            DispatchQueue.main.async { self.tick() }
            return
        default: break
        }
        sendMessage(fd, ["ok": false])
    }

    /// Drops what expired or whose requester ended; quits when nothing is left.
    func tick() {
        let now = Date()
        approvals = approvals.filter { pid, approval in approval.expires > now && startTime(pid) == approval.start }
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
        let menu = NSMenu()
        for approval in approvals.values.sorted(by: { $0.who < $1.who }) {
            let names = approval.secrets.keys.sorted().joined(separator: ", ")
            let item = NSMenuItem(title: "\(approval.who) can read \(names) without asking", action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        }
        for grant in grants.sorted(by: { $0.who < $1.who }) {
            let names = grant.secrets.keys.sorted().joined(separator: ", ")
            let left = clock(Int(grant.expires.timeIntervalSince(now).rounded(.up)))
            let item = NSMenuItem(title: "\(grant.who) and what it runs can read \(names) without asking: "
                                  + "\(times(grant.uses)), \(left) left", action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        }
        menu.addItem(.separator())
        let lock = NSMenuItem(title: "Lock Now", action: #selector(lockNow), keyEquivalent: "")
        lock.target = self
        menu.addItem(lock)
        statusItem.menu = menu
    }

    @objc func lockNow() {
        approvals.removeAll()
        grants.removeAll()
        tick()
    }

    /// A short notice at the top right each time an approval is used, so it never happens unseen.
    func showNotice(who: String, names: [String], intent: String?, left: String) {
        notice?.orderOut(nil)
        var lines = ["\(who) read \(names.joined(separator: ", "))"]
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

// MARK: Commands

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
        guard let length = parseLength(args[1]), length <= maxGrantLength else {
            die("touchenv: --for takes a length like 30m, 8h or 1h30m, 24h at most", 2)
        }
        grantLength = length
        grantLengthText = args[1]
        args.removeFirst(2)
    } else if option == "--uses", command == "grant", args.count > 1 {
        guard let uses = Int(args[1]), (1...maxGrantUses).contains(uses) else {
            die("touchenv: --uses takes a number from 1 to \(maxGrantUses)", 2)
        }
        grantUses = uses
        args.removeFirst(2)
    } else if option == "--intent", args.count > 1 {
        // One line, and no control characters: they could restyle the prompt (see strong).
        let text = String(String.UnicodeScalarView(args[1].replacingOccurrences(of: "\n", with: " ").unicodeScalars
            .filter { !CharacterSet.controlCharacters.contains($0) })).trimmingCharacters(in: .whitespaces)
        intent = text.isEmpty ? nil : (text.count > 200 ? String(text.prefix(199)) + "…" : text)
        args.removeFirst(2)
    } else {
        die("touchenv: unknown option \(option)", 2)
    }
}

switch command {
case "set":
    guard args.count == 1, validName(args[0]) else { die("usage: touchenv set [--sync] NAME  (NAME = env var style)", 2) }
    let name = args[0]
    let data = readStdin()
    if data.isEmpty { die("touchenv: empty secret, nothing stored") }
    if let wasSynced = synced(name) {
        requireIntent(intent, example: "touchenv set --intent \"<why>\" \(name)")
        let who = requester().name
        let target = sync ? "iCloud Keychain" : "your Keychain"
        authenticate("Allow \(who) to replace \(strong(name)) in \(target)?", intent: intent,
                     reason: "let \(who) replace the secret \(name) in \(target)")
        if wasSynced == sync {
            let status = SecItemUpdate(query(name) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            if status != errSecSuccess { die("touchenv: keychain error \(status)") }
        } else {
            // Syncing on or off changes the item's protection, which an update can't: store it anew.
            let status = SecItemDelete(query(name) as CFDictionary)
            if status != errSecSuccess { die("touchenv: keychain error \(status)") }
            add(name, data, sync: sync)
        }
    } else {
        add(name, data, sync: sync)
    }
    print("stored \(name) (\(data.count) bytes)\(sync ? ", synced through iCloud Keychain" : "")")

case "get":
    guard args.count == 1 else { die("usage: touchenv get NAME", 2) }
    requireIntent(intent, example: "touchenv get --intent \"<why>\" \(args[0])")
    let who = requester().name
    authenticate("Show \(who) \(strong(args[0])) from \(place([args[0]])) in full?", intent: intent,
                 reason: "show \(who) the secret \(args[0]) in full")
    FileHandle.standardOutput.write(read(args[0]))

case "rm":
    guard args.count == 1 else { die("usage: touchenv rm NAME", 2) }
    requireIntent(intent, example: "touchenv rm --intent \"<why>\" \(args[0])")
    let who = requester().name
    authenticate("Allow \(who) to delete \(strong(args[0])) from \(place([args[0]]))?", intent: intent,
                 reason: "let \(who) delete the secret \(args[0])")
    let status = SecItemDelete(query(args[0]) as CFDictionary)
    if status != errSecSuccess { die("touchenv: keychain error \(status)") }
    print("deleted \(args[0])")

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
    requireIntent(intent, example: "touchenv run --intent \"<why>\" \(args[..<split].joined(separator: " ")) -- \(shortCommand(argv))")
    let names = specs.map(\.name).joined(separator: ", ")
    let who = requester().name
    let wanted = specs.map(\.name)
    signal(SIGPIPE, SIG_IGN)
    var secrets: [String: Data] = [:]
    // A "Don't ask again for 5 minutes" approval or a grant, if one covers this requester and every secret asked for.
    if let reply = askAgent(["op": "get", "names": wanted, "intent": intent ?? NSNull()]), reply["ok"] as? Bool == true,
       let encoded = reply["secrets"] as? [String: String] {
        for (name, value) in encoded { secrets[name] = Data(base64Encoded: value) }
    }
    if !wanted.allSatisfy({ secrets[$0] != nil }) {
        let full = argv.map { $0.contains(" ") ? "'\($0)'" : $0 }.joined(separator: " ")
        let keep = authenticate("Allow \(who) to read \(strong(wanted)) from \(place(wanted))?", intent: intent,
                                detail: full.count > 2000 ? String(full.prefix(1999)) + "…" : full,
                                reason: "give \(who) the secret\(specs.count > 1 ? "s" : "") \(names) for the command: \(shortCommand(argv))",
                                offerSession: true)
        for name in wanted where secrets[name] == nil { secrets[name] = read(name) }
        if keep {
            if !startAgent() || askAgent(["op": "grant", "secrets": secrets.mapValues { $0.base64EncodedString() }]) == nil {
                FileHandle.standardError.write("touchenv: couldn't keep the approval; next time asks again\n".data(using: .utf8)!)
            }
        }
    }

    var env = ProcessInfo.processInfo.environment
    var tempDir: URL?
    for spec in specs {
        let data = secrets[spec.name]!
        if spec.file {
            if tempDir == nil {
                let dir = FileManager.default.temporaryDirectory.appendingPathComponent("touchenv-\(UUID().uuidString)")
                do {
                    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false,
                                                            attributes: [.posixPermissions: 0o700])
                } catch { die("touchenv: \(error.localizedDescription)") }
                tempDir = dir
            }
            let path = tempDir!.appendingPathComponent(spec.name)
            FileManager.default.createFile(atPath: path.path, contents: data, attributes: [.posixPermissions: 0o600])
            env[spec.name] = path.path
        } else {
            guard let value = String(data: data, encoding: .utf8) else {
                die("touchenv: \(spec.name) is not text; use \(spec.name):file")
            }
            env[spec.name] = value
        }
    }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = argv
    process.environment = env
    // Ctrl-C reaches the child through the terminal's process group; touchenv waits and still cleans up.
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM) { _ in }
    do { try process.run() } catch { die("touchenv: \(error.localizedDescription)") }
    process.waitUntilExit()
    if let dir = tempDir { try? FileManager.default.removeItem(at: dir) }
    exit(process.terminationReason == .uncaughtSignal ? 128 + process.terminationStatus : process.terminationStatus)

case "grant":
    guard let length = grantLength, let uses = grantUses, !args.isEmpty, args.allSatisfy(validName) else {
        die("usage: touchenv grant --for 8h --uses 20 NAME [NAME2 ...]  (both limits are required; 24h at most)", 2)
    }
    var wanted: [String] = []
    for name in args where !wanted.contains(name) { wanted.append(name) }
    let list = wanted.joined(separator: ", ")
    requireIntent(intent, example: "touchenv grant --intent \"<why>\" --for \(grantLengthText) --uses \(uses) \(wanted.joined(separator: " "))")
    let who = requester()
    // The grant covers the requester and what it runs, so there must be one to name.
    guard who.pid > 1 else { die("touchenv: can't tell which app is asking, so there is nothing to grant to") }
    for name in wanted where synced(name) == nil { die("touchenv: no secret named \(name)") }
    let limits = "for \(spokenLength(length)), up to \(times(uses))"
    authenticate("Allow \(who.name) and what it runs to read \(strong(wanted)) from \(place(wanted)) without asking, \(limits)? "
                 + "It stays on while the Mac is locked.", intent: intent,
                 reason: "let \(who.name) and what it runs read \(list) without asking, \(limits), also while the Mac is locked")
    var secrets: [String: String] = [:]
    for name in wanted { secrets[name] = read(name).base64EncodedString() }
    signal(SIGPIPE, SIG_IGN)
    guard startAgent(), let reply = askAgent(["op": "allow", "secrets": secrets, "seconds": length, "uses": uses]),
          reply["ok"] as? Bool == true else { die("touchenv: couldn't start the grant; nothing was allowed") }
    let until = DateFormatter.localizedString(from: Date().addingTimeInterval(length), dateStyle: .none, timeStyle: .short)
    print("\(reply["who"] as? String ?? who.name) and what it runs can read \(list) with touchenv run without asking: "
          + "\(times(uses)), until \(until), also while the Mac is locked. touchenv lock ends it.")

case "lock":
    if askAgent(["op": "lock"]) != nil { print("locked: every approval and grant ended") }
    else { print("nothing to lock") }

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
    let existing = Set(names.filter { synced($0) != nil })
    let who = requester().name
    var title = "Allow \(who) to add \(strong(names)) from \(from)?"
    if !existing.isEmpty {
        let list = existing.sorted().joined(separator: ", ")
        title += replace ? " Replaces your \(list)." : " Keeps your \(list)."
    }
    authenticate(title, intent: intent, reason: "let \(who) add secrets from \(from)")
    var stored = 0
    for secret in incoming {
        if existing.contains(secret.name) {
            guard replace else {
                print("skipped \(secret.name): already here (touchenv import --replace to overwrite)")
                continue
            }
            let status = SecItemDelete(query(secret.name) as CFDictionary)
            if status != errSecSuccess { die("touchenv: keychain error \(status)") }
        }
        add(secret.name, secret.data, sync: secret.sync)
        stored += 1
        print("stored \(secret.name) (\(secret.data.count) bytes)\(secret.sync ? ", synced through iCloud Keychain" : "")")
    }
    // One import per receiving key, and the file has done its job.
    SecItemDelete(receivingQuery() as CFDictionary)
    do {
        try FileManager.default.removeItem(atPath: path)
        print("deleted \(path)")
    } catch {
        print("couldn't delete \(path) (\(error.localizedDescription)): delete it yourself")
    }
    print("\(stored) secret\(stored == 1 ? "" : "s") from \(from). Now delete keys.tenv on \(from) too, and empty its Trash.")

case "agent":
    Agent().run()

case "help", "-h", "--help":
    print(usage)

case "version", "--version":
    print(version)

default:
    die("touchenv: unknown command \(command)", 2)
}
