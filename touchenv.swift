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
//
// Items are generic passwords (service "touchenv") in the Data Protection keychain, in the keychain access group
// the signed touchenv.app holds (its only keychain-access-groups entitlement), with a userPresence access control:
// macOS itself asks for Touch ID (or the Mac password) on every read, this device only, never synced.
// Synced items (set --sync) can't carry that access control, so iCloud Keychain will take them: only the signed app
// can read them, and touchenv asks for Touch ID itself before every read.
// The Touch ID prompt is touchenv's own window with the sensor embedded (LAAuthenticationView): who asks (the nearest
// parent process that is not a shell), which secrets, the stated intent, and the command behind "More detail".
// Without Touch ID, or on "Use Password…", the macOS dialog asks instead.
// Build and sign with ./build.sh.

import AppKit
import Darwin
import Foundation
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import Security

let version = "1.2.1"
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

func parentPid(_ pid: pid_t) -> pid_t? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
    return pid_t(info.pbi_ppid)
}

/// The nearest ancestor that is not a shell or a wrapper: the agent, or the terminal when you typed it yourself.
func requester() -> String {
    let passThrough: Set<String> = ["sh", "zsh", "bash", "fish", "dash", "ksh", "tcsh", "env", "sudo", "login",
                                    "nohup", "time", "timeout", "xargs", "make", "script", "tmux", "screen"]
    let known = ["claude": "Claude Code", "codex": "Codex", "cursor-agent": "Cursor", "Cursor": "Cursor",
                 "gemini": "Gemini CLI", "aider": "aider", "goose": "Goose", "opencode": "opencode",
                 "ghostty": "Ghostty", "Terminal": "Terminal", "iTerm2": "iTerm", "Code": "VS Code",
                 "Code Helper": "VS Code", "WezTerm": "WezTerm", "wezterm-gui": "WezTerm", "kitty": "kitty",
                 "alacritty": "Alacritty", "warp": "Warp", "stable": "Warp"]
    var pid = getppid()
    for _ in 0..<32 {
        guard pid > 1, let name = executableName(pid) else { break }
        if !passThrough.contains(name.trimmingCharacters(in: CharacterSet(charactersIn: "-"))) {
            return known[name] ?? name
        }
        guard let parent = parentPid(pid) else { break }
        pid = parent
    }
    return "a process"
}

func shortCommand(_ argv: [String]) -> String {
    let joined = argv.map { $0.contains(" ") ? "'\($0)'" : $0 }.joined(separator: " ")
    return joined.count > 160 ? String(joined.prefix(157)) + "…" : joined
}

// MARK: Prompt

enum Outcome { case approved, denied, password }

/// touchenv's own window: the question, the intent, the command behind "More detail", and the Touch ID sensor
/// embedded, so macOS shows no dialog of its own. There is no Allow button: only a finger approves.
final class Prompt: NSObject {
    let panel = NSPanel(contentRect: .zero, styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
    let detailToggle = NSButton(title: "More detail ›", target: nil, action: nil)
    var detailField: NSTextField?
    var chosen: Outcome?
    var outcome = Outcome.denied

    init(title: String, intent: String?, detail: String?) {
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
        // dialog's own still icon (the Touch ID disc badged with the app icon) sits over it on an opaque cover.
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
        let badge = NSImageView(image: NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath))
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

        var views: [NSView] = [sensor, label(title, .boldSystemFont(ofSize: 13))]
        if let intent { views.append(label("Intent: \(intent)", .systemFont(ofSize: 13))) }
        if let detail {
            detailToggle.target = self
            detailToggle.action = #selector(toggleDetail)
            detailToggle.isBordered = false
            detailToggle.refusesFirstResponder = true
            detailToggle.contentTintColor = .linkColor
            detailToggle.font = .systemFont(ofSize: 11)
            let field = label(detail, .monospacedSystemFont(ofSize: 11, weight: .regular), .secondaryLabelColor)
            field.isSelectable = true
            field.isHidden = true
            views += [detailToggle, field]
            detailField = field
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
        panel.level = .floating
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
func authenticate(_ title: String, intent: String?, detail: String? = nil, reason: String) {
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
        switch Prompt(title: title, intent: intent, detail: detail).run(reason: reason) {
        case .approved: return
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

// MARK: Commands

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else { die(usage, 2) }
args.removeFirst()
var intent: String?
var sync = false
while let option = args.first, option.hasPrefix("--"), option != "--" {
    if option == "--sync", command == "set" {
        sync = true
        args.removeFirst()
    } else if option == "--intent", args.count > 1 {
        let text = args[1].trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "\n", with: " ")
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
        let who = requester()
        let target = sync ? "iCloud Keychain" : "your Keychain"
        authenticate("Allow \(who) to replace \(name) in \(target)?", intent: intent,
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
    let who = requester()
    authenticate("Show \(who) \(args[0]) from \(place([args[0]])) in full?", intent: intent,
                 reason: "show \(who) the secret \(args[0]) in full")
    FileHandle.standardOutput.write(read(args[0]))

case "rm":
    guard args.count == 1 else { die("usage: touchenv rm NAME", 2) }
    let who = requester()
    authenticate("Allow \(who) to delete \(args[0]) from \(place([args[0]]))?", intent: intent,
                 reason: "let \(who) delete the secret \(args[0])")
    let status = SecItemDelete(query(args[0]) as CFDictionary)
    if status != errSecSuccess { die("touchenv: keychain error \(status)") }
    print("deleted \(args[0])")

case "ls":
    let who = requester()
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
    let names = specs.map(\.name).joined(separator: ", ")
    let who = requester()
    let full = argv.map { $0.contains(" ") ? "'\($0)'" : $0 }.joined(separator: " ")
    authenticate("Allow \(who) to read \(names) from \(place(specs.map(\.name)))?", intent: intent,
                 detail: full.count > 2000 ? String(full.prefix(1999)) + "…" : full,
                 reason: "give \(who) the secret\(specs.count > 1 ? "s" : "") \(names) for the command: \(shortCommand(argv))")

    var env = ProcessInfo.processInfo.environment
    var tempDir: URL?
    for spec in specs {
        let data = read(spec.name)
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

case "help", "-h", "--help":
    print(usage)

case "version", "--version":
    print(version)

default:
    die("touchenv: unknown command \(command)", 2)
}
