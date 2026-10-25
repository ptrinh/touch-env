// touchenv — secrets in the macOS Keychain, every read behind Touch ID (or the Mac password).
//
//   touchenv set NAME          secret from stdin (typed with no echo, or piped: touchenv set NAME < file)
//   touchenv get NAME          print the secret
//   touchenv run NAME[:file] [NAME2[:file] ...] -- command args...
//                              run the command with each secret in env var NAME (one Touch ID for all);
//                              ":file" puts it in a private temp file instead and NAME holds the path,
//                              the file is removed when the command ends
//   touchenv ls                list names (no Touch ID, no values)
//   touchenv rm NAME           delete
//
// Items are generic passwords (service "touchenv") in the Data Protection keychain, in the keychain access group
// the signed touchenv.app holds (its only keychain-access-groups entitlement), with a userPresence access control:
// macOS itself asks for Touch ID (or the Mac password) on every read, this device only, never synced.
// The Touch ID prompt names who asks (the nearest parent process that is not a shell), the secrets and the command.
// Build and sign with ./build.sh.

import Darwin
import Foundation
import LocalAuthentication
import Security

let version = "1.0.1"
let service = "touchenv"
let usage = """
touchenv \(version) — secrets in the macOS Keychain, every read behind Touch ID

  touchenv set NAME                     store a secret (typed with no echo, or piped: touchenv set NAME < file)
  touchenv get NAME                     print it
  touchenv run NAME[:file] ... -- CMD   run CMD with each secret in env var NAME; with :file, NAME holds
                                        the path of a private temp file, removed when CMD ends
  touchenv ls                           list names
  touchenv rm NAME                      delete
"""
let context = LAContext()

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

// MARK: Keychain

func authenticate(_ reason: String) {
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        die("touchenv: cannot ask for Touch ID: \(error?.localizedDescription ?? "unknown")")
    }
    let done = DispatchSemaphore(value: 0)
    var ok = false
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
        ok = success
        done.signal()
    }
    done.wait()
    if !ok { die("touchenv: not approved") }
}

func query(_ name: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: name,
     kSecUseDataProtectionKeychain as String: true, kSecUseAuthenticationContext as String: context]
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

switch command {
case "set":
    guard args.count == 1, validName(args[0]) else { die("usage: touchenv set NAME  (NAME = env var style)", 2) }
    let name = args[0]
    let data = readStdin()
    if data.isEmpty { die("touchenv: empty secret, nothing stored") }
    var probe = query(name)
    probe[kSecReturnAttributes as String] = true
    context.interactionNotAllowed = true
    let exists = SecItemCopyMatching(probe as CFDictionary, nil) != errSecItemNotFound
    context.interactionNotAllowed = false
    if exists {
        authenticate("let \(requester()) replace the secret \(name)")
        let status = SecItemUpdate(query(name) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status != errSecSuccess { die("touchenv: keychain error \(status)") }
    } else {
        var q = query(name)
        q[kSecValueData as String] = data
        q[kSecAttrLabel as String] = "touchenv: \(name)"
        q.removeValue(forKey: kSecUseAuthenticationContext as String)
        // The system asks for Touch ID (or the Mac password) on every read, whoever reads.
        q[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, nil)!
        let status = SecItemAdd(q as CFDictionary, nil)
        if status != errSecSuccess { die("touchenv: keychain error \(status)") }
    }
    print("stored \(name) (\(data.count) bytes)")

case "get":
    guard args.count == 1 else { die("usage: touchenv get NAME", 2) }
    authenticate("show \(requester()) the secret \(args[0]) in full")
    FileHandle.standardOutput.write(read(args[0]))

case "rm":
    guard args.count == 1 else { die("usage: touchenv rm NAME", 2) }
    authenticate("let \(requester()) delete the secret \(args[0])")
    let status = SecItemDelete(query(args[0]) as CFDictionary)
    if status != errSecSuccess { die("touchenv: keychain error \(status)") }
    print("deleted \(args[0])")

case "ls":
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                            kSecUseDataProtectionKeychain as String: true,
                            kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
    var out: CFTypeRef?
    if SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let items = out as? [[String: Any]] {
        items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted().forEach { print($0) }
    }

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
    authenticate("give \(requester()) the secret\(specs.count > 1 ? "s" : "") \(names) for the command: \(shortCommand(argv))")

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
