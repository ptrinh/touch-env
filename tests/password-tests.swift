
// MARK: - --password tests (appended to touchenv.swift by tests/run.sh, compiled with -D TOUCHENV_TESTS)
//
// This binary runs itself as a child (--child) in a new session whose controlling terminal is a pseudo-terminal the
// parent drives: the parent sees what the child writes to /dev/tty and types into it. The password check is a fake
// (it knows "correct horse"), the wrong-password count lives in a file, and the secrets are a test value: no
// Keychain, no OpenDirectory, no real password, no window.

let secretValue = "s3cr3t-VALUE-77-not-for-the-terminal"
let goodPassword = "correct horse"

final class FileThrottleStore: ThrottleStore {
    let path: String
    init(_ path: String) { self.path = path }
    func load() -> PasswordThrottle? {
        guard let data = FileManager.default.contents(atPath: path) else { return PasswordThrottle() }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(PasswordThrottle.self, from: data)
    }
    func save(_ throttle: PasswordThrottle) -> Bool {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return FileManager.default.createFile(atPath: path, contents: try! encoder.encode(throttle))
    }
}

/// Spawns this binary with `args`, Ctrl-C at its default (the caller may ignore it), and waits.
func spawnSelf(_ args: [String], setsid: Bool) -> Int32 {
    var attributes: posix_spawnattr_t?
    posix_spawnattr_init(&attributes)
    var defaults = sigset_t()
    sigemptyset(&defaults)
    sigaddset(&defaults, SIGINT)
    posix_spawnattr_setsigdefault(&attributes, &defaults)
    posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGDEF | (setsid ? POSIX_SPAWN_SETSID : 0)))
    let path = processPath(getpid())!
    let argv: [UnsafeMutablePointer<CChar>?] = ([path] + args).map { strdup($0) } + [nil]
    var pid = pid_t()
    guard posix_spawn(&pid, path, nil, &attributes, argv, environ) == 0 else { return 99 }
    argv.forEach { free($0) }
    var status: Int32 = 0
    waitpid(pid, &status, 0)
    return (status & 0x7f) != 0 ? 128 + (status & 0x7f) : (status >> 8) & 0xff
}

// The session holder: makes the pseudo-terminal its session's terminal, runs the child in the foreground, and
// stays, so the terminal isn't revoked when the child ends; then says whether echo is on.
if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--session" {
    let fd = open(ProcessInfo.processInfo.environment["TEST_SLAVE"]!, O_RDWR)
    if fd < 0 || ioctl(fd, UInt(0x2000_7461), 0) != 0 {   // TIOCSCTTY
        FileHandle.standardError.write("session: no controlling terminal: \(errno)\n".data(using: .utf8)!)
        exit(9)
    }
    signal(SIGINT, SIG_IGN)
    let status = spawnSelf(["--child", CommandLine.arguments[2]], setsid: false)
    var t = termios()
    tcgetattr(fd, &t)
    FileHandle.standardError.write("ECHO-AFTER: \(t.c_lflag & tcflag_t(ECHO) != 0 ? "on" : "off")\n".data(using: .utf8)!)
    exit(status)
}

if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--child" {
    let env = ProcessInfo.processInfo.environment
    homePath = env["TEST_HOME"]!
    syncedLookup = { ["SYNCED_A": true, "SYNCED_B": true, "LOCAL_L": false][$0] }
    passwordVerifier = { typed in Array(typed) == Array(goodPassword.utf8) ? .ok : .wrong }
    throttleStore = FileThrottleStore(env["THROTTLE_FILE"]!)
    throttleUnit = 0.5
    passwordWiped = { buffer, count in
        let clean = (0..<count).allSatisfy { buffer[$0] == 0 }
        FileHandle.standardError.write((clean ? "buffer wiped\n" : "BUFFER NOT WIPED\n").data(using: .utf8)!)
    }
    let names = env["NAMES"]!.split(separator: ",").map(String.init)
    currentAttempt = AccessAttempt(event: "read", secrets: names, who: "Tester", program: "/bin/tester", intent: "test intent")
    let secrets = passwordRead(names: names, summary: ["touchenv: show Tester \(names.joined(separator: ", ")) in full?",
                                                       "  Intent: test intent \u{1b}[31mred"],
                               read: { _ in Data(secretValue.utf8) })
    if CommandLine.arguments[2] == "run" {
        // As touchenv run, where the command inherits the terminal: is anything typed ahead still waiting there?
        let tty = open("/dev/tty", O_RDONLY)
        var pending: Int32 = 0
        _ = ioctl(tty, UInt(0x4004_667f), &pending)   // FIONREAD
        var t = termios()
        tcgetattr(tty, &t)
        FileHandle.standardError.write("echo before the command: \(t.c_lflag & tcflag_t(ECHO) != 0 ? "on" : "off")\n".data(using: .utf8)!)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", "echo \"pending: $PENDING env: ${#TOKEN}\""]
        p.environment = ["TOKEN": String(decoding: secrets[names[0]]!, as: UTF8.self), "PENDING": "\(pending)", "PATH": "/usr/bin:/bin"]
        try! p.run()
        p.waitUntilExit()
    } else {
        FileHandle.standardOutput.write(secrets[names[0]]!)
    }
    exit(0)
}

let testDir = ProcessInfo.processInfo.environment["TOUCHENV_TEST_DIR"]!
homePath = testDir + "/home"
try! FileManager.default.createDirectory(atPath: homePath, withIntermediateDirectories: true)
let throttleFile = testDir + "/throttle.json"
var failures = 0, passes = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if ok { passes += 1 } else { failures += 1; print("FAIL (line \(line)): \(what)") }
}
let me = processPath(getpid())!

/// A pseudo-terminal and what the child has written to it so far.
final class Terminal {
    var master: Int32 = -1, slave: Int32 = -1
    var name = ""
    var output = ""
    let lock = NSLock()
    init() {
        precondition(openpty(&master, &slave, nil, nil, nil) == 0)
        name = String(cString: ttyname(slave))
        let fd = master
        Thread.detachNewThread { [weak self] in
            var buffer = [UInt8](repeating: 0, count: 4096)
            while true {
                let n = read(fd, &buffer, buffer.count)
                if n <= 0 { break }
                self?.lock.lock()
                self?.output += String(decoding: buffer[0..<n], as: UTF8.self)
                self?.lock.unlock()
            }
        }
    }
    var text: String { lock.lock(); defer { lock.unlock() }; return output }
    func count(_ s: String) -> Int { text.components(separatedBy: s).count - 1 }
    @discardableResult
    func waitFor(_ s: String, times n: Int = 1, timeout: TimeInterval = 10) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end { if count(s) >= n { return true }; usleep(20_000) }
        return false
    }
    func type(_ s: String) { _ = s.utf8CString.withUnsafeBufferPointer { write(master, $0.baseAddress, $0.count - 1) } }
    var echoOn: Bool { var t = termios(); tcgetattr(slave, &t); return t.c_lflag & tcflag_t(ECHO) != 0 }
}

struct Child { let pid: pid_t; let out: String; let err: String }

/// Starts this binary as --child in a new session; with a terminal, that terminal is its controlling one.
func start(_ mode: String, names: String, terminal: Terminal?, stdinFile: String? = nil, extraEnv: [String: String] = [:]) -> Child {
    let out = testDir + "/out-\(UUID().uuidString)", err = testDir + "/err-\(UUID().uuidString)"
    var attributes: posix_spawnattr_t?
    posix_spawnattr_init(&attributes)
    posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID))
    var actions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&actions)
    posix_spawn_file_actions_addopen(&actions, 0, stdinFile ?? "/dev/null", O_RDONLY, 0)
    posix_spawn_file_actions_addopen(&actions, 1, out, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
    posix_spawn_file_actions_addopen(&actions, 2, err, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
    var env = ["TEST_HOME": homePath, "TEST_SLAVE": terminal?.name ?? "", "THROTTLE_FILE": throttleFile, "NAMES": names,
               "PATH": "/usr/bin:/bin"]
    env.merge(extraEnv) { _, new in new }
    let argv: [UnsafeMutablePointer<CChar>?] = [strdup(me), strdup(terminal == nil ? "--child" : "--session"), strdup(mode), nil]
    let envp: [UnsafeMutablePointer<CChar>?] = env.map { strdup("\($0.key)=\($0.value)") } + [nil]
    var pid = pid_t()
    let status = posix_spawn(&pid, me, &actions, &attributes, argv, envp)
    argv.forEach { free($0) }
    envp.forEach { free($0) }
    precondition(status == 0)
    return Child(pid: pid, out: out, err: err)
}

func finish(_ child: Child) -> (status: Int32, signaled: Bool, out: String, err: String) {
    var status: Int32 = 0
    waitpid(child.pid, &status, 0)
    let read = { (p: String) in String(decoding: FileManager.default.contents(atPath: p) ?? Data(), as: UTF8.self) }
    let code = (status >> 8) & 0xff
    return (code, code == 128 + SIGINT, read(child.out), read(child.err))
}

func resetThrottle() { try? FileManager.default.removeItem(atPath: throttleFile) }
func throttleNow() -> PasswordThrottle { FileThrottleStore(throttleFile).load()! }
func logText() -> String {
    ((try? FileManager.default.contentsOfDirectory(atPath: accessLogDir())) ?? []).filter { $0.hasPrefix("touchenv-access-") }
        .map { String(decoding: FileManager.default.contents(atPath: accessLogDir() + "/" + $0)!, as: UTF8.self) }.joined()
}
let prompt = "(not shown): "
FileManager.default.createFile(atPath: testDir + "/pw-file", contents: Data((goodPassword + "\n").utf8))

// MARK: Units

throttleUnit = 1
check(throttleDelay(0) == 0 && throttleDelay(1) == 1 && throttleDelay(2) == 2 && throttleDelay(3) == 4, "1, 2, 4 …")
check(throttleDelay(40) == 3600, "an hour at most")
check(terminalText("a\u{1b}[2Jb\nc\u{202e}d") == "a [2Jb c d", "no control characters to the terminal")

// MARK: The right password: get

resetThrottle()
do {
    let tty = Terminal()
    let child = start("get", names: "SYNCED_A", terminal: tty)
    check(tty.waitFor(prompt), "the prompt is on the terminal: \(tty.text)")
    check(!tty.echoOn, "echo is off while it waits")
    check(tty.text.contains("Intent: test intent") && tty.text.contains("show Tester SYNCED_A"), "what is approved is shown first")
    check(!tty.text.contains("\u{1b}"), "no escape sequence reaches the terminal")
    tty.type(goodPassword + "\n")
    let r = finish(child)
    check(r.status == 0, "approved: \(r.err)")
    check(r.out == secretValue, "stdout carries only the secret: [\(r.out)]")
    check(!r.out.contains("not shown") && !r.out.contains("Intent"), "no prompt on stdout")
    usleep(100_000)
    check(!tty.text.contains(goodPassword), "the password is not echoed")
    check(!tty.text.contains(secretValue), "the secret is not on the terminal")
    check(r.err.contains("ECHO-AFTER: on"), "echo is back on")
    check(r.err.contains("buffer wiped") && !r.err.contains("NOT WIPED"), "the buffer is wiped")
    let e = readAccessLog().last
    check(e?.outcome == ReadOutcome.passwordCLI && e?.secrets == ["SYNCED_A"] && e?.intent == "test intent", "logged: \(String(describing: e))")
    check(throttleNow().failures == 0, "no failure counted")
}

// MARK: stdout piped elsewhere: the prompt still comes from the terminal

resetThrottle()
do {
    let tty = Terminal()
    let child = start("get", names: "SYNCED_A", terminal: tty, stdinFile: testDir + "/pw-file")
    check(tty.waitFor(prompt), "prompt with stdin from a file")
    tty.type(goodPassword + "\n")
    let r = finish(child)
    check(r.status == 0 && r.out == secretValue, "only the secret: [\(r.out)]")
}

// MARK: Wrong, then right: the wait grows, the count clears

resetThrottle()
do {
    let tty = Terminal()
    let child = start("get", names: "SYNCED_A", terminal: tty)
    tty.waitFor(prompt)
    tty.type("wrong one\n")
    check(tty.waitFor("Wrong password."), "says so")
    let t0 = Date()
    check(tty.waitFor(prompt, times: 2), "asks again")
    check(Date().timeIntervalSince(t0) >= 0.4, "after a wait")
    tty.type(goodPassword + "\n")
    let r = finish(child)
    check(r.status == 0 && r.out == secretValue, "the second try works")
    check(throttleNow().failures == 0, "success clears the count")
    let lines = readAccessLog().suffix(2)
    check(lines.first?.outcome == ReadOutcome.refused && lines.first?.note == "wrong password (try 1 of 3)"
          && lines.last?.outcome == ReadOutcome.passwordCLI, "both logged: \(lines.map(\.note))")
}

// MARK: Three wrong, then the next run must wait

resetThrottle()
do {
    let tty = Terminal()
    let child = start("get", names: "SYNCED_A", terminal: tty)
    for n in 1...3 {
        check(tty.waitFor(prompt, times: n), "prompt \(n)")
        tty.type("guess \(n)\n")
    }
    let r = finish(child)
    check(r.status == 1 && r.err.contains("wrong password") && r.out.isEmpty, "refused after 3: \(r.err)")
    check(throttleNow().failures == 3 && throttleNow().notBefore > Date(), "3 counted, with a wait")
    let wrong = readAccessLog().filter { $0.note.hasPrefix("wrong password (try") }.suffix(3)
    check(wrong.map(\.note) == ["wrong password (try 1 of 3)", "wrong password (try 2 of 3)", "wrong password (try 3 of 3)"],
          "each try logged")
    check(!logText().contains("guess"), "no password in the log")
    check(r.err.contains("ECHO-AFTER: on"), "echo back on")
    // At once again: no prompt at all.
    let tty2 = Terminal()
    let again = finish(start("get", names: "SYNCED_A", terminal: tty2))
    check(again.status == 1 && again.err.contains("too many wrong passwords; try again in"), "the next run must wait: \(again.err)")
    check(!tty2.text.contains(prompt), "and isn't even asked")
    check(readAccessLog().last?.note == "too many wrong passwords", "logged")
    // A file the child can't parse: fail closed.
    FileManager.default.createFile(atPath: throttleFile, contents: Data("junk".utf8))
    let junk = finish(start("get", names: "SYNCED_A", terminal: Terminal()))
    check(junk.status == 1 && junk.err.contains("can't read the count"), "an unreadable count checks nothing: \(junk.err)")
}

// MARK: Refused before any prompt

resetThrottle()
do {
    let tty = Terminal()
    let r = finish(start("get", names: "SYNCED_A,LOCAL_L", terminal: tty))
    check(r.status == 1 && r.err.contains("LOCAL_L") && r.err.contains("without --password") && !r.err.contains("SYNCED_A is"),
          "a local secret refuses the whole request: \(r.err)")
    check(!tty.text.contains(prompt) && r.out.isEmpty, "before any prompt")
    check(readAccessLog().last?.note == "local secret: LOCAL_L", "logged")
    let missing = finish(start("get", names: "NOPE", terminal: Terminal()))
    check(missing.status == 1 && readAccessLog().last?.note == "no secret named NOPE", "a missing secret")
    // No terminal: the password isn't taken from anywhere else.
    let none = finish(start("get", names: "SYNCED_A", terminal: nil, stdinFile: testDir + "/pw-file",
                            extraEnv: ["TOUCHENV_PASSWORD": goodPassword, "PASSWORD": goodPassword]))
    check(none.status == 1 && none.err.contains("needs a terminal") && none.out.isEmpty,
          "no terminal: refused, whatever is in stdin or the environment: \(none.err)")
    check(readAccessLog().last?.note == "no terminal", "logged")
}

// MARK: Ctrl-C, end of input

do {
    let tty = Terminal()
    let child = start("get", names: "SYNCED_A", terminal: tty)
    tty.waitFor(prompt)
    check(!tty.echoOn, "echo off")
    tty.type("\u{3}")   // Ctrl-C, as typed
    let r = finish(child)
    check(r.signaled && r.out.isEmpty, "Ctrl-C ends it: \(r.status) \(r.err)")
    check(r.err.contains("ECHO-AFTER: on"), "and echo is back on")
    let tty2 = Terminal()
    let eof = start("get", names: "SYNCED_A", terminal: tty2)
    tty2.waitFor(prompt)
    tty2.type("\u{4}")
    let r2 = finish(eof)
    check(r2.status == 1 && readAccessLog().last?.outcome == ReadOutcome.cancelled, "Ctrl-D: cancelled, logged")
    check(r2.err.contains("ECHO-AFTER: on"), "echo back on")
}

// MARK: run: the command doesn't get what was typed ahead

resetThrottle()
do {
    let tty = Terminal()
    let child = start("run", names: "SYNCED_A", terminal: tty)
    tty.waitFor(prompt)
    tty.type(goodPassword + "\nLEFTOVER\n")
    let r = finish(child)
    check(r.status == 0, "run approved: \(r.err)")
    check(r.out == "pending: 0 env: \(secretValue.count)\n", "typed-ahead input flushed, the secret in the environment: [\(r.out)]")
    check(!r.out.contains(secretValue), "only the command's output on stdout")
    check(r.err.contains("echo before the command: on"), "echo restored before the command runs: \(r.err)")
}

check(!logText().contains(goodPassword) && !logText().contains(secretValue), "no password or value in the log")

print("\(passes) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
