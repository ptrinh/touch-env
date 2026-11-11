
// MARK: - Standing grant and access log tests (appended to touchenv.swift by tests/run.sh, -D TOUCHENV_TESTS)
//
// No Keychain: the grants live in MemoryStandingStore. No Touch ID, no window. Real processes for the caller checks:
// this binary runs itself under /bin/sh, bash, zsh and copies of them, as --caller-probe, and reports what
// standingDecision makes of the process that ran it, with the real Security framework signature checks.

let testDir = ProcessInfo.processInfo.environment["TOUCHENV_TEST_DIR"]!
homePath = testDir + "/home"

final class MemoryStandingStore: StandingStore {
    var items: [String: (grant: StandingGrant, values: [String: Data])] = [:]
    func list() -> [StandingGrant] { items.values.map(\.grant).sorted { $0.program < $1.program } }
    func values(_ program: String) -> [String: Data]? { items[program]?.values }
    func put(_ grant: StandingGrant, values: [String: Data]) -> OSStatus { items[grant.program] = (grant, values); return errSecSuccess }
    func update(_ grant: StandingGrant) -> OSStatus {
        guard let old = items[grant.program] else { return errSecItemNotFound }
        items[grant.program] = (grant, old.values)
        return errSecSuccess
    }
    func remove(_ program: String) -> OSStatus { items.removeValue(forKey: program) == nil ? errSecItemNotFound : errSecSuccess }
}
let memory = MemoryStandingStore()
standingStore = memory

func grantsFile(_ grants: [StandingGrant]) -> String {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .secondsSince1970
    let path = testDir + "/grants-\(UUID().uuidString).json"
    FileManager.default.createFile(atPath: path, contents: try! encoder.encode(grants))
    return path
}

// The probe: what does standingDecision say about the process that ran me?
if CommandLine.arguments.count == 4, CommandLine.arguments[1] == "--caller-probe" {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .secondsSince1970
    let grants = try! decoder.decode([StandingGrant].self, from: FileManager.default.contents(atPath: CommandLine.arguments[2])!)
    guard let caller = callerInfo(getppid()) else { print("no-caller"); exit(0) }
    switch standingDecision(grants, names: [CommandLine.arguments[3]], caller: caller, checks: realCodeChecks, now: Date()) {
    case .none: print("none")
    case .allowed(let g): print("allowed \(g.program)")
    case .refused(_, let reason): print("refused \(reason)")
    case .ended(_, let reason): print("ended \(reason)")
    }
    FileHandle.standardError.write("caller \(caller.executable) \(caller.arguments) cwd \(caller.cwd)\n".data(using: .utf8)!)
    exit(0)
}

var failures = 0, passes = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if ok { passes += 1 } else { failures += 1; print("FAIL (line \(line)): \(what)") }
}

@discardableResult
func sh(_ argv: [String], cwd: String = testDir, env extra: [String: String] = [:]) -> (status: Int32, out: String, err: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: argv[0])
    p.arguments = Array(argv.dropFirst())
    p.currentDirectoryURL = URL(fileURLWithPath: cwd)
    var env = ["PATH": "/usr/bin:/bin", "HOME": homePath]
    env.merge(extra) { _, new in new }
    p.environment = env
    let out = Pipe(), err = Pipe()
    p.standardOutput = out
    p.standardError = err
    p.standardInput = FileHandle.nullDevice
    try! p.run()
    let o = out.fileHandleForReading.readDataToEndOfFile(), e = err.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: o, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
            String(decoding: e, as: UTF8.self))
}
func write(_ path: String, _ text: String, mode: Int = 0o700) {
    FileManager.default.createFile(atPath: path, contents: Data(text.utf8), attributes: [.posixPermissions: mode])
}

let probe = processPath(getpid())!
let secretValue = "s3cr3t-VALUE-4242-do-not-log"

// MARK: Lengths

check(parseLength("90d") == 90 * 86400, "90d")
check(parseLength("1d12h") == 36 * 3600, "1d12h")
check(parseLength("8h") == 8 * 3600 && parseLength("1h30m") == 5400, "hours and minutes as before")
check(parseLength("1d1d") == nil && parseLength("d") == nil && parseLength("0d") == nil, "bad day lengths refused")

// MARK: The interpreter's arguments

check(scriptArgument(["/bin/sh", "helper.sh"]) == "helper.sh", "sh helper.sh")
check(scriptArgument(["/bin/sh", "-e", "helper.sh", "x"]) == "helper.sh", "options before the script")
check(scriptArgument(["bash", "-o", "pipefail", "helper.sh"]) == "helper.sh", "-o takes a value")
check(scriptArgument(["bash", "--norc", "--", "helper.sh"]) == "helper.sh", "-- ends the options")
check(scriptArgument(["sh", "-c", "touchenv get A", "helper.sh"]) == nil, "-c: commands, not a script")
check(scriptArgument(["sh", "-ec", "touchenv get A"]) == nil, "-c among other letters")
check(scriptArgument(["sh", "-s", "helper.sh"]) == nil, "-s: commands from stdin")
check(scriptArgument(["bash", "--rcfile", "evil", "helper.sh"]) == nil, "an option with a file of its own")
check(scriptArgument(["zsh"]) == nil, "no script at all")

// MARK: Scripts: identity

let scripts = testDir + "/scripts"
try! FileManager.default.createDirectory(atPath: scripts, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
let helper = scripts + "/helper.sh"
let helperText = """
    #!/bin/sh
    # like ~/.claude/mcp-trinh-headers.sh: the value inside $( ), then printed
    out=$("$PROBE" --caller-probe "$GRANTS" API_TOKEN)
    printf '%s\\n' "$out"

    """
write(helper, helperText)
let realHelper = realPath(helper)!
check(pathSafetyProblem(realHelper) == nil, "the test folder is private: \(pathSafetyProblem(realHelper) ?? "")")

guard case .success(let scriptGrantTemplate) = identifyProgram(helper) else { fatalError("helper.sh not identified") }
var scriptGrant = scriptGrantTemplate
scriptGrant.names = ["API_TOKEN"]
check(scriptGrant.kind == "script" && scriptGrant.program == realHelper, "a script is bound to its real path")
check(scriptGrant.sha256 == sha256Hex(Data(helperText.utf8)), "and to the SHA-256 of its contents")
check(scriptGrant.requirement == nil, "a script has no signature")

let link = scripts + "/link.sh"
symlink(helper, link)
if case .success(let g) = identifyProgram(link) { check(g.program == realHelper, "a symbolic link is bound to the file it points to") }
else { check(false, "symlink identified") }

if case .failure(let p) = identifyProgram(testDir + "/nope") { check(p.description.contains("no such file"), "missing: \(p)") }
else { check(false, "a missing file refused") }
if case .failure(let p) = identifyProgram(scripts) { check(p.description.contains("folder"), "folder: \(p)") }
else { check(false, "a folder refused") }
write(scripts + "/tool.py", "#!/usr/bin/python3\nprint(1)\n")
if case .failure(let p) = identifyProgram(scripts + "/tool.py") { check(p.description.contains("shell scripts"), "python: \(p)") }
else { check(false, "a python script refused") }
write(scripts + "/env.sh", "#!/usr/bin/env bash\necho\n")
if case .success(let g) = identifyProgram(scripts + "/env.sh") { check(g.kind == "script", "#!/usr/bin/env bash is a shell script") }
else { check(false, "#!/usr/bin/env bash taken") }
write(scripts + "/open.sh", "#!/bin/sh\necho\n", mode: 0o766)
chmod(scripts + "/open.sh", 0o766)
if case .failure(let p) = identifyProgram(scripts + "/open.sh") { check(p.description.contains("changed by other users"), "writable: \(p)") }
else { check(false, "a script others can write is refused at grant time") }

// MARK: Scripts: the real process checks

func probeRun(_ argv: [String], grants: [StandingGrant], cwd: String = scripts) -> String {
    let r = sh(argv, cwd: cwd, env: ["PROBE": probe, "GRANTS": grantsFile(grants), "TOUCHENV_TEST_DIR": testDir])
    return r.out
}

check(probeRun(["/bin/sh", "helper.sh"], grants: [scriptGrant]) == "allowed \(realHelper)", "sh helper.sh (relative, from its folder)")
check(probeRun(["/bin/sh", realHelper], grants: [scriptGrant]) == "allowed \(realHelper)", "sh /full/path/helper.sh")
check(probeRun([helper], grants: [scriptGrant]) == "allowed \(realHelper)", "run directly, through #!/bin/sh")
check(probeRun(["/bin/bash", "helper.sh"], grants: [scriptGrant]) == "allowed \(realHelper)", "bash helper.sh")
check(probeRun(["/bin/zsh", "helper.sh"], grants: [scriptGrant]) == "allowed \(realHelper)", "zsh helper.sh")
check(probeRun(["/bin/sh", "-e", "helper.sh"], grants: [scriptGrant]) == "allowed \(realHelper)", "sh -e helper.sh")
check(probeRun(["/bin/sh", "link.sh"], grants: [scriptGrant]) == "allowed \(realHelper)", "through a symbolic link to it")
check(probeRun(["/bin/sh", "scripts/helper.sh"], grants: [scriptGrant], cwd: testDir) == "allowed \(realHelper)", "relative from another folder")
// Another way to run the same commands is not the script.
check(probeRun(["/bin/sh", "-c", "out=$(\"$PROBE\" --caller-probe \"$GRANTS\" API_TOKEN); echo \"$out\"", realHelper],
               grants: [scriptGrant]) == "none", "sh -c with the script's path as an argument: not the script")
// The same text somewhere else is another program.
let copyDir = testDir + "/other"
try! FileManager.default.createDirectory(atPath: copyDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
write(copyDir + "/helper.sh", helperText)
check(probeRun(["/bin/sh", copyDir + "/helper.sh"], grants: [scriptGrant]) == "none", "an identical copy elsewhere")
// A shell that isn't the system's own (a copy of bash) isn't trusted to report what it runs.
try? FileManager.default.copyItem(atPath: "/bin/bash", toPath: copyDir + "/bash")
// (macOS may not even start a copy of its own shell; either way it gets nothing.)
let copied = probeRun([copyDir + "/bash", "helper.sh"], grants: [scriptGrant])
check(copied == "none" || copied.isEmpty, "a copy of bash elsewhere: \(copied)")
// Only the secrets granted.
var otherNames = scriptGrant
otherNames.names = ["OTHER"]
check(probeRun(["/bin/sh", "helper.sh"], grants: [otherNames]) == "none", "a grant for other secrets doesn't cover this one")
// Limits.
var expired = scriptGrant
expired.expires = Date().addingTimeInterval(-1)
check(probeRun(["/bin/sh", "helper.sh"], grants: [expired]).hasPrefix("ended the standing grant expired"), "expired")
var usedUp = scriptGrant
usedUp.usesLeft = 0
check(probeRun(["/bin/sh", "helper.sh"], grants: [usedUp]).hasPrefix("ended the standing grant's uses ran out"), "used up")
// Changes.
write(helper, helperText + "printf 'and now something else\\n'\n")
check(probeRun(["/bin/sh", "helper.sh"], grants: [scriptGrant]).hasPrefix("refused") , "an edited script is refused")
check(probeRun(["/bin/sh", "helper.sh"], grants: [scriptGrant]).contains("SHA-256 differs"), "and says why")
write(helper, helperText)
check(probeRun(["/bin/sh", "helper.sh"], grants: [scriptGrant]) == "allowed \(realHelper)", "put back as it was: allowed again")
chmod(helper, 0o722)
check(probeRun(["/bin/sh", "helper.sh"], grants: [scriptGrant]).contains("can be changed by other users"), "a script others can write")
chmod(helper, 0o700)
chmod(scripts, 0o777)
check(probeRun(["/bin/sh", realHelper], grants: [scriptGrant]).contains("the folder"), "a folder others can write")
chmod(scripts, 0o700)
check(probeRun(["/bin/sh", "helper.sh"], grants: [scriptGrant]) == "allowed \(realHelper)", "all back: allowed")

// MARK: Signed programs

guard case .success(var bashGrant) = identifyProgram("/bin/bash"), case .success(var zshGrant) = identifyProgram("/bin/zsh") else {
    fatalError("system shells not identified")
}
bashGrant.names = ["API_TOKEN"]
zshGrant.names = ["API_TOKEN"]
check(bashGrant.kind == "signed" && bashGrant.requirement?.contains("com.apple.bash") == true, "bash: \(bashGrant.requirement ?? "")")
check(bashGrant.signer?.hasPrefix("Apple") == true, "Apple's signature named: \(bashGrant.signer ?? "")")
let underBash = ["/bin/bash", "-c", "\"$PROBE\" --caller-probe \"$GRANTS\" API_TOKEN; true"]
check(probeRun(underBash, grants: [bashGrant]) == "allowed \(bashGrant.program)", "a signed program, checked by its signature")
check(probeRun(underBash, grants: [zshGrant]) == "none", "another signed program's grant doesn't cover it")
var forged = bashGrant
forged.requirement = zshGrant.requirement
check(probeRun(underBash, grants: [forged]).hasPrefix("refused"), "the granted path signed differently: refused")
if case .success(let me) = identifyProgram(probe) {
    check(me.signer?.hasPrefix("ad hoc") == true && me.requirement?.contains("cdhash") == true,
          "an ad hoc signed build is bound to its exact hash: \(me.requirement ?? "")")
} else { check(false, "the test binary identified") }

// MARK: Reading under a standing grant (memory store, the log)

let logDir = accessLogDir()
func allLogText() -> String {
    ((try? FileManager.default.contentsOfDirectory(atPath: logDir)) ?? []).filter { $0.hasPrefix("touchenv-access") }
        .map { String(decoding: FileManager.default.contents(atPath: logDir + "/" + $0) ?? Data(), as: UTF8.self) }
        .joined()
}
func lastEntry() -> AccessEntry? { readAccessLog().last }

let fakeCaller = Caller(pid: 4242, start: 1, executable: "/bin/sh", arguments: ["/bin/sh", realHelper], cwd: "/")
let trusting = CodeChecks(applePlatform: { _ in true }, satisfies: { _, _ in false })
_ = memory.put(scriptGrant, values: ["API_TOKEN": Data(secretValue.utf8)])
check(memory.list() == [scriptGrant], "record round trip")
var read1 = standingRead(names: ["API_TOKEN"], caller: fakeCaller, who: "Claude Code", intent: "connect MCP",
                         checks: trusting, stillThere: { _ in true })
if case .secrets(let s) = read1 { check(s["API_TOKEN"] == Data(secretValue.utf8), "the value comes from the grant's copy") }
else { check(false, "standing read allowed") }
check(memory.list()[0].reads == 1 && memory.list()[0].lastUsed != nil, "reads counted, last use kept")
var e = lastEntry()
check(e?.event == "read" && e?.outcome == ReadOutcome.standing && e?.secrets == ["API_TOKEN"] && e?.program == realHelper
      && e?.intent == "connect MCP" && e?.who == "Claude Code", "standing read logged: \(String(describing: e))")
read1 = standingRead(names: ["API_TOKEN"], caller: fakeCaller, who: "x", intent: nil, checks: trusting, stillThere: { _ in false })
if case .refused = read1 { check(lastEntry()?.note.contains("went away") == true, "a caller gone during the checks is refused") }
else { check(false, "caller gone refused") }
// Uses run out under the lock.
var limited = scriptGrant
limited.usesLeft = 1
_ = memory.put(limited, values: ["API_TOKEN": Data(secretValue.utf8)])
if case .secrets = standingRead(names: ["API_TOKEN"], caller: fakeCaller, who: "x", intent: nil, checks: trusting, stillThere: { _ in true }) {
    check(memory.list()[0].usesLeft == 0 && lastEntry()?.note == "0 uses left", "last use taken")
} else { check(false, "one use allowed") }
if case .none = standingRead(names: ["API_TOKEN"], caller: fakeCaller, who: "x", intent: nil, checks: trusting, stillThere: { _ in true }) {
    check(lastEntry()?.outcome == ReadOutcome.refused && lastEntry()?.note.contains("asking instead") == true, "used up: logged, then asks")
} else { check(false, "used up falls through") }
// A changed script: refused, no prompt.
_ = memory.put(scriptGrant, values: ["API_TOKEN": Data(secretValue.utf8)])
write(helper, helperText + "# edited\n")
if case .refused(let why) = standingRead(names: ["API_TOKEN"], caller: fakeCaller, who: "x", intent: nil, checks: trusting, stillThere: { _ in true }) {
    check(why.contains("SHA-256") && lastEntry()?.outcome == ReadOutcome.refused, "hash mismatch refused and logged")
} else { check(false, "hash mismatch refused") }
write(helper, helperText)
// Not the system's shell.
let distrusting = CodeChecks(applePlatform: { _ in false }, satisfies: { _, _ in false })
if case .refused(let why) = standingRead(names: ["API_TOKEN"], caller: fakeCaller, who: "x", intent: nil, checks: distrusting, stillThere: { _ in true }) {
    check(why.contains("system's own shell"), "interpreter signature refused: \(why)")
} else { check(false, "interpreter signature") }
// Signature mismatch, logged.
_ = memory.put(forged, values: ["API_TOKEN": Data(secretValue.utf8)])
let bashCaller = Caller(pid: 4243, start: 1, executable: "/bin/bash", arguments: ["bash", "-c", "x"], cwd: "/")
if case .refused = standingRead(names: ["API_TOKEN"], caller: bashCaller, who: "x", intent: nil, checks: trusting, stillThere: { _ in true }) {
    check(lastEntry()?.note.contains("not signed as it was") == true, "signature mismatch logged")
} else { check(false, "signature mismatch") }
_ = memory.remove(forged.program)

// MARK: set, rm, revoke, lock

_ = memory.put(scriptGrant, values: ["API_TOKEN": Data(secretValue.utf8)])
check(standingSecretChanged("API_TOKEN", to: Data("new".utf8), who: "t") == 1 && memory.values(realHelper)?["API_TOKEN"] == Data("new".utf8),
      "set updates the grant's copy")
var two = scriptGrant
two.names = ["API_TOKEN", "B"]
_ = memory.put(two, values: ["API_TOKEN": Data("a".utf8), "B": Data("b".utf8)])
standingSecretChanged("B", to: nil, who: "t")
check(memory.list().first?.names == ["API_TOKEN"] && memory.values(realHelper)?["B"] == nil, "rm drops that secret from the grant")
standingSecretChanged("API_TOKEN", to: nil, who: "t")
check(memory.list().isEmpty && lastEntry()?.event == "revoke", "rm of its last secret ends the grant")

_ = memory.put(scriptGrant, values: ["API_TOKEN": Data(secretValue.utf8)])
_ = memory.put(bashGrant, values: ["API_TOKEN": Data(secretValue.utf8)])
check(revokeStanding(testDir + "/nothing", who: "t", how: "test").isEmpty, "revoking an unknown program ends nothing")
check(revokeStanding(link, who: "t", how: "test").map(\.program) == [realHelper], "revoke by a path that leads to it")
check(memory.list().map(\.program) == [bashGrant.program], "the other stays")
check(lastEntry()?.event == "revoke" && lastEntry()?.program == realHelper, "revoke logged")
_ = memory.put(scriptGrant, values: ["API_TOKEN": Data(secretValue.utf8)])
check(revokeStanding(realHelper, who: "t", how: "test").count == 1, "revoke by the full path")
check(standingMatching("~/x.sh", in: [StandingGrant(program: homePath + "/x.sh", kind: "script", names: [], created: Date())]).count == 1,
      "revoke by ~/ path")
_ = memory.put(scriptGrant, values: ["API_TOKEN": Data(secretValue.utf8)])
let lockText = lockStanding(all: false, who: "t")
check(memory.list().count == 2 && lockText?.contains("2 standing grants still on") == true && lockText?.contains("lock --all") == true,
      "lock leaves standing grants and says how to end them: \(lockText ?? "")")
let lockAllText = lockStanding(all: true, who: "t")
check(memory.list().isEmpty && lockAllText?.hasPrefix("ended 2 standing grants") == true, "lock --all ends them: \(lockAllText ?? "")")
check(lockStanding(all: false, who: "t") == nil, "nothing to say when there are none")
check(readAccessLog().filter { $0.event == "revoke" && $0.note == "touchenv lock --all" }.count == 2, "lock --all logged per grant")
check(describeStanding(scriptGrant).joined().contains("no time or use limit") && describeStanding(limited).joined().contains("1 time left"),
      "the listing shows limits")

// MARK: Record encoding

var full = scriptGrant
full.expires = Date(timeIntervalSince1970: 2_000_000_000)
full.usesLeft = 7
full.lastUsed = Date(timeIntervalSince1970: 1_900_000_000)
full.reads = 3
full.created = Date(timeIntervalSince1970: 1_800_000_000)
check(decodeStanding(encodeStanding(full)) == full, "record encodes and decodes")
check(!String(decoding: encodeStanding(full), as: UTF8.self).contains("s3cr3t"), "the record holds no value")
check(decodeValues(encodeValues(["A": Data(secretValue.utf8)]))?["A"] == Data(secretValue.utf8), "values round trip")
check(decodeStanding(Data("{}".utf8)) == nil && decodeValues(Data("[1]".utf8)) == nil, "junk refused")

// MARK: The access log: outcomes

for outcome in [ReadOutcome.touchID, ReadOutcome.fiveMinute, ReadOutcome.grant, ReadOutcome.standing, ReadOutcome.refused,
                ReadOutcome.cancelled, ReadOutcome.failed] {
    currentAttempt = AccessAttempt(event: "read", secrets: ["A", "B"], who: "Claude Code", program: "/usr/bin/x", intent: "why")
    logAttempt(outcome, note: outcome == ReadOutcome.failed ? "keychain error -25300" : "")
    let entry = lastEntry()
    check(entry?.outcome == outcome && entry?.secrets == ["A", "B"] && entry?.who == "Claude Code" && entry?.program == "/usr/bin/x"
          && entry?.intent == "why", "\(outcome) logged: \(String(describing: entry))")
    check(currentAttempt == nil, "one line per attempt")
}
logAttempt(ReadOutcome.touchID)
check(lastEntry()?.outcome == ReadOutcome.failed, "no attempt under way: nothing logged")

// MARK: The access log: hostile text

let before = allLogText().split(separator: "\n").count
let hostile = "fine\n2026-01-01T00:00:00Z\tread\tA\ttouch-id\tforged\t-\t-\t-\r\u{1b}[2K\u{1b}[31mRED\u{202e}evil\u{2028}x"
    + String(repeating: "y", count: 5000)
logAccess(AccessEntry(event: "read", secrets: ["A", "bad\nname"], outcome: "refused\tx", who: hostile, program: hostile,
                      intent: hostile, note: hostile))
let after = allLogText().split(separator: "\n", omittingEmptySubsequences: false)
check(after.filter { !$0.isEmpty }.count == before + 1, "a hostile entry is exactly one line")
let hostileLine = String(after.filter { !$0.isEmpty }.last!)
check(hostileLine.split(separator: "\t", omittingEmptySubsequences: false).count == 8, "with exactly eight fields")
check(!hostileLine.unicodeScalars.contains { ($0.properties.generalCategory == .control && $0 != "\t") || $0.properties.generalCategory == .format
                                             || $0 == "\u{2028}" }, "no control, escape or bidi characters")
check(parseAccessLine(hostileLine)!.intent.count <= 200 && hostileLine.count < 2000, "lengths capped")
check(parseAccessLine(hostileLine)!.secrets == ["A"], "only real names in the names field")
check(!readAccessLog().contains { $0.who == "forged" }, "no forged entry read back")

// MARK: The access log: never a value

check(!allLogText().contains(secretValue) && !allLogText().contains("s3cr3t"), "no value in the log")

// MARK: The access log: folder and file

var st = stat()
check(lstat(accessLogFile(for: Date()), &st) == 0 && st.st_mode & 0o777 == 0o600, "the log is 0600")
chmod(logDir, 0o777)
let countBefore = readAccessLog().count
logAccess(AccessEntry(event: "read", outcome: "touch-id"))
check(readAccessLog().count == countBefore, "not written into a folder others can write")
chmod(logDir, 0o700)

// MARK: The access log: two years, and the cap

let fresh = testDir + "/home2"
homePath = fresh
let now = logCalendar.date(from: DateComponents(year: 2026, month: 11, day: 15, hour: 12))!
func entry(_ daysAgo: Double, _ note: String) -> AccessEntry {
    AccessEntry(time: now.addingTimeInterval(-daysAgo * 86400), event: "read", secrets: ["A"], outcome: "touch-id", note: note)
}
try! FileManager.default.createDirectory(atPath: accessLogDir(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
for e in [entry(800, "old month"), entry(731, "just over"), entry(729.9, "just under"), entry(400, "last year"), entry(1, "yesterday")] {
    appendLogLine(accessLine(e), to: accessLogFile(for: e.time))
}
check(FileManager.default.fileExists(atPath: accessLogFile(for: entry(800, "").time)), "the old month's file is there before")
pruneAccessLog(now: now)
var notes = readAccessLog().map(\.note)
check(notes == ["just under", "last year", "yesterday"], "older than two years removed, the rest kept: \(notes)")
check(!FileManager.default.fileExists(atPath: accessLogFile(for: entry(800, "").time)), "a month entirely older is deleted")
check(FileManager.default.fileExists(atPath: accessLogFile(for: entry(729.9, "").time)), "the month across the line is pruned, not deleted")
// Pruning runs from logAccess at most once a day.
accessLogNow = { now }
logAccess(entry(0, "today"))
let marker = accessLogDir() + "/touchenv-access.pruned"
check(FileManager.default.fileExists(atPath: marker), "the day's pruning is marked")
appendLogLine(accessLine(entry(735, "planted")), to: accessLogFile(for: entry(735, "").time))
logAccess(AccessEntry(time: now.addingTimeInterval(3600), event: "read", outcome: "touch-id", note: "an hour later"))
check(readAccessLog().contains { $0.note == "planted" }, "no second pruning the same day")
logAccess(AccessEntry(time: now.addingTimeInterval(86400 + 60), event: "read", outcome: "touch-id", note: "next day"))
notes = readAccessLog().map(\.note)
check(!notes.contains("planted") && notes.suffix(3) == ["today", "an hour later", "next day"], "next day: pruned again, new lines kept: \(notes)")
// The cap, across months.
accessLogCap = 4096
for month in 0..<4 {
    for i in 0..<20 {
        let e = AccessEntry(time: logCalendar.date(byAdding: .month, value: -3 + month, to: now)!.addingTimeInterval(Double(i)),
                            event: "read", secrets: ["A"], outcome: "touch-id", note: "m\(month) i\(i) " + String(repeating: "p", count: 40))
        appendLogLine(accessLine(e), to: accessLogFile(for: e.time))
    }
}
pruneAccessLog(now: now)
let capped = readAccessLog()
let total = ((try? FileManager.default.contentsOfDirectory(atPath: accessLogDir())) ?? []).filter { accessLogMonth($0) != nil }
    .reduce(0) { $0 + fileSize(accessLogDir() + "/" + $1) }
check(total <= 4096 + 300, "under the cap after pruning: \(total)")
check(capped.contains { $0.note.hasPrefix("m3 i19") }, "the newest entry stays")
check(!capped.contains { $0.note.hasPrefix("m0 ") }, "the oldest go first")
check(capped.filter { $0.outcome == "dropped" && $0.note.contains("oldest entries dropped") }.count == 1, "one line says so")
// One month alone over the cap.
for i in 0..<200 {
    appendLogLine(accessLine(AccessEntry(time: now.addingTimeInterval(Double(i)), event: "read", outcome: "touch-id",
                                         note: "flood \(i) " + String(repeating: "q", count: 40))), to: accessLogFile(for: now))
}
pruneAccessLog(now: now)
let flooded = readAccessLog()
check(fileSize(accessLogFile(for: now)) <= 4096, "a runaway month is cut to the cap")
check(flooded.contains { $0.note.hasPrefix("flood 199 ") } && !flooded.contains { $0.note.hasPrefix("flood 0 ") }, "newest kept")
accessLogCap = 64 << 20
accessLogNow = { Date() }

// MARK: touchenv log: filters and summary

homePath = testDir + "/home3"
try! FileManager.default.createDirectory(atPath: accessLogDir(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
let t = Date()
for (ago, name, outcome, who, program) in [(3.0 * 86400, "TOKEN", "touch-id", "Terminal", "/bin/zsh"),
                                           (7200.0, "TOKEN", "standing-grant", "Claude Code", "/Users/x/h.sh"),
                                           (3600.0, "TOKEN", "standing-grant", "Claude Code", "/Users/x/h.sh"),
                                           (1800.0, "OTHER", "cancelled", "Codex", "/opt/codex"),
                                           (60.0, "TOKEN", "refused", "Claude Code", "/Users/x/h.sh")] {
    appendLogLine(accessLine(AccessEntry(time: t.addingTimeInterval(-ago), event: "read", secrets: [name], outcome: outcome,
                                         who: who, program: program, intent: "i")), to: accessLogFile(for: t.addingTimeInterval(-ago)))
}
appendLogLine(accessLine(AccessEntry(time: t, event: "grant", secrets: ["TOKEN"], outcome: "standing", who: "Terminal",
                                     program: "/Users/x/h.sh")), to: accessLogFile(for: t))
let all = readAccessLog()
var report = accessReport(all, since: nil, names: [], summary: false)
check(report.count == 6 && report.first!.contains("Terminal") && report.last!.contains("grant"), "all lines, newest last")
report = accessReport(all, since: t.addingTimeInterval(-86400), names: [], summary: false)
check(report.count == 5, "--since 24h")
report = accessReport(all, since: nil, names: ["OTHER"], summary: false)
check(report.count == 1 && report[0].contains("cancelled"), "by name")
report = accessReport(all, since: nil, names: [], summary: true)
check(report.first == "OTHER: 1 read: cancelled 1", "summary per secret: \(report)")
check(report.contains("TOKEN: 4 reads: standing-grant 2, refused 1, touch-id 1"), "outcomes counted, most first: \(report)")
check(report.contains { $0.hasSuffix("3  Claude Code (/Users/x/h.sh)") }, "the program asking most, first")
check(accessReport(all, since: t.addingTimeInterval(1), names: [], summary: true) == ["no reads logged in that time"], "empty")
check(logUsage.contains("two years"), "touchenv log --help states the retention")

print("\(passes) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
