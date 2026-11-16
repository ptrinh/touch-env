
// MARK: - grant --totp tests (appended to touchenv.swift by tests/run.sh, compiled with -D TOUCHENV_TESTS)
//
// The code arithmetic against RFC 6238's own vectors, what a code is accepted for (once, this step and the one
// before, the lock after five wrong ones), and approveWithTOTP run as a child (--child) with the key in a file and
// the clock given: no Keychain, no window, no authenticator app.

final class FileTOTPStore: TOTPStore {
    let path: String
    var failSaves = false
    init(_ path: String) { self.path = path }
    func load() -> TOTPLoad {
        guard let data = FileManager.default.contents(atPath: path) else { return .none }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let state = try? decoder.decode(TOTPState.self, from: data) else { return .unreadable }
        return .state(state)
    }
    func save(_ state: TOTPState) -> Bool {
        if failSaves { return false }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return FileManager.default.createFile(atPath: path, contents: try! encoder.encode(state))
    }
    func remove() -> Bool { (try? FileManager.default.removeItem(atPath: path)) != nil }
}

let rfcSecret = Data("12345678901234567890".utf8)

if CommandLine.arguments.count >= 3, CommandLine.arguments[1] == "--child" {
    // --child CODE: approve a grant of $NAMES for $SECONDS and $USES at time $NOW with the key file $TOTP_FILE.
    let env = ProcessInfo.processInfo.environment
    homePath = env["TEST_HOME"]!
    syncedLookup = { ["SYNCED_A": true, "SYNCED_B": true, "LOCAL_L": false][$0] }
    let store = FileTOTPStore(env["TOTP_FILE"]!)
    store.failSaves = env["FAIL_SAVES"] == "1"
    totpStore = store
    let names = env["NAMES"]!.split(separator: ",").map(String.init)
    currentAttempt = AccessAttempt(event: "grant", secrets: names, who: "Tester", program: "/bin/tester", intent: "test intent")
    approveWithTOTP(names: names, code: CommandLine.arguments[2], seconds: Double(env["SECONDS"]!)!, uses: Int(env["USES"]!)!,
                    now: Date(timeIntervalSince1970: Double(env["NOW"]!)!))
    print("APPROVED")
    exit(0)
}

let testDir = ProcessInfo.processInfo.environment["TOUCHENV_TEST_DIR"]!
homePath = testDir + "/home"
try! FileManager.default.createDirectory(atPath: homePath, withIntermediateDirectories: true)
var failures = 0, passes = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if ok { passes += 1 } else { failures += 1; print("FAIL (line \(line)): \(what)") }
}

// MARK: The arithmetic

check(base32Encode(rfcSecret) == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "base32 of the RFC key")
check(base32Encode(Data([0xff])) == "74" && base32Encode(Data()) == "" && base32Encode(Data("fo".utf8)) == "MZXQ", "base32, odd lengths")
for (time, eight) in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"), (1234567890, "89005924"),
                      (2000000000, "69279037"), (20000000000, "65353130")] {
    let step = totpStep(Date(timeIntervalSince1970: TimeInterval(time)))
    check(totpCode(secret: rfcSecret, step: step, digits: 8) == eight, "RFC 6238 vector at \(time)")
    check(totpCode(secret: rfcSecret, step: step) == String(eight.suffix(6)), "six digits at \(time)")
}
check(totpURI(secret: rfcSecret, account: "an@My Mac")
        == "otpauth://totp/touchenv%3Aan@My%20Mac?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=touchenv&algorithm=SHA1&digits=6&period=30",
      "the otpauth link: \(totpURI(secret: rfcSecret, account: "an@My Mac"))")
check(sameDigits("123456", "123456") && !sameDigits("123456", "123457") && !sameDigits("12345", "123456"), "sameDigits")

// MARK: What a code is accepted for

let t0 = Date(timeIntervalSince1970: 1_800_000_015)   // the middle of a step
let step0 = totpStep(t0)
func fresh() -> TOTPState { TOTPState(secret: rfcSecret, created: t0, maxSeconds: 3600, maxUses: 10) }
func code(_ offset: Int64) -> String { totpCode(secret: rfcSecret, step: step0 + offset) }
throttleUnit = 1

do {
    var s = fresh()
    check(checkTOTP(code(0), state: &s, now: t0) == .ok && s.lastStep == step0 && s.lastUsed == t0, "the code shown now")
    check(checkTOTP(code(0), state: &s, now: t0) == .used && s.failures == 0, "the same code again: used, not counted as wrong")
    check(checkTOTP(code(-1), state: &s, now: t0) == .used, "an older code after a newer one was taken")
    check(checkTOTP(code(1), state: &s, now: t0.addingTimeInterval(30)) == .ok, "the next code, in its own step")
}
do {
    var s = fresh()
    check(checkTOTP(code(-1), state: &s, now: t0) == .ok && s.lastStep == step0 - 1, "the code of the step before")
    check(checkTOTP(code(0), state: &s, now: t0) == .ok, "then this step's")
}
do {
    var s = fresh()
    check(checkTOTP(code(1), state: &s, now: t0) == .wrong, "a code from the next step isn't taken early")
    check(checkTOTP(code(-2), state: &s, now: t0.addingTimeInterval(5)) == .wrong, "nor one two steps old")
    check(s.failures == 2 && s.lastStep == 0, "both counted")
}
do {
    var s = fresh()
    for bad in ["", "12345", "1234567", "12345a", "１２３４５６", " 123456", "12 3456"] {
        check(checkTOTP(bad, state: &s, now: t0) == .malformed, "not six digits: [\(bad)]")
    }
    check(s == fresh(), "malformed codes change nothing")
}
do {
    // Wrong codes: 1 s, 2 s, 4 s, 8 s between tries, the fifth locks; the right code doesn't open a lock.
    var s = fresh()
    var now = t0
    let wrong = code(0) == "000000" ? "111111" : "000000"
    check(checkTOTP(wrong, state: &s, now: now) == .wrong && s.failures == 1, "first wrong code")
    check(checkTOTP(code(0), state: &s, now: now) == .wait(1), "the right code must wait too")
    check(s.failures == 1 && s.lastStep == 0, "waiting counts nothing and uses nothing")
    for (n, delay) in [(2, 1.0), (3, 2.0), (4, 4.0)] {
        now = now.addingTimeInterval(delay)
        check(checkTOTP(wrong, state: &s, now: now) == .wrong && s.failures == n, "wrong code \(n)")
    }
    check(checkTOTP(wrong, state: &s, now: now.addingTimeInterval(7)) == .wait(1), "8 s after the fourth")
    now = now.addingTimeInterval(8)
    check(checkTOTP(wrong, state: &s, now: now) == .locked && s.failures == 5 && s.locked, "the fifth locks")
    let later = now.addingTimeInterval(86400)
    check(checkTOTP(totpCode(secret: rfcSecret, step: totpStep(later)), state: &s, now: later) == .locked, "locked for the right code too, a day on")
    check(describeTOTP(s, now: later).contains { $0.hasPrefix("LOCKED") }, "status says locked")
}
do {
    var s = fresh()
    let wrong = code(0) == "000000" ? "111111" : "000000"
    _ = checkTOTP(wrong, state: &s, now: t0)
    check(checkTOTP(code(0), state: &s, now: t0.addingTimeInterval(1)) == .ok && s.failures == 0 && s.notBefore == .distantPast,
          "a right code clears the count")
}

// MARK: approveWithTOTP, as touchenv grant --totp runs it

let keyFile = testDir + "/totp.json"
let me = processPath(getpid())!
func approve(_ code: String, names: String = "SYNCED_A,SYNCED_B", seconds: Int = 3600, uses: Int = 10, at now: Date = t0,
             failSaves: Bool = false) -> (status: Int32, out: String, err: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: me)
    p.arguments = ["--child", code]
    p.environment = ["TEST_HOME": homePath, "TOTP_FILE": keyFile, "NAMES": names, "SECONDS": "\(seconds)", "USES": "\(uses)",
                     "NOW": "\(now.timeIntervalSince1970)", "FAIL_SAVES": failSaves ? "1" : "0"]
    let out = Pipe(), err = Pipe()
    p.standardOutput = out
    p.standardError = err
    try! p.run()
    let o = out.fileHandleForReading.readDataToEndOfFile(), e = err.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: o, as: UTF8.self), String(decoding: e, as: UTF8.self))
}
let fileStore = FileTOTPStore(keyFile)
func stored() -> TOTPState? { if case .state(let s) = fileStore.load() { return s } else { return nil } }

do {
    let r = approve(code(0))
    check(r.status == 1 && r.err.contains("codes aren't set up") && r.err.contains("touchenv totp setup"), "not set up: \(r.err)")
}
check(fileStore.save(fresh()), "key file written")
do {
    let r = approve(code(0), names: "SYNCED_A,LOCAL_L")
    check(r.status == 1 && r.err.contains("synced through iCloud Keychain only") && r.err.contains("LOCAL_L"), "a local secret: \(r.err)")
    check(!r.err.contains("SYNCED_A is"), "names only the local one")
    let m = approve(code(0), names: "NOPE")
    check(m.status == 1 && m.err.contains("no secret named NOPE"), "a missing secret")
    let long = approve(code(0), seconds: 3601)
    check(long.status == 1 && long.err.contains("at most 1 hour and 10 times"), "longer than setup allows: \(long.err)")
    let many = approve(code(0), uses: 11)
    check(many.status == 1 && many.err.contains("at most 1 hour"), "more uses than setup allows")
    check(stored() == fresh(), "none of those refusals used the code up or counted a wrong one")
}
do {
    let r = approve(code(0), failSaves: true)
    check(r.status == 1 && !r.out.contains("APPROVED") && r.err.contains("nothing approved"), "a code that can't be marked used approves nothing: \(r.err)")
}
do {
    let r = approve(code(0))
    check(r.status == 0 && r.out.contains("APPROVED"), "the right code approves: \(r.err)")
    check(stored()?.lastStep == step0, "and is marked used")
    let again = approve(code(0))
    check(again.status == 1 && again.err.contains("already used"), "the same code a second time: \(again.err)")
    let bad = approve("12345")
    check(bad.status == 1 && bad.err.contains("six digits"), "five digits")
    let wrong = approve(code(0) == "000000" ? "111111" : "000000", at: t0.addingTimeInterval(1))
    check(wrong.status == 1 && wrong.err.contains("wrong code"), "a wrong code: \(wrong.err)")
    check(stored()?.failures == 1, "counted in the key file")
    let soon = approve(code(1), at: t0.addingTimeInterval(1.5))
    check(soon.status == 1 && soon.err.contains("too many wrong codes"), "must wait after a wrong one: \(soon.err)")
}
do {
    var locked = fresh()
    locked.failures = totpTries
    check(fileStore.save(locked), "locked key file written")
    let r = approve(code(0))
    check(r.status == 1 && r.err.contains("locked") && r.err.contains("touchenv totp unlock"), "locked: \(r.err)")
}
do {
    try! Data("not json".utf8).write(to: URL(fileURLWithPath: keyFile))
    let r = approve(code(0))
    check(r.status == 1 && r.err.contains("can't read or save"), "an unreadable key approves nothing: \(r.err)")
}
do {
    let log = readAccessLog()
    check(log.contains { $0.event == "grant" && $0.outcome == ReadOutcome.refused && $0.note == "wrong code" }, "the wrong code is in the access log")
    check(log.contains { $0.note == "code already used" } && log.contains { $0.note.hasPrefix("local secret") }, "and the other refusals")
    check(!log.contains { $0.note.contains(code(0)) || $0.intent.contains(code(0)) }, "never a code")
}

print("\(passes) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
