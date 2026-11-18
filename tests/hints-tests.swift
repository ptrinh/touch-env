
// MARK: - Agent hint and "why not" tests (appended to touchenv.swift by tests/run.sh, compiled with -D TOUCHENV_TESTS)
//
// What an AI agent is told after a prompt (approved, declined, stopped), why a prompt ended, and when a secret is
// called missing. No Keychain, no Touch ID, no window: the access log lives in the test folder, and missingSecret runs
// in a copy of this binary (--missing-probe) since it exits.

let testDir = ProcessInfo.processInfo.environment["TOUCHENV_TEST_DIR"]!
homePath = testDir + "/home"

// The probe: missingSecret with the given listing status, as an agent (or not).
if CommandLine.arguments.count == 4, CommandLine.arguments[1] == "--missing-probe" {
    syncedListingStatus = OSStatus(CommandLine.arguments[2])!
    agentHints = CommandLine.arguments[3] == "agent"
    missingSecret("MSSTORE_CLIENT_SECRET")
}

var failures = 0, passes = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if ok { passes += 1 } else { failures += 1; print("FAIL (line \(line)): \(what)") }
}

// Why a prompt ended.
check(notApprovedReason(cancelled: true, code: nil, locked: false) == "declined", "Cancel clicked")
check(notApprovedReason(cancelled: false, code: .userCancel, locked: false) == "declined", "userCancel")
check(notApprovedReason(cancelled: false, code: .systemCancel, locked: true) == "the Mac locked while the prompt was open",
      "systemCancel, locked")
check(notApprovedReason(cancelled: false, code: .systemCancel, locked: false)?.contains("another Touch ID prompt") == true,
      "systemCancel: another prompt")
check(notApprovedReason(cancelled: false, code: .appCancel, locked: false) == "the prompt was closed before anyone answered",
      "appCancel")
check(notApprovedReason(cancelled: false, code: .notInteractive, locked: false)?.contains("can't show a prompt") == true,
      "notInteractive")
check(notApprovedReason(cancelled: false, code: nil, locked: false) == nil, "nothing known")
check(notApprovedReason(cancelled: false, code: nil, locked: true) == "the Mac is locked", "nothing known, locked")

// "no secret named" only when the Keychain answered in full.
check(uncheckedReason(listing: errSecSuccess, locked: true) == nil, "listing complete")
check(uncheckedReason(listing: errSecItemNotFound, locked: false) == nil, "no synced secrets at all")
check(uncheckedReason(listing: errSecInteractionNotAllowed, locked: true)?.hasPrefix("the Mac is locked") == true,
      "locked Mac: interaction not allowed")
check(uncheckedReason(listing: errSecInteractionNotAllowed, locked: false)?.contains("another prompt") == true,
      "interaction not allowed, unlocked")
check(uncheckedReason(listing: -34018, locked: false) == "keychain error -34018", "another error")
check(keychainProblem(errSecUserCanceled, locked: false).contains("cancelled"), "user cancelled")
check(keychainProblem(errSecAuthFailed, locked: false).hasPrefix("not approved"), "auth failed")

func probe(_ status: OSStatus, _ who: String) -> (status: Int32, err: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
    p.arguments = ["--missing-probe", String(status), who]
    p.environment = ["TOUCHENV_TEST_DIR": testDir]
    let err = Pipe()
    p.standardError = err
    p.standardOutput = FileHandle.nullDevice
    try! p.run()
    let data = err.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}
var r = probe(errSecSuccess, "person")
check(r.status == 1 && r.err == "touchenv: no secret named MSSTORE_CLIENT_SECRET\n", "really missing: \(r.err)")
r = probe(-34018, "person")
check(r.status == 1 && r.err.hasPrefix("touchenv: couldn't check whether MSSTORE_CLIENT_SECRET is stored: ")
      && r.err.contains("keychain error -34018") && !r.err.contains("no secret named") && !r.err.contains("away"),
      "listing failed: \(r.err)")
r = probe(errSecInteractionNotAllowed, "agent")
check(r.status == 1 && r.err.contains("couldn't check whether") && r.err.contains(awayHint), "listing failed, agent: \(r.err)")
r = probe(errSecSuccess, "agent")
check(r.err == "touchenv: no secret named MSSTORE_CLIENT_SECRET\n", "really missing, agent: no hint: \(r.err)")

// Counting an app's recent prompts, from the access log.
let now = Date(timeIntervalSince1970: 1_800_000_000)
func read(_ minutesAgo: Double, _ names: [String], _ outcome: String, who: String = "Claude Code", event: String = "read") -> AccessEntry {
    AccessEntry(time: now.addingTimeInterval(-minutesAgo * 60), event: event, secrets: names, outcome: outcome, who: who)
}
let entries = [
    read(45, ["OLD_KEY"], ReadOutcome.touchID),                         // too long ago
    read(20, ["ASC_KEY_PATH"], ReadOutcome.touchID),
    read(15, ["MSSTORE_CLIENT_SECRET"], ReadOutcome.cancelled),
    read(12, ["ASC_KEY_PATH"], ReadOutcome.grant),                      // no prompt
    read(10, ["OTHER"], ReadOutcome.touchID, who: "Terminal"),          // another app
    read(9, ["X"], "timed", event: "grant"),                            // not a read
    read(1, ["BORDERCHECK_SIGNING_KEY", "ASC_KEY_PATH"], ReadOutcome.touchID),
]
let recent = recentPrompts(entries, who: "Claude Code", now: now)
check(recent.map(\.secrets) == [["ASC_KEY_PATH"], ["MSSTORE_CLIENT_SECRET"], ["BORDERCHECK_SIGNING_KEY", "ASC_KEY_PATH"]],
      "recent prompts: \(recent.map(\.secrets))")
let many = approvedHint(who: "Claude Code", names: ["BORDERCHECK_SIGNING_KEY"], recent: recent)
check(many == "touchenv: Claude Code has asked for Touch ID 3 times in 30 minutes (ASC_KEY_PATH, MSSTORE_CLIENT_SECRET, "
      + "BORDERCHECK_SIGNING_KEY). Ask the person once for the rest: touchenv grant --intent \"<why>\" --for 2h --uses 20 KEY ...",
      "several prompts: \(many)")
let first = approvedHint(who: "Claude Code", names: ["ASC_KEY_PATH"], recent: [recent[0]])
check(first.hasPrefix("touchenv: tip: if this task will need more secrets later, ask once now: touchenv grant --intent")
      && first.contains("--for 2h --uses 20 ASC_KEY_PATH OTHER_KEY ...") && !first.contains("\n"), "first prompt: \(first)")
check(!awayHint.contains("\n") && awayHint.contains("Don't retry in a loop"), "away hint is one line")

// recentAccessEntries reads the log files that can hold the last 30 minutes, across a month's end.
let monthStart = logCalendar.date(from: DateComponents(year: 2027, month: 3, day: 1))!
accessLogNow = { monthStart.addingTimeInterval(-10 * 60) }
logAccess(AccessEntry(event: "read", secrets: ["A"], outcome: ReadOutcome.touchID, who: "Claude Code"))
accessLogNow = { monthStart.addingTimeInterval(5 * 60) }
logAccess(AccessEntry(event: "read", secrets: ["B"], outcome: ReadOutcome.touchID, who: "Claude Code"))
let logged = recentAccessEntries(since: monthStart.addingTimeInterval(-25 * 60), now: monthStart.addingTimeInterval(5 * 60))
check(logged.map(\.secrets) == [["A"], ["B"]], "both months: \(logged.map(\.secrets))")
check(recentAccessEntries(since: monthStart, now: monthStart.addingTimeInterval(5 * 60)).map(\.secrets) == [["B"]], "since")

print("\(passes) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
