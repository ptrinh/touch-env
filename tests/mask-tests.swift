
// MARK: - Masking tests (appended to touchenv.swift by tests/run.sh, compiled with -D TOUCHENV_TESTS)
//
// The Masker on its own, and pumpMasked on the output of a real child process (/bin/sh), as touchenv run uses it.
// The secrets are test values.

var failures = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if !ok { failures += 1; print("FAIL line \(line): \(what)") }
}
func text(_ d: Data) -> String { String(decoding: d, as: UTF8.self) }

let token = "ghp_TESTa1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"
let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----\n"
let needles = maskNeedles([Data(token.utf8), Data(pem.utf8), Data("abc".utf8)])

// Whole values, and each long line of a multi-line one; values under 6 bytes are left alone.
check(needles.contains(Data(token.utf8)) && needles.contains(Data("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC".utf8)), "needles")
check(!needles.contains(Data("abc".utf8)), "a short value is not masked")

// One chunk.
var m = Masker(needles)
var out = m.feed(Data("token=\(token) and abc\n".utf8)) + m.finish()
check(text(out) == "token=***REDACTED*** and abc\n", "one chunk: \(text(out))")

// Split across chunks at every point: the same result, and nothing but a possible secret's start is held back.
for cut in 1..<(token.count + 8) {
    let whole = Data("x \(token) y".utf8)
    var mk = Masker(needles)
    let first = mk.feed(whole.prefix(cut))
    let second = mk.feed(whole.dropFirst(cut))
    let all = first + second + mk.finish()
    check(text(all) == "x ***REDACTED*** y", "split at \(cut): \(text(all))")
}
var held = Masker(needles)
check(text(held.feed(Data("line one\nline two\n".utf8))) == "line one\nline two\n", "ordinary output is not held back")
check(text(held.feed(Data("almost gh".utf8))) == "almost ", "the start of a token is held back")
check(text(held.feed(Data("x\n".utf8))) == "ghx\n", "and let go when it is not one")

// A key printed whole, or one line of it.
var mk2 = Masker(needles)
out = mk2.feed(Data(("cat key:\n" + pem + "line: MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n").utf8)) + mk2.finish()
check(text(out) == "cat key:\n***REDACTED***line: ***REDACTED***\n", "key: \(text(out))")

// Through a pipe from a real command that writes the token in two pieces, with a pause between them.
let process = Process()
process.executableURL = URL(fileURLWithPath: "/bin/sh")
let half = token.count / 2
process.arguments = ["-c", "printf 'start %s' \"$A\"; sleep 0.2; printf '%s end\\n' \"$B\"; printf 'to stderr %s\\n' \"$A$B\" >&2"]
process.environment = ["A": String(token.prefix(half)), "B": String(token.dropFirst(half))]
let outPipe = Pipe(), errPipe = Pipe(), sink = Pipe(), errSink = Pipe()
process.standardOutput = outPipe
process.standardError = errPipe
let pumps = DispatchGroup()
pumpMasked(from: outPipe.fileHandleForReading, to: sink.fileHandleForWriting, needles: needles, done: pumps)
pumpMasked(from: errPipe.fileHandleForReading, to: errSink.fileHandleForWriting, needles: needles, done: pumps)
let started = Date()
try! process.run()
process.waitUntilExit()
check(pumps.wait(timeout: .now() + 5) == .success, "the pumps end when the command does")
check(Date().timeIntervalSince(started) < 3, "no wait for the 5-second limit: \(Date().timeIntervalSince(started))s")
try! sink.fileHandleForWriting.close()
try! errSink.fileHandleForWriting.close()
check(text(sink.fileHandleForReading.readDataToEndOfFile()) == "start ***REDACTED*** end\n", "stdout through the pipe")
check(text(errSink.fileHandleForReading.readDataToEndOfFile()) == "to stderr ***REDACTED***\n", "stderr through the pipe")

// get: a line break for a terminal only, and never a second one.
check(text(secretOutput(Data("abc".utf8), terminal: true)) == "abc\n", "terminal")
check(text(secretOutput(Data("abc".utf8), terminal: false)) == "abc", "pipe")
check(text(secretOutput(Data("abc\n".utf8), terminal: true)) == "abc\n", "already ends a line")

// The note before a key starts syncing names the price and the way back.
check(syncNote.contains("not by macOS's Touch ID lock") && syncNote.contains("touchenv unsync NAME") && !syncNote.contains("\\"),
      "sync note: \(syncNote)")

// When to mask: not a terminal, or an AI assistant runs it.
check(shouldMask(isTerminal: false, environment: [:]), "a pipe")
check(!shouldMask(isTerminal: true, environment: ["TERM_PROGRAM": "iTerm.app"]), "a person's terminal")
check(shouldMask(isTerminal: true, environment: ["CLAUDECODE": "1"]), "Claude Code in a terminal of its own")
check(shouldMask(isTerminal: true, environment: ["AI_AGENT": "x"]), "another assistant")
check(shouldMask(isTerminal: true, environment: [:], agent: true), "an assistant told by its process")

if failures == 0 { print("ok: masking") } else { print("\(failures) failure(s)"); exit(1) }
