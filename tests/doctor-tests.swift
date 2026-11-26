
// MARK: - touchenv doctor tests (appended to touchenv.swift by tests/run.sh, compiled with -D TOUCHENV_TESTS)
//
// Which values look like secrets, and doctor on a throwaway git repository and home folder: a tracked and an untracked
// .env, templates and node_modules left alone, a symlinked CLAUDE.md never written through, --fix --yes idempotent,
// and no value ever printed. bordercheck is a stand-in; git runs without your global or system config.

let testDir = ProcessInfo.processInfo.environment["TOUCHENV_TEST_DIR"]!
homePath = testDir + "/home"
setenv("GIT_CONFIG_GLOBAL", "/dev/null", 1)
setenv("GIT_CONFIG_NOSYSTEM", "1", 1)

var failures = 0, passes = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if ok { passes += 1 } else { failures += 1; print("FAIL (line \(line)): \(what)") }
}
let fm = FileManager.default
func write(_ path: String, _ text: String) {
    try! fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    try! text.write(toFile: path, atomically: true, encoding: .utf8)
}
func git(_ repo: String, _ arguments: String...) {
    let r = captureOutput(findInPath("git")!, ["-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "-c",
                                               "commit.gpgsign=false"] + arguments)
    precondition(r?.status == 0, "git \(arguments) failed")
}

// Values.
let openai = "sk-proj-TESTa1B2c3D4e5F6g7H8i9J0kLmNo"
let github = "ghp_TESTa1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV"
check(secretLooking(name: "OPENAI_API_KEY", value: openai), "an OpenAI key")
check(secretLooking(name: "ANYTHING", value: github), "a GitHub token under any name")
check(secretLooking(name: "DB_PASSWORD", value: "hunter2hunter2"), "a password by its name")
check(secretLooking(name: "DATABASE_URL", value: "postgres://app:s3cretPass@db:5432/app"), "a password in a URL")
check(!secretLooking(name: "DATABASE_URL", value: "postgres://app:${DB_PASSWORD}@db/app"), "a variable in a URL")
check(!secretLooking(name: "DATABASE_URL", value: "postgres://db:5432/app"), "a URL without a password")
check(!secretLooking(name: "API_KEY", value: "your-api-key-here"), "a placeholder")
check(!secretLooking(name: "API_KEY", value: "${API_KEY}"), "a variable")
check(!secretLooking(name: "API_KEY", value: "short"), "too short")
check(!secretLooking(name: "GOOGLE_APPLICATION_CREDENTIALS", value: "/Users/me/key.json"), "a path")
check(!secretLooking(name: "NEXT_PUBLIC_API_KEY", value: "abcdef123456789"), "a public key")
check(!secretLooking(name: "APP_NAME", value: "something-long-enough"), "not a secret's name")
check(!secretLooking(name: "AUTH_URL", value: "https://auth.example.org/login"), "a URL by a secret-like name")

let parsed = envSecrets("""
# OPENAI_API_KEY=\(openai)
export GITHUB_TOKEN="\(github)"
APP_ENV=production
STRIPE_SECRET='sk_live_TESTa1B2c3D4e5F6g7' # live
EMPTY_TOKEN=
PRIVATE_KEY="-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA
-----END OPENSSH PRIVATE KEY-----"
""")
check(parsed.map(\.name) == ["GITHUB_TOKEN", "STRIPE_SECRET", "PRIVATE_KEY"], "names: \(parsed.map(\.name))")
check(parsed.map(\.line) == [2, 4, 6], "lines: \(parsed.map(\.line))")

check(isEnvFileName(".env") && isEnvFileName(".env.local") && isEnvFileName(".envrc"), "env files")
check(!isEnvFileName(".env.example") && !isEnvFileName(".env.local.sample") && !isEnvFileName(".env.template")
      && !isEnvFileName("env"), "templates and others")

// A repository: a tracked .env, untracked ones, a template, node_modules, a virtualenv named .env.
let repo = testDir + "/repo", home = testDir + "/home", managed = testDir + "/managed/CLAUDE.md"
try? fm.removeItem(atPath: repo)
try? fm.removeItem(atPath: home)
try! fm.createDirectory(atPath: repo, withIntermediateDirectories: true)
git(repo, "init", "-q")
write(repo + "/.env", "SHARED_TOKEN=\(github)\n")
write(repo + "/README", "x\n")
git(repo, "add", ".env", "README")
git(repo, "commit", "-q", "-m", "init")
write(repo + "/.env.local", "APP_ENV=dev\nOPENAI_API_KEY=\(openai)\n")
write(repo + "/api/.env.production", "DB_PASSWORD=hunter2hunter2\n")
write(repo + "/.env.example", "OPENAI_API_KEY=\(openai)\n")
write(repo + "/node_modules/pkg/.env", "OPENAI_API_KEY=\(openai)\n")
write(repo + "/.env-venv/pyvenv.cfg", "home = /usr\n")
write(repo + "/.env-venv/lib/.env", "OPENAI_API_KEY=\(openai)\n")
check(findEnvFiles(root: repo).files == [".env", ".env.local", "api/.env.production"], "found: \(findEnvFiles(root: repo).files)")
check(gitTracked(repo + "/.env") && !gitTracked(repo + "/.env.local"), "tracked or not")

// A home: CLAUDE.md a link to a file another tool keeps, a Codex folder without AGENTS.md.
write(managed, "# managed elsewhere\n")
try! fm.createDirectory(atPath: home + "/.claude", withIntermediateDirectories: true)
try! fm.createDirectory(atPath: home + "/.codex", withIntermediateDirectories: true)
try! fm.createSymbolicLink(atPath: home + "/.claude/CLAUDE.md", withDestinationPath: managed)

func run(fix: Bool, yes: Bool = true, answer: Bool = false, guardProbe: GuardProbe = .output("Off. bordercheck ..."),
         path: String = repo) -> (status: Int32, out: String, asked: Int) {
    var out: [String] = [], asked = 0
    let status = doctor(path: path, fix: fix, yes: yes, home: home, ask: { _ in asked += 1; return answer },
                        guardStatus: { guardProbe }, say: { out.append($0) })
    return (status, out.joined(separator: "\n"), asked)
}

var r = run(fix: false)
check(r.status == 1, "findings: exit 1")
check(r.out.contains("fix   .env.local:2 OPENAI_API_KEY") && r.out.contains("fix   api/.env.production:1 DB_PASSWORD"), r.out)
check(r.out.contains("info  .env:1 SHARED_TOKEN (tracked by git"), "a tracked .env is info")
check(!r.out.contains(".env.example") && !r.out.contains("node_modules") && !r.out.contains("venv"), "skipped: \(r.out)")
check(!r.out.contains(openai) && !r.out.contains(github) && !r.out.contains("hunter2"), "no value printed")
check(r.out.contains("fix   Claude Code: no touchenv rule") && r.out.contains("fix   Codex: no touchenv rule"), r.out)
check(r.out.contains("fix   bordercheck guard is off"), "guard off")
check(!fm.fileExists(atPath: home + "/.codex/AGENTS.md"), "no --fix: nothing written")

// --fix, answered no: nothing written.
r = run(fix: true, yes: false, answer: false)
check(r.asked == 1 && !fm.fileExists(atPath: home + "/.codex/AGENTS.md"), "declined: asked once (the link isn't asked)")

// --fix --yes: Codex gets the block, the link is left alone and the lines to add are shown.
r = run(fix: true)
let agents = (try? String(contentsOfFile: home + "/.codex/AGENTS.md", encoding: .utf8)) ?? ""
check(agents.contains(doctorBegin) && agents.contains("touchenv run") && agents.contains(doctorEnd), "Codex block written")
check((try? String(contentsOfFile: managed, encoding: .utf8)) == "# managed elsewhere\n", "the link's target untouched")
check(r.out.contains("is a link to \(managed)") && r.out.contains(doctorBegin), "the lines to add, shown")
check(r.out.contains("ok    Codex: added"), "Codex fixed")
check(r.status == 1, "still something to fix")

// Again: nothing changes.
r = run(fix: true)
check((try? String(contentsOfFile: home + "/.codex/AGENTS.md", encoding: .utf8)) == agents, "second --fix: no change")
check(r.out.contains("ok    Codex: ~/.codex/AGENTS.md"), r.out)

// A plain file that has some text already: the block goes after it, once.
try! fm.removeItem(atPath: home + "/.claude/CLAUDE.md")
write(home + "/.claude/CLAUDE.md", "# mine")
check((try? appendRule(to: home + "/.claude/CLAUDE.md")) == .added, "appended")
check((try? appendRule(to: home + "/.claude/CLAUDE.md")) == .already, "once")
let claude = (try? String(contentsOfFile: home + "/.claude/CLAUDE.md", encoding: .utf8)) ?? ""
check(claude.hasPrefix("# mine\n\n\(doctorBegin)") && claude.components(separatedBy: doctorBegin).count == 2, claude)

// Clean: the rule in place, the secrets moved out, the guard on.
try! fm.removeItem(atPath: repo + "/.env.local")
try! fm.removeItem(atPath: repo + "/api/.env.production")
r = run(fix: false, guardProbe: .output("In ~/.claude/settings.json:\n  prompt   on (x)\n  command  on (y)\n  output   on (z)\n"))
check(r.status == 0 && r.out.hasSuffix("Nothing to fix."), r.out)
check(run(fix: false, guardProbe: .missing).status == 0, "bordercheck missing is info")
check(run(fix: false, guardProbe: .output("In x:\n  prompt   on (a)\n  command  off (b)\n")).status == 1, "a hook off")

// Errors, and a folder outside git.
check(run(fix: false, path: testDir + "/nope").status == 2, "no such folder")
let plain = testDir + "/plain"
write(plain + "/.env", "API_TOKEN=\(github)\n")
r = run(fix: false, path: plain)
check(r.out.contains("not a git repository") && r.out.contains("fix   .env:1 API_TOKEN"), r.out)

print("\(passes) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
