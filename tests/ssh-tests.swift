
// MARK: - Tests (appended to touchenv.swift by tests/run.sh, compiled with -D TOUCHENV_TESTS)

let testDir = ProcessInfo.processInfo.environment["TOUCHENV_TEST_DIR"]!
let withSSHD = CommandLine.arguments.contains("--sshd")
var failures = 0, passes = 0
FileManager.default.changeCurrentDirectoryPath(testDir)   // sockets go here by relative path (sun_path is short)
homePath = testDir + "/home"
try! FileManager.default.createDirectory(atPath: homePath, withIntermediateDirectories: true)

func check(_ ok: Bool, _ what: String, file: String = #file, line: Int = #line) {
    if ok { passes += 1 } else { failures += 1; print("FAIL (line \(line)): \(what)") }
}

@discardableResult
func sh(_ argv: [String], env extra: [String: String] = [:], stdin: Data? = nil) -> (status: Int32, out: String, err: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: argv[0])
    p.arguments = Array(argv.dropFirst())
    p.currentDirectoryURL = URL(fileURLWithPath: testDir)
    var env = ["PATH": "/usr/bin:/bin", "HOME": homePath]
    env.merge(extra) { _, new in new }
    p.environment = env
    let out = Pipe(), err = Pipe(), input = Pipe()
    p.standardOutput = out
    p.standardError = err
    p.standardInput = stdin == nil ? FileHandle.nullDevice : input
    try! p.run()
    if let stdin { input.fileHandleForWriting.write(stdin); try? input.fileHandleForWriting.close() }
    let o = out.fileHandleForReading.readDataToEndOfFile(), e = err.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: o, as: UTF8.self), String(decoding: e, as: UTF8.self))
}

func bytes(_ path: String) -> [UInt8] { [UInt8](FileManager.default.contents(atPath: path)!) }
func write(_ path: String, _ text: String) { FileManager.default.createFile(atPath: path, contents: Data(text.utf8)) }

// MARK: Keys made by ssh-keygen

struct TestKey { let file: String; let type: String; let bits: String; let passphrase: String?; let format: String? }
let keys = [
    TestKey(file: "ed", type: "ed25519", bits: "", passphrase: nil, format: nil),
    TestKey(file: "ec256", type: "ecdsa", bits: "256", passphrase: nil, format: nil),
    TestKey(file: "ec384", type: "ecdsa", bits: "384", passphrase: nil, format: nil),
    TestKey(file: "ec521", type: "ecdsa", bits: "521", passphrase: nil, format: nil),
    TestKey(file: "rsa2048", type: "rsa", bits: "2048", passphrase: nil, format: nil),
    TestKey(file: "rsa3072", type: "rsa", bits: "3072", passphrase: nil, format: nil),
    TestKey(file: "ed-pass", type: "ed25519", bits: "", passphrase: "correct horse ' \" $x", format: nil),
    TestKey(file: "rsa-pem", type: "rsa", bits: "2048", passphrase: nil, format: "PEM"),
    TestKey(file: "ec-pem-pass", type: "ecdsa", bits: "384", passphrase: "pem pass", format: "PEM"),
    TestKey(file: "rsa-pkcs8", type: "rsa", bits: "2048", passphrase: nil, format: "PKCS8"),
]
for k in keys {
    var argv = ["/usr/bin/ssh-keygen", "-q", "-t", k.type, "-N", k.passphrase ?? "", "-C", "test-\(k.file)", "-f", testDir + "/" + k.file]
    if !k.bits.isEmpty { argv += ["-b", k.bits] }
    if let f = k.format { argv += ["-m", f] }
    let r = sh(argv)
    check(r.status == 0, "ssh-keygen \(k.file): \(r.err)")
}

func keygenFingerprint(_ file: String) -> (bits: Int, fp: String) {
    let parts = sh(["/usr/bin/ssh-keygen", "-l", "-f", testDir + "/" + file + ".pub"]).out.split(separator: " ")
    return (Int(parts[0]) ?? -1, String(parts[1]))
}

var parsed: [String: SSHPrivateKey] = [:]
var storedText: [String: [UInt8]] = [:]
let tempBefore = Set((try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)) ?? [])
for k in keys {
    let path = testDir + "/" + k.file
    let original = bytes(path)
    do {
        var text = original
        switch try parseSSHKeyFile(original) {
        case .openssh(let key):
            check(k.passphrase == nil && k.format == nil, "\(k.file) parsed directly")
            parsed[k.file] = key
        case .convert(let needs):
            check(needs == (k.passphrase != nil), "\(k.file): passphrase detection")
            check(k.passphrase != nil || k.format != nil, "\(k.file) needs converting")
            if k.passphrase != nil {
                do { _ = try convertWithSSHKeygen(original, passphrase: Array("wrong".utf8)); check(false, "\(k.file): wrong passphrase accepted") }
                catch { check("\(error)" == "wrong passphrase", "\(k.file): wrong passphrase message: \(error)") }
            }
            text = try convertWithSSHKeygen(original, passphrase: Array((k.passphrase ?? "").utf8))
            guard case .openssh(let key) = try parseSSHKeyFile(text) else { check(false, "\(k.file): converted isn't OpenSSH"); continue }
            parsed[k.file] = key
        }
        storedText[k.file] = text
        let key = parsed[k.file]!
        let expected = keygenFingerprint(k.file)
        check(key.publicKey.fingerprint == expected.fp, "\(k.file): fingerprint \(key.publicKey.fingerprint) vs \(expected.fp)")
        check(key.publicKey.bits == expected.bits, "\(k.file): bits \(key.publicKey.bits) vs \(expected.bits)")
        let pubLine = String(decoding: bytes(path + ".pub"), as: UTF8.self)
        check(SSHPublicKey(line: pubLine) == key.publicKey, "\(k.file): .pub matches")
        check(bytes(path) == original, "\(k.file): the original file is unchanged")
    } catch { check(false, "\(k.file): \(error)") }
}
let tempAfter = Set((try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)) ?? [])
check(tempAfter.subtracting(tempBefore).filter { $0.hasPrefix("touchenv-ssh-") }.isEmpty, "ssh-keygen's temp folders are removed")

// MARK: Signatures, checked by ssh-keygen -Y verify and the other way round

func sshsigData(_ namespace: String, _ message: [UInt8]) -> [UInt8] {
    var w = SSHWriter()
    w.bytes = Array("SSHSIG".utf8)
    w.string(namespace)
    w.string("")
    w.string("sha512")
    w.string([UInt8](SHA512.hash(data: Data(message))))
    return w.bytes
}
func armorSignature(_ key: SSHPublicKey, _ namespace: String, _ signature: [UInt8]) -> String {
    var w = SSHWriter()
    w.bytes = Array("SSHSIG".utf8)
    w.u32(1)
    w.string(key.blob)
    w.string(namespace)
    w.string("")
    w.string("sha512")
    w.string(signature)
    let b64 = Data(w.bytes).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN SSH SIGNATURE-----\n\(b64)\n-----END SSH SIGNATURE-----\n"
}
let message = Array("the message \(UUID())".utf8)
FileManager.default.createFile(atPath: testDir + "/msg", contents: Data(message))
for (name, key) in parsed.sorted(by: { $0.key < $1.key }) {
    write(testDir + "/allowed", "tester \(key.publicKey.line(comment: ""))\n")
    for flags: UInt32 in key.publicKey.kind == .rsa ? [2, 4] : [0] {
        guard let sig = try? key.sign(sshsigData("test", message), flags: flags) else { check(false, "\(name): sign"); continue }
        check(verifySSHSignature(publicBlob: key.publicKey.blob, signature: sig, data: sshsigData("test", message)), "\(name): own verify")
        check(!verifySSHSignature(publicBlob: key.publicKey.blob, signature: sig, data: sshsigData("other", message)), "\(name): own verify rejects")
        write(testDir + "/msg.sig", armorSignature(key.publicKey, "test", sig))
        let r = sh(["/bin/sh", "-c", "/usr/bin/ssh-keygen -Y verify -f allowed -I tester -n test -s msg.sig < msg"])
        check(r.status == 0, "\(name) flags \(flags): ssh-keygen -Y verify: \(r.out) \(r.err)")
    }
    if key.publicKey.kind == .rsa {
        check((try? key.sign([1, 2, 3], flags: 0)) == nil, "\(name): ssh-rsa (SHA-1) refused")
    }
    // ssh-keygen signs with the file; touchenv's verify accepts it.
    if let k = keys.first(where: { $0.file == name }), k.passphrase == nil, k.format == nil {
        try? FileManager.default.removeItem(atPath: testDir + "/msg.sig")
        let r = sh(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", testDir + "/" + name, "-n", "test", testDir + "/msg"])
        check(r.status == 0, "\(name): ssh-keygen -Y sign")
        if let armored = dearmor(bytes(testDir + "/msg.sig"), label: "SSH SIGNATURE") {
            var rd = SSHReader(armored)
            _ = try? rd.raw(6); _ = try? rd.u32(); _ = try? rd.string(); _ = try? rd.string(); _ = try? rd.string(); _ = try? rd.string()
            let sig = (try? rd.string()) ?? []
            check(verifySSHSignature(publicBlob: key.publicKey.blob, signature: sig, data: sshsigData("test", message)),
                  "\(name): verifies ssh-keygen's signature")
        } else { check(false, "\(name): dearmor ssh-keygen's signature") }
    }
}

// MARK: Hostile key files: never a crash, never a key from garbage

func reArmor(_ body: [UInt8]) -> [UInt8] {
    Array(("-----BEGIN OPENSSH PRIVATE KEY-----\n" + Data(body).base64EncodedString(options: .lineLength64Characters)
           + "\n-----END OPENSSH PRIVATE KEY-----\n").utf8)
}
let edBody = dearmor(bytes(testDir + "/ed"), label: "OPENSSH PRIVATE KEY")!
check((try? parseSSHKeyFile(reArmor(edBody))) != nil, "re-armored key parses")
check((try? parseSSHKeyFile(reArmor(edBody + [0]))) == nil, "trailing byte after the key refused")
check((try? parseSSHKeyFile(bytes(testDir + "/ed") + Array("junk".utf8))) == nil, "text after the armor refused")
check((try? parseSSHKeyFile(Array(bytes(testDir + "/ed").dropLast(40)))) == nil, "truncated file refused")
check((try? parseSSHKeyFile(bytes(testDir + "/ed.pub"))) == nil, "public key file refused")
do {
    // nkeys = 2
    var b = edBody
    let at = 15 + 4 + 4 + 4 + 4 + 4   // magic, "none", "none", "" → nkeys
    b[at + 3] = 2
    check((try? parseSSHKeyFile(reArmor(b))) == nil, "two keys refused")
}
do {
    var unsupported = SSHWriter()
    unsupported.string("sk-ssh-ed25519@openssh.com")
    unsupported.string([UInt8](repeating: 1, count: 32))
    unsupported.string("ssh:")
    do { _ = try SSHPublicKey(blob: unsupported.bytes); check(false, "sk key accepted") }
    catch { check("\(error)".contains("security-key"), "sk key refused clearly: \(error)") }
}
var rng = SystemRandomNumberGenerator()
var fuzzAccepted = 0
for i in 0..<3000 {
    var b = i % 2 == 0 ? edBody : dearmor(bytes(testDir + "/rsa2048"), label: "OPENSSH PRIVATE KEY")!
    for _ in 0..<Int.random(in: 1...4, using: &rng) { b[Int.random(in: 0..<b.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng) }
    if case .openssh(let k)? = try? parseSSHKeyFile(reArmor(b)) {
        fuzzAccepted += 1
        let same = i % 2 == 0 ? parsed["ed"]! : parsed["rsa2048"]!
        if k.publicKey != same.publicKey || k.secret != same.secret { check(false, "a damaged file gave a different key") }
    }
}
print("fuzzed 3000 damaged key files: \(fuzzAccepted) still parsed, each to the same key (the damage hit the comment)")

// MARK: Arithmetic

for _ in 0..<2000 {
    let a = UInt64.random(in: 0...UInt64.max), m = UInt64.random(in: 1...UInt64(UInt32.max) * 4)
    func be(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8(v >> (56 - 8 * $0) & 0xff) } }
    let got = bigMod(be(a), Array(be(m).drop { $0 == 0 })).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    if got != a % m { check(false, "bigMod \(a) % \(m) = \(got)"); break }
}
check(true, "bigMod against UInt64")

// MARK: Grants

do {
    let now = Date()
    let g = Agent.Grant(pid: 100, start: 7, who: "Terminal", secrets: ["SSH_A": Data([1]), "B": Data([2])], expires: now + 60, uses: 2)
    let tree: [(pid: pid_t, start: UInt64)] = [(300, 1), (200, 1), (100, 7)]
    check(Agent.coveringGrant([g], names: ["SSH_A"], above: tree, now: now) == 0, "grant covers a process below the requester")
    check(Agent.coveringGrant([g], names: ["SSH_A", "C"], above: tree, now: now) == nil, "grant doesn't cover another key")
    check(Agent.coveringGrant([g], names: ["SSH_A"], above: [(300, 1), (100, 8)], now: now) == nil, "a reused pid isn't covered")
    check(Agent.coveringGrant([g], names: ["SSH_A"], above: tree, now: now + 61) == nil, "an expired grant covers nothing")
    var used = g
    used.uses = 0
    check(Agent.coveringGrant([used], names: ["SSH_A"], above: tree, now: now) == nil, "a used-up grant covers nothing")
}

// MARK: Command lines, known_hosts, names

do {
    let d = sshDestination(["ssh", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-upload-pack", "'x/y.git'"])
    check(d?.text == "git@github.com" && d?.host == "github.com", "git's ssh command: \(String(describing: d))")
    let p = sshDestination(["ssh", "-p", "2222", "-l", "me", "-i", "key", "-vT", "host.example", "ls"])
    check(p?.text == "me@host.example port 2222" && p?.port == 2222, "ssh -p -l: \(String(describing: p))")
    let u = sshDestination(["ssh", "-p2200", "ssh://u@h.example:2201"])
    check(u?.text == "u@h.example port 2201", "ssh:// form: \(String(describing: u))")
    check(sshDestination(["ssh", "-V"]) == nil, "no destination")
    check(sshName(fromPath: "/x/.ssh/id_ed25519") == "SSH_ID_ED25519", "name from id_ed25519")
    check(sshName(fromPath: "work-github.pem") == "SSH_WORK_GITHUB", "name from work-github.pem")
    check(validName(sshName(fromPath: "2fa key")), "derived names are valid")
    check(shellQuoted("/Users/a/.ssh/id_rsa") == "/Users/a/.ssh/id_rsa" && shellQuoted("/a b/c'd") == "'/a b/c'\\''d'", "rm quoting")
}
do {
    let host = parsed["ed"]!.publicKey
    write(testDir + "/kh", "# comment\nplain.example,[alias.example]:2222 \(host.line(comment: "x"))\n")
    check(knownHostNames(for: host.blob, host: "plain.example", port: nil, files: [testDir + "/kh"]).typed, "plain known_hosts entry")
    check(knownHostNames(for: host.blob, host: "alias.example", port: 2222, files: [testDir + "/kh"]).typed, "[host]:port entry")
    check(!knownHostNames(for: host.blob, host: "other.example", port: nil, files: [testDir + "/kh"]).typed, "other host")
    check(knownHostNames(for: host.blob, host: "other.example", port: nil, files: [testDir + "/kh"]).names.first == "plain.example", "names listed")
    sh(["/usr/bin/ssh-keygen", "-H", "-f", testDir + "/kh"])
    check(knownHostNames(for: host.blob, host: "plain.example", port: nil, files: [testDir + "/kh"]).typed, "hashed known_hosts entry")
    check(!knownHostNames(for: host.blob, host: "nope.example", port: nil, files: [testDir + "/kh"]).typed, "hashed entry, other host")
}

// MARK: The agent protocol, against OpenSSH's clients

let identities = ["ed", "ec384", "rsa2048"].map { SSHIdentity(name: "SSH_" + $0.uppercased(), key: parsed[$0]!.publicKey, synced: $0 == "ed") }
final class Recorder {
    let lock = NSLock()
    var asks: [SSHAsk] = []
    var inside = 0, maxInside = 0
    var refuse = false
    var cover = false
}
let recorder = Recorder()
var logLines: [String] = []
let server = SSHAgentServer(
    identities: { identities },
    covered: { a in
        recorder.lock.lock(); defer { recorder.lock.unlock() }
        return recorder.cover ? storedText[String(a.identity.name.dropFirst(4)).lowercased()] : nil
    },
    ask: { a in
        recorder.lock.lock()
        recorder.asks.append(a)
        recorder.inside += 1
        recorder.maxInside = max(recorder.maxInside, recorder.inside)
        let refuse = recorder.refuse
        recorder.lock.unlock()
        usleep(150_000)
        recorder.lock.lock(); recorder.inside -= 1; recorder.lock.unlock()
        if refuse { return .failure(.refused("test says no")) }
        return .success(storedText[String(a.identity.name.dropFirst(4)).lowercased()]!)
    },
    log: { line in recorder.lock.lock(); logLines.append(line); recorder.lock.unlock() },
    knownHostFiles: [testDir + "/known_hosts"])
func listen(_ path: String) -> Int32 {
    unlink(path)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    var address = socketAddress(path)
    let bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    precondition(bound == 0 && listen(fd, 16) == 0)
    return fd
}
signal(SIGPIPE, SIG_IGN)
let listener = listen("agent.sock")
Thread.detachNewThread { server.serve(listener) }
let agentEnv = ["SSH_AUTH_SOCK": "agent.sock"]

do {
    let l = sh(["/usr/bin/ssh-add", "-l"], env: agentEnv)
    check(l.status == 0 && identities.allSatisfy { l.out.contains($0.key.fingerprint) && l.out.contains($0.name) }, "ssh-add -l: \(l.out)\(l.err)")
    let big = sh(["/usr/bin/ssh-add", "-L"], env: agentEnv)
    check(big.out.contains(identities[0].key.line(comment: identities[0].name)), "ssh-add -L")
    check(sh(["/usr/bin/ssh-add", "-D"], env: agentEnv).status != 0, "ssh-add -D refused")
    check(sh(["/usr/bin/ssh-add", testDir + "/ec256"], env: agentEnv).status != 0, "ssh-add KEY refused")
    check(sh(["/usr/bin/ssh-add", "-d", testDir + "/ed.pub"], env: agentEnv).status != 0, "ssh-add -d refused")
    check(logLines.contains { $0.contains("add, remove or lock") }, "refusals logged")
}
for name in ["ed", "ec384", "rsa2048"] {
    try? FileManager.default.removeItem(atPath: testDir + "/msg.sig")
    let r = sh(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", testDir + "/\(name).pub", "-n", "git", testDir + "/msg"], env: agentEnv)
    check(r.status == 0, "\(name): ssh-keygen -Y sign through touchenv's agent: \(r.err)")
    write(testDir + "/allowed", "tester \(parsed[name]!.publicKey.line(comment: ""))\n")
    let v = sh(["/bin/sh", "-c", "/usr/bin/ssh-keygen -Y verify -f allowed -I tester -n git -s msg.sig < msg"])
    check(v.status == 0, "\(name): agent signature verifies: \(v.out)\(v.err)")
}
check(recorder.asks.count == 3 && recorder.asks.allSatisfy { $0.purpose == .sshsig(namespace: "git") }, "each signature asked; purpose git")
check(recorder.asks.first?.action == "sign a git commit or tag", "git signing is named")
check(recorder.asks.first?.via.contains("ssh-keygen") == true, "via ssh-keygen: \(recorder.asks.first?.via ?? [])")
do {
    // Several at once: they queue, one prompt at a time.
    recorder.asks = []
    let group = DispatchGroup()
    var ok = 0
    let okLock = NSLock()
    for i in 0..<4 {
        group.enter()
        DispatchQueue.global().async {
            let sigPath = testDir + "/c\(i).sig"
            try? FileManager.default.removeItem(atPath: sigPath)
            FileManager.default.createFile(atPath: testDir + "/c\(i)", contents: Data(message))
            let r = sh(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", testDir + "/ed.pub", "-n", "git", testDir + "/c\(i)"], env: agentEnv)
            okLock.lock(); if r.status == 0 { ok += 1 }; okLock.unlock()
            group.leave()
        }
    }
    group.wait()
    check(ok == 4 && recorder.maxInside == 1, "4 concurrent requests: \(ok) signed, at most \(recorder.maxInside) prompt at once")
    // A refusal fails the client; a grant (covered) signs without asking.
    recorder.refuse = true
    try? FileManager.default.removeItem(atPath: testDir + "/msg.sig")
    check(sh(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", testDir + "/ed.pub", "-n", "git", testDir + "/msg"], env: agentEnv).status != 0,
          "refused prompt: no signature")
    recorder.refuse = false
    recorder.cover = true
    let before = recorder.asks.count
    try? FileManager.default.removeItem(atPath: testDir + "/msg.sig")
    check(sh(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", testDir + "/ed.pub", "-n", "git", testDir + "/msg"], env: agentEnv).status == 0
          && recorder.asks.count == before, "covered by a grant: signed with no prompt")
    recorder.cover = false
}

// Raw protocol: framing and hostile input.
func rawConnection() -> Int32 { connectUnix("agent.sock")! }
do {
    let fd = rawConnection()
    check(agentRequest(fd, [99]) == SSHAgentServer.failure, "unknown message: failure")
    check(agentRequest(fd, [11, 0]) == SSHAgentServer.failure, "identities with trailing byte: failure")
    var w = SSHWriter()
    w.u8(27); w.string("query")
    check(agentRequest(fd, w.bytes) == SSHAgentServer.failure, "unknown extension: failure")
    w = SSHWriter(); w.u8(22); w.string("pw")
    check(agentRequest(fd, w.bytes) == SSHAgentServer.failure, "lock: failure")
    w = SSHWriter(); w.u8(13); w.string(identities[0].key.blob); w.string(sshsigData("git", message)); w.u32(0); w.u8(0)
    let before = recorder.asks.count
    check(agentRequest(fd, w.bytes) == SSHAgentServer.failure && recorder.asks.count == before, "sign with trailing byte: failure, no prompt")
    w = SSHWriter(); w.u8(13); w.u32(0xffff_fff0)
    check(agentRequest(fd, w.bytes) == SSHAgentServer.failure, "sign with a lying length: failure")
    // A session-bind whose signature doesn't verify taints the connection.
    w = SSHWriter(); w.u8(27); w.string("session-bind@openssh.com"); w.string(identities[0].key.blob); w.string([1, 2, 3])
    w.string(try! parsed["ed"]!.sign([9, 9, 9])); w.u8(0)
    check(agentRequest(fd, w.bytes) == SSHAgentServer.failure, "bad session-bind refused")
    w = SSHWriter(); w.u8(13); w.string(identities[0].key.blob); w.string(sshsigData("git", message)); w.u32(0)
    check(agentRequest(fd, w.bytes) == SSHAgentServer.failure, "tainted connection signs nothing")
    close(fd)
    // A good session-bind, then a login for another session: refused.
    let fd2 = rawConnection()
    let hostKey = parsed["ec384"]!
    let session = [UInt8](repeating: 7, count: 32)
    w = SSHWriter(); w.u8(27); w.string("session-bind@openssh.com"); w.string(hostKey.publicKey.blob); w.string(session)
    w.string(try! hostKey.sign(session)); w.u8(0)
    check(agentRequest(fd2, w.bytes) == SSHAgentServer.success, "good session-bind accepted")
    func login(_ sid: [UInt8], key: [UInt8]) -> [UInt8] {
        var d = SSHWriter()
        d.string(sid); d.u8(50); d.string("me"); d.string("ssh-connection"); d.string("publickey"); d.u8(1)
        d.string("ssh-ed25519"); d.string(key)
        return d.bytes
    }
    w = SSHWriter(); w.u8(13); w.string(identities[0].key.blob); w.string(login([8, 8, 8], key: identities[0].key.blob)); w.u32(0)
    check(agentRequest(fd2, w.bytes) == SSHAgentServer.failure, "login for another session refused")
    w = SSHWriter(); w.u8(13); w.string(identities[0].key.blob); w.string(login(session, key: identities[1].key.blob)); w.u32(0)
    check(agentRequest(fd2, w.bytes) == SSHAgentServer.failure, "login naming another key refused")
    w = SSHWriter(); w.u8(13); w.string(identities[0].key.blob); w.string(login(session, key: identities[0].key.blob)); w.u32(0)
    let reply = agentRequest(fd2, w.bytes)
    check(reply?.first == 14, "login for the bound session signs")
    check(recorder.asks.last?.serverNote?.contains(hostKey.publicKey.fingerprint) == true, "prompt names the server key: \(recorder.asks.last?.serverNote ?? "nil")")
    w = SSHWriter(); w.u8(27); w.string("session-bind@openssh.com"); w.string(hostKey.publicKey.blob); w.string(session)
    w.string(try! hostKey.sign(session)); w.u8(0)
    check(agentRequest(fd2, w.bytes) == SSHAgentServer.failure, "a second bind after a login bind refused")
    close(fd2)
    // Oversized frame: the connection is dropped.
    let fd3 = rawConnection()
    _ = writeFull(fd3, [0x7f, 0xff, 0xff, 0xff, 11])
    check(readFull(fd3, 4) == nil, "oversized frame closes the connection")
    close(fd3)
    // Random garbage: the server survives.
    for _ in 0..<300 {
        let f = rawConnection()
        let n = Int.random(in: 1...64)
        var junk = (0..<n).map { _ in UInt8.random(in: 0...255) }
        junk = [0, 0, 0, UInt8(n)] + junk
        _ = writeFull(f, junk)
        shutdown(f, SHUT_WR)
        _ = readFull(f, 5)
        close(f)
    }
    check(sh(["/usr/bin/ssh-add", "-l"], env: agentEnv).status == 0, "server still answers after 300 garbage connections")
}
do {
    var pair: [Int32] = [0, 0]
    socketpair(AF_UNIX, SOCK_STREAM, 0, &pair)
    check(!clientLeft(pair[0]), "client still there")
    close(pair[1])
    check(clientLeft(pair[0]), "client gone")
    close(pair[0])
}

// MARK: A real ssh login through the agent (--sshd): a throwaway sshd on a high port, nothing of yours involved

if withSSHD {
    let port = Int.random(in: 40000...60000)
    sh(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", testDir + "/hostkey"])
    write(testDir + "/authorized_keys", identities.map { $0.key.line(comment: $0.name) }.joined(separator: "\n") + "\n")
    chmod(testDir + "/authorized_keys", 0o600)
    write(testDir + "/sshd_config", """
        Port \(port)
        ListenAddress 127.0.0.1
        HostKey \(testDir)/hostkey
        PidFile \(testDir)/sshd.pid
        AuthorizedKeysFile \(testDir)/authorized_keys
        StrictModes no
        UsePAM no
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        PubkeyAuthentication yes

        """)
    let sshd = Process()
    sshd.executableURL = URL(fileURLWithPath: "/usr/sbin/sshd")
    sshd.arguments = ["-D", "-e", "-f", testDir + "/sshd_config"]
    let sshdErr = Pipe()
    sshd.standardError = sshdErr
    sshd.standardOutput = FileHandle.nullDevice
    try! sshd.run()
    usleep(700_000)
    let user = NSUserName()
    func login(_ keyName: String) -> (status: Int32, out: String, err: String) {
        sh(["/usr/bin/ssh", "-F", "/dev/null", "-p", "\(port)", "-o", "IdentityFile=\(testDir)/\(keyName).pub",
            "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=\(testDir)/known_hosts", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "UpdateHostKeys=no", "-o", "AddKeysToAgent=no", "\(user)@127.0.0.1", "echo logged-in"], env: agentEnv)
    }
    recorder.asks = []
    let r = login("ed")
    check(r.status == 0 && r.out.contains("logged-in"), "ssh login with Ed25519 through touchenv's agent: \(r.err)")
    if let a = recorder.asks.last {
        check(a.binds.count == 1, "ssh sent session-bind@openssh.com (\(a.binds.count))")
        check(a.destination?.text == "\(user)@127.0.0.1 port \(port)", "destination from ssh's arguments: \(a.destination?.text ?? "nil")")
        check(a.serverNote?.hasPrefix("Server: 127.0.0.1, its key as in your known_hosts") == true, "server note: \(a.serverNote ?? "nil")")
        if case .login(let u, _, let hk) = a.purpose { check(u == user && hk != nil, "login purpose, hostbound: \(u)") } else { check(false, "login purpose") }
        print("sign prompt for the ssh login would read:\n  \(sshPromptText(a).title.replacingOccurrences(of: "\u{1}", with: "**").replacingOccurrences(of: "\u{2}", with: "**"))")
        sshPromptText(a).notes.forEach { print("  " + $0) }
    } else { check(false, "the login asked") }
    recorder.asks = []
    let rsa = login("rsa2048")
    check(rsa.status == 0, "ssh login with RSA (rsa-sha2) through touchenv's agent: \(rsa.err)")
    check(login("ec384").status == 0, "ssh login with ECDSA P-384 through touchenv's agent")
    recorder.refuse = true
    let no = login("ed")
    check(no.status != 0 && no.err.contains("Permission denied"), "refused prompt: ssh fails: \(no.err)")
    recorder.refuse = false
    sshd.terminate()
    sshd.waitUntilExit()
}

// MARK: touchenv ssh load: into a throwaway ssh-agent

do {
    let agent = Process()
    agent.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-agent")
    agent.arguments = ["-D", "-a", "stock.sock"]
    agent.currentDirectoryURL = URL(fileURLWithPath: testDir)
    agent.standardOutput = FileHandle.nullDevice
    agent.standardError = FileHandle.nullDevice
    try! agent.run()
    var fd: Int32? = nil
    for _ in 0..<50 where fd == nil { usleep(50_000); fd = connectUnix("stock.sock") }
    if let fd {
        check(peerIsApple(fd), "Apple's ssh-agent passes the peer check")
        let key = parsed["ec521"]!
        check(agentRequest(fd, addIdentityMessage(key, comment: "SSH_EC521", seconds: 120)) == SSHAgentServer.success, "added with a lifetime")
        let rsaKey = parsed["rsa3072"]!
        check(agentRequest(fd, addIdentityMessage(rsaKey, comment: "SSH_RSA3072", seconds: 120)) == SSHAgentServer.success, "RSA added")
        let l = sh(["/usr/bin/ssh-add", "-l"], env: ["SSH_AUTH_SOCK": "stock.sock"])
        check(l.out.contains(key.publicKey.fingerprint) && l.out.contains("SSH_EC521"), "ssh-add -l shows it: \(l.out)")
        try? FileManager.default.removeItem(atPath: testDir + "/msg.sig")
        let s = sh(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", testDir + "/rsa3072.pub", "-n", "test", testDir + "/msg"], env: ["SSH_AUTH_SOCK": "stock.sock"])
        write(testDir + "/allowed", "tester \(rsaKey.publicKey.line(comment: ""))\n")
        check(s.status == 0 && sh(["/bin/sh", "-c", "/usr/bin/ssh-keygen -Y verify -f allowed -I tester -n test -s msg.sig < msg"]).status == 0,
              "the loaded RSA key signs in ssh-agent")
        var w = SSHWriter(); w.u8(18); w.string(key.publicKey.blob)
        check(agentRequest(fd, w.bytes) == SSHAgentServer.success, "unloaded")
        check(agentRequest(fd, w.bytes) == SSHAgentServer.failure, "unloading again: not loaded")
        close(fd)
    } else { check(false, "throwaway ssh-agent") }
    agent.terminate()
    agent.waitUntilExit()
    let own = connectUnix("agent.sock")!
    check(!peerIsApple(own), "a non-Apple agent fails the peer check")
    close(own)
}

// MARK: The steps after touchenv ssh add (temp home, temp ~/.ssh/config)

do {
    var lines: [String] = []
    let keyPath = homePath + "/.ssh/id_ed25519"
    sshNextSteps(name: "SSH_ID_ED25519", keyPath: keyPath, state: SSHSetupState(agentInstalled: false, configText: nil),
                 interactive: false, install: { check(false, "installed without asking") }, addLines: { check(false, "edited unasked"); return nil },
                 ask: { _, _ in check(false, "asked when not interactive"); return false }, say: { lines.append($0) })
    let text = lines.joined(separator: "\n")
    let order = ["touchenv ssh agent install", "IdentityAgent", "ssh -T git@github.com", "touchenv ssh load --for 8h SSH_ID_ED25519", "rm ~/.ssh/id_ed25519"]
        .map { text.range(of: $0)?.lowerBound }
    check(order.allSatisfy { $0 != nil } && zip(order, order.dropFirst()).allSatisfy { $0! < $1! }, "steps in order:\n\(text)")
    check(!FileManager.default.fileExists(atPath: sshConfigPath()), "non-interactive: config untouched")
    print("--- after ssh add, nothing set up, no terminal ---\n\(text)\n---")

    lines = []
    sshNextSteps(name: "SSH_ID_ED25519", keyPath: keyPath,
                 state: SSHSetupState(agentInstalled: true, configText: "Host *\n  IdentityAgent \(sshConfigSocket)\n"),
                 interactive: true, ask: { _, _ in check(false, "asked when all is set"); return false }, say: { lines.append($0) })
    check(lines.contains { $0.contains("is set up") } && !lines.joined().contains("agent install"), "all set: one line")

    // Interactive, yes to both: a fake install, the real config edit on the temp home.
    try! FileManager.default.createDirectory(atPath: homePath + "/.ssh", withIntermediateDirectories: true)
    let original = "Host old\n  User someone"   // no final newline
    write(sshConfigPath(), original)
    lines = []
    var questions: [String] = []
    sshNextSteps(name: "SSH_ID_ED25519", keyPath: keyPath, state: SSHSetupState(agentInstalled: false, configText: original),
                 interactive: true, install: {}, ask: { q, _ in questions.append(q); return true }, say: { lines.append($0) })
    let edited = String(decoding: bytes(sshConfigPath()), as: UTF8.self)
    check(questions.count == 2 && questions[1].contains("~/.ssh/config"), "two questions, the second names the file: \(questions)")
    check(lines.contains { $0.contains("IdentityAgent") } && lines.firstIndex { $0.contains("IdentityAgent") }! < lines.count, "the lines are shown before asking")
    check(edited.hasPrefix(original + "\n") && edited.contains("IdentityAgent \(sshConfigSocket)"), "appended:\n\(edited)")
    check(String(decoding: bytes(sshConfigPath() + ".touchenv-backup"), as: UTF8.self) == original, "backup made first")
    check(sshConfigState(edited).pointsHere, "detected afterwards")
    check(try! removeSSHConfigLines() && String(decoding: bytes(sshConfigPath()), as: UTF8.self) == original + "\n", "uninstall --config removes exactly those lines")
    // Interactive, no to both.
    lines = []
    sshNextSteps(name: "SSH_ID_ED25519", keyPath: keyPath, state: SSHSetupState(agentInstalled: false, configText: original),
                 interactive: true, install: { check(false, "installed on no") }, ask: { _, _ in false }, say: { lines.append($0) })
    check(lines.contains { $0.contains("touchenv ssh agent install") }, "declined: the steps are printed")
    check(sshConfigState("Host x\n IdentityAgent ~/other.sock\n").otherAgent, "another agent noticed")
}

// MARK: The LaunchAgent

do {
    let plist = sshAgentPlistText(executable: "/Applications/touchenv.app/Contents/MacOS/touchenv")
    write(testDir + "/agent.plist", plist)
    let lint = sh(["/usr/bin/plutil", "-lint", testDir + "/agent.plist"])
    check(lint.status == 0, "LaunchAgent plist is valid: \(lint.out)")
    let mode = sh(["/usr/bin/plutil", "-extract", "Sockets.SSH.SockPathMode", "raw", testDir + "/agent.plist"]).out
    check(mode.trimmingCharacters(in: .whitespacesAndNewlines) == "384", "socket mode 0600")
}

print("\(passes) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
