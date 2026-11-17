// permwatch-root: yönetici modu yardımcısı (root olarak çalışır).
//
// Güvenlik tasarımı:
//  - Komut almaz (soket, argümanla komut yok); yalnızca sabit, salt-okunur bir komut listesini
//    çalıştırır ve sonuçları root'a ait klasöre, başlatan kullanıcıya ait 0600 dosyalar olarak yazar.
//  - Tek "girdi", kullanıcının kendi klasöründeki capture.on dosyasının var olup olmadığıdır:
//    yalnızca paket yakalamayı açar/kapatır, içeriği okunmaz. Paketler eksiksiz kaydedilir.
//  - Başlatan permwatch süreci kapanınca kendiliğinden çıkar.
//  - Servis modunda (--daemon, SMAppService ile kurulur): konsoldaki kullanıcı için çalışır ve yalnızca
//    permwatch açıkken (uygulamanın birkaç saniyede bir güncellediği "alive" dosyası tazeyken) veri toplar;
//    aksi halde boşta bekler.
//
// Kullanım: permwatch-root <üst-pid>   |   permwatch-root --daemon
import Darwin
import Foundation
import Security

let outDir = "/Library/Application Support/permwatch"
let outPath = outDir + "/root.json"
let packetsPath = outDir + "/packets.jsonl"
let pcapPath = outDir + "/capture.pcap"

let daemon = CommandLine.arguments.dropFirst().first == "--daemon"
guard daemon || (CommandLine.arguments.count >= 2 && Int32(CommandLine.arguments[1]) != nil) else {
    FileHandle.standardError.write(Data("kullanım: permwatch-root <üst-pid> | --daemon\n".utf8))
    exit(64)
}
let parent: Int32 = daemon ? 0 : Int32(CommandLine.arguments[1])!
guard getuid() == 0 else {
    FileHandle.standardError.write(Data("root olarak çalışmalı\n".utf8))
    exit(77)
}

// Çıktıların sahibi: başlatan kullanıcı (servis modunda konsoldaki kullanıcı). Başka kullanıcılar okuyamaz.
var owner: uid_t = 0, ownerGid: gid_t = 0
var home = "/var/empty"
var flagPath = "", alivePath = "", dnsFlagPath = ""

func setOwner(_ uid: uid_t) {
    guard let pw = getpwuid(uid) else { return }
    owner = uid; ownerGid = pw.pointee.pw_gid
    home = String(cString: pw.pointee.pw_dir)
    flagPath = home + "/Library/Application Support/permwatch/capture.on"
    dnsFlagPath = home + "/Library/Application Support/permwatch/dnswatch.on"
    alivePath = home + "/Library/Application Support/permwatch/alive"
}

if daemon {
    var st = stat()
    guard stat("/dev/console", &st) == 0 else { exit(65) }
    setOwner(st.st_uid)
} else {
    var bsd = proc_bsdinfo()
    guard proc_pidinfo(parent, PROC_PIDTBSDINFO, 0, &bsd, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 else { exit(65) }
    setOwner(bsd.pbi_uid)
}

// MARK: - Engelleme (pf)
//
// Kullanıcının klasöründeki "blocklist" dosyasından YALNIZCA geçerli IP adresleri okunur (inet_pton,
// en fazla 1000); kurallar sabit şablondan üretilir ve macOS'un zaten tanımlı "com.apple/*" bağlantı
// noktasına yüklenir (pf.conf değişmez). pf, başka programları bozmamak için jetonla açılır.

let pfAnchor = "com.apple/250.permwatch"
var pfToken: String?
var blockStamp: Double = -1
var blockStatus: [String: Any] = [:]

func validIP(_ s: String) -> Bool {
    var a4 = in_addr(), a6 = in6_addr()
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1
}

func readBlocklist() -> (stamp: Double, ips: [String]) {
    // Servis modunda liste yalnızca imzası doğrulanmış uygulamadan (XPC) gelir; kullanıcı dosyasına bakılmaz.
    if daemon {
        let ips = control.snapshot().block.filter(validIP).prefix(1000)
        return (Double(ips.joined(separator: ",").hashValue & 0xffffffff) + 1, Array(ips))
    }
    let path = home + "/Library/Application Support/permwatch/blocklist"
    var st = stat()
    guard lstat(path, &st) == 0, st.st_uid == owner, (st.st_mode & S_IFMT) == S_IFREG, st.st_size < 64 * 1024,
          let text = try? String(contentsOfFile: path, encoding: .utf8) else { return (0, []) }
    var ips: [String] = []
    for line in text.split(separator: "\n") {
        let s = line.trimmingCharacters(in: .whitespaces)
        if validIP(s), !ips.contains(s) { ips.append(s) }
        if ips.count >= 1000 { break }
    }
    return (Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9, ips)
}

func pfctl(_ args: [String], stdin: String? = nil) -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
    p.arguments = args
    let out = Pipe(), inp = Pipe()
    p.standardOutput = out; p.standardError = out
    if stdin != nil { p.standardInput = inp }
    guard (try? p.run()) != nil else { return (-1, "pfctl") }
    if let s = stdin { inp.fileHandleForWriting.write(Data(s.utf8)); try? inp.fileHandleForWriting.close() }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

func applyBlocklist() {
    let (stamp, ips) = readBlocklist()
    guard stamp != blockStamp else { return }
    blockStamp = stamp
    if ips.isEmpty {
        _ = pfctl(["-a", pfAnchor, "-F", "all"])
        if let t = pfToken { _ = pfctl(["-X", t]); pfToken = nil }
        blockStatus = ["count": 0]
        return
    }
    let rules = """
    table <permwatch_block> persist { \(ips.joined(separator: ", ")) }
    block drop out quick to <permwatch_block>
    block drop in quick from <permwatch_block>

    """
    let (rc, msg) = pfctl(["-a", pfAnchor, "-f", "-"], stdin: rules)
    if rc != 0 { blockStatus = ["count": 0, "error": String(msg.prefix(300))]; return }
    if pfToken == nil {
        let (_, out) = pfctl(["-E"])
        pfToken = out.split(separator: "\n").first { $0.contains("Token") }?.split(separator: ":").last?
            .trimmingCharacters(in: .whitespaces)
    }
    blockStatus = ["count": ips.count]
}

/// Servis modunda: permwatch son 20 saniyede "buradayım" dedi mi? (Dosya kullanıcıya ait olmalı.)
func appAlive() -> Bool {
    // Servis modunda: imzası doğrulanmış uygulama son 20 saniyede XPC ile durum gönderdi mi?
    if daemon { return Date().timeIntervalSince(control.snapshot().lastSync) < 20 }
    var st = stat()
    guard lstat(alivePath, &st) == 0, st.st_uid == owner, (st.st_mode & S_IFMT) == S_IFREG else { return false }
    return Date().timeIntervalSince1970 - Double(st.st_mtimespec.tv_sec) < 20
}

func run(_ tool: String, _ args: [String]) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: tool)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()   // önce oku (64 KB tamponu)
    p.waitUntilExit()
    return String(decoding: data, as: UTF8.self)
}

/// Çıktı boşsa nedenini de döndürür (tanı için): (stdout, stderr'in sonu).
func runWithError(_ tool: String, _ args: [String]) -> (String, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: tool)
    p.arguments = args
    let pipe = Pipe()
    let errPath = outDir + "/.stderr.tmp"
    FileManager.default.createFile(atPath: errPath, contents: nil, attributes: [.posixPermissions: 0o600])
    let errHandle = FileHandle(forWritingAtPath: errPath)
    p.standardOutput = pipe
    p.standardError = errHandle ?? FileHandle.nullDevice
    do { try p.run() } catch { return ("", "\(error)") }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    try? errHandle?.close()
    let err = (FileManager.default.contents(atPath: errPath)).map { String(decoding: $0.suffix(300), as: UTF8.self) } ?? ""
    unlink(errPath)
    return (String(decoding: data, as: UTF8.self), p.terminationStatus == 0 ? err : "exit \(p.terminationStatus): \(err)")
}

// MARK: - Kendi imzamız ve paketteki motorların doğrulanması

/// Yardımcının geçerli imzasındaki Team ID (geçici imzalı geliştirme derlemelerinde nil).
let ownTeam: String? = {
    var me: SecCode?
    guard SecCodeCopySelf([], &me) == errSecSuccess, let me, SecCodeCheckValidity(me, [], nil) == errSecSuccess else { return nil }
    var st: SecStaticCode?
    guard SecCodeCopyStaticCode(me, [], &st) == errSecSuccess, let st else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(st, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let d = info as? [String: Any], let t = d[kSecCodeInfoTeamIdentifier as String] as? String,
          t.allSatisfy({ $0.isLetter || $0.isNumber }) else { return nil }
    return t
}()

/// root olarak çalıştırılacak program bizimle aynı geliştiricinin geçerli imzasını taşıyor mu?
/// (Uygulama paketi kullanıcının yazabildiği bir yerdeyse içindeki motor değiştirilmiş olabilir.)
/// Yardımcının kendisi imzasızsa (geliştirme derlemesi) denetlenemez: izin verilir.
func signedByUs(_ path: String) -> Bool {
    guard let team = ownTeam else { return true }
    var st: SecStaticCode?, req: SecRequirement?
    let r = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &st) == errSecSuccess, let st,
          SecRequirementCreateWithString(r as CFString, [], &req) == errSecSuccess else { return false }
    return SecStaticCodeCheckValidity(st, SecCSFlags(rawValue: kSecCSStrictValidate), req) == errSecSuccess
}

/// Uygulama güncellenince (paketteki yardımcı dosyası değişince) eski sürümle çalışmaya devam etme:
/// çık, launchd yenisini başlatsın. Yalnızca servis modunda.
let ownExe: String = {
    var buf = [CChar](repeating: 0, count: 4096)
    return proc_pidpath(getpid(), &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : ""
}()
let ownStamp: (ino_t, Int) = {
    var st = stat()
    return stat(ownExe, &st) == 0 ? (st.st_ino, st.st_mtimespec.tv_sec) : (0, 0)
}()
func binaryReplaced() -> Bool {
    guard daemon, !ownExe.isEmpty, ownStamp.0 != 0 else { return false }
    var st = stat()
    // Dosya geçici olarak yoksa (derleme/güncelleme sürerken) bekle; varsa ve farklıysa yenisi gelmiş.
    guard stat(ownExe, &st) == 0 else { return false }
    return st.st_ino != ownStamp.0 || st.st_mtimespec.tv_sec != ownStamp.1
}

// MARK: - XPC: uygulamadan gelen istekler

/// Uygulamanın istediği durum. Yalnızca imzası doğrulanmış permwatch uygulaması, oturum sahibi olarak yazabilir.
final class Control: NSObject, NSXPCListenerDelegate, RootControl, @unchecked Sendable {
    struct State {
        var capture = false
        var dns = false
        var block: [String] = []
        /// VPN isteği (JSON). Uygulama kapalıyken de geçerli kalır: root'a ait dosyada saklanır.
        var vpn: String?
        var lastSync = Date.distantPast
    }
    private let lock = NSLock()
    private var state = State()
    static let vpnStore = outDir + "/vpn/want.json"

    override init() {
        super.init()
        // Önceki çalışmadan kalan VPN isteği (root'a ait, yalnızca root okuyabilir).
        var st = stat()
        if lstat(Self.vpnStore, &st) == 0, st.st_uid == 0, (st.st_mode & S_IFMT) == S_IFREG,
           let d = FileManager.default.contents(atPath: Self.vpnStore) {
            state.vpn = String(data: d, encoding: .utf8)
        }
    }

    func snapshot() -> State { lock.lock(); defer { lock.unlock() }; return state }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // Yalnızca aynı geliştiricinin imzaladığı permwatch uygulaması ve konsoldaki kullanıcı.
        guard let team = ownTeam, c.effectiveUserIdentifier == owner else { return false }
        c.setCodeSigningRequirement(RootXPC.clientRequirement(team: team))
        c.exportedInterface = NSXPCInterface(with: RootControl.self)
        c.exportedObject = self
        c.resume()
        return true
    }

    func sync(_ data: Data, reply: @escaping (Bool) -> Void) {
        guard data.count < 512 * 1024, let j = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            reply(false); return
        }
        lock.lock()
        state.capture = j["capture"] as? Bool ?? false
        state.dns = j["dns"] as? Bool ?? false
        state.block = ((j["block"] as? [String]) ?? []).filter(validIP)
        var vpnChanged = false
        if j.keys.contains("vpn") {
            let new: String? = (j["vpn"] as? [String: Any]).flatMap { try? JSONSerialization.data(withJSONObject: $0) }
                .flatMap { String(data: $0, encoding: .utf8) }
            vpnChanged = new != state.vpn
            state.vpn = new
        }
        state.lastSync = Date()
        let v = state.vpn
        lock.unlock()
        if vpnChanged {
            try? FileManager.default.createDirectory(atPath: outDir + "/vpn", withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
            if let v {
                let fd = open(Self.vpnStore + ".tmp", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600)
                if fd >= 0 {
                    let d = Data(v.utf8)
                    _ = d.withUnsafeBytes { write(fd, $0.baseAddress, d.count) }
                    close(fd)
                    rename(Self.vpnStore + ".tmp", Self.vpnStore)
                }
            } else {
                unlink(Self.vpnStore)
            }
        }
        reply(true)
    }
}

let control = Control()

/// root'a ait klasörde, sembolik bağlantı izlemeden, kullanıcıya ait 0600 dosya açar.
func openOwned(_ path: String, append: Bool) -> Int32 {
    let fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | (append ? O_APPEND : O_TRUNC), 0o600)
    if fd >= 0 { fchown(fd, owner, ownerGid); fchmod(fd, 0o600) }
    return fd
}

func writeAtomic(_ data: Data, to path: String) {
    let tmp = path + ".tmp"
    unlink(tmp)
    let fd = openOwned(tmp, append: false)
    guard fd >= 0 else { return }
    _ = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
    close(fd)
    rename(tmp, path)
}

/// KERN_PROCARGS2: argümanlar ve DYLD_* ortam değişkenleri (root olarak her süreç için).
func procArgs(_ pid: Int32) -> (args: [String], dyld: [String])? {
    var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
    var argmax: Int32 = 0
    var size = MemoryLayout<Int32>.size
    guard sysctl(&mib, 2, &argmax, &size, nil, 0) == 0 else { return nil }
    var buf = [UInt8](repeating: 0, count: Int(argmax))
    size = buf.count
    mib = [CTL_KERN, KERN_PROCARGS2, pid]
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return nil }
    let argc = Int(buf.withUnsafeBytes { $0.load(as: Int32.self) })
    var i = 4
    while i < size && buf[i] != 0 { i += 1 }
    while i < size && buf[i] == 0 { i += 1 }
    var strings: [String] = []
    var start = i
    while i < size {
        if buf[i] == 0 {
            if i == start { break }
            strings.append(String(decoding: buf[start..<i], as: UTF8.self))
            start = i + 1
        }
        i += 1
    }
    let args = Array(strings.prefix(argc).prefix(24))
    let dyld = strings.dropFirst(argc).filter { $0.hasPrefix("DYLD_") }
    return (args, Array(dyld))
}

// MARK: - Paket yakalama (PKTAP: her paketle birlikte gönderen süreç)

final class Capture {
    private let engine: CaptureEngine
    private let lock = NSLock()
    private var pending: [Packet] = []
    private var fd: Int32 = -1
    private var written = 0
    let device: String
    var skipped: Int { engine.skipped }
    var linkType: Int32 { engine.linkType }

    /// PKTAP (süreç bilgisi) açılamadıysa nedeni; yakalama yine de süreç bilgisiz sürer.
    private(set) var pktapError: String?

    init(payload: Bool) throws {
        var lastError = "pktap"
        for (dev, pk) in [("pktap,all", true), ("pktap", true), ("pktap,all", false), ("pktap", false)] {
            let e = CaptureEngine(device: dev)
            e.wantPktap = pk
            do {
                try e.open()
                e.storePayload = payload
                engine = e
                device = dev
                if !pk { pktapError = lastError }
                unlink(packetsPath)
                fd = openOwned(packetsPath, append: true)
                if e.dump(to: pcapPath) { chown(pcapPath, owner, ownerGid); chmod(pcapPath, 0o600) }
                e.onPacket = { [weak self] p in
                    guard let self else { return }
                    self.lock.lock(); self.pending.append(p); self.lock.unlock()
                }
                e.start()
                return
            } catch {
                lastError = (error as? CaptureError)?.message ?? "\(error)"
            }
        }
        throw CaptureError(message: lastError)
    }

    /// Biriken paket özetlerini JSON Lines olarak ekler; 32 MB'ı aşınca dosyayı yeniden başlatır.
    func flush() {
        lock.lock(); let batch = pending; pending.removeAll(keepingCapacity: true); lock.unlock()
        guard !batch.isEmpty, fd >= 0 else { return }
        let enc = JSONEncoder()
        var out = Data()
        for p in batch { if let d = try? enc.encode(p) { out.append(d); out.append(0x0a) } }
        if written + out.count > 32 << 20 {
            close(fd); unlink(packetsPath)
            fd = openOwned(packetsPath, append: true); written = 0
        }
        _ = out.withUnsafeBytes { write(fd, $0.baseAddress, out.count) }
        written += out.count
    }

    func stop() {
        engine.stop()
        flush()
        if fd >= 0 { close(fd); fd = -1 }
        // Özet dosyası yalnızca canlı aktarım içindi; yakalama bitince diskte bırakma.
        unlink(packetsPath)
    }
}

// MARK: - DNS izleme (zararlı sunucu kontrolü için: hangi adres hangi alan adına ait)

/// Yalnızca DNS yanıtlarını okur: alan adı → adresler ve soran süreç. Paket içeriği saklanmaz,
/// diske yalnızca son birkaç bin eşleme (root.json içinde, kullanıcıya ait) yazılır.
final class DNSWatch {
    private let engine: CaptureEngine
    private let lock = NSLock()
    private var map: [String: (host: String, proc: String, ts: Double)] = [:]

    init() throws {
        var lastError = "pktap"
        for pk in [true, false] {
            let e = CaptureEngine(device: "pktap,all")
            e.wantPktap = pk
            e.filter = "port 53"
            e.storePayload = false
            e.maxPerSecond = 400
            do { try e.open(snaplen: 1500) } catch { lastError = (error as? CaptureError)?.message ?? "\(error)"; continue }
            engine = e
            e.onPacket = { [weak self] p in
                guard let self, let host = p.host?.lowercased(), let ips = p.dns, !ips.isEmpty else { return }
                self.lock.lock()
                for ip in ips where validIP(ip) { self.map[ip] = (host, p.proc ?? "", p.ts) }
                if self.map.count > 6000 {
                    for (k, _) in self.map.sorted(by: { $0.value.ts < $1.value.ts }).prefix(2000) { self.map[k] = nil }
                }
                self.lock.unlock()
            }
            e.start()
            return
        }
        throw CaptureError(message: lastError)
    }

    var snapshot: [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        return map.map { ["ip": $0.key, "host": $0.value.host, "proc": $0.value.proc, "ts": $0.value.ts] }
    }

    func stop() { engine.stop() }
}

try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true,
                                         attributes: [.posixPermissions: 0o755])
chown(outDir, 0, 0); chmod(outDir, 0o755)
// Eski sürümün herkese açık bıraktığı dosyayı kaldır.
unlink(outPath)

var slow: [String: String] = [:]
let slowLock = NSLock()
var slowBusy = false
var lsofError = ""
var medium: [String: Any] = [:]
var capture: Capture?
var captureError: String?
var tick = 0
var lastSig = ""
var dnsWatch: DNSWatch?
var dnsError: String?
let vpn = VPNRunner()
vpnGlobal = vpn
// XPC: uygulamanın istekleri (yalnızca servis modunda; launchd'nin kayıtlı Mach servisi).
var xpcListener: NSXPCListener?
if daemon {
    let l = NSXPCListener(machServiceName: RootXPC.rootService)
    l.delegate = control
    l.resume()
    xpcListener = l
}
signal(SIGTERM) { _ in vpnShutdown(); exit(0) }
while true {
    // VPN, permwatch penceresi kapalıyken de bağlı kalır; yalnızca kullanıcı "Bağlantıyı kes" deyince biter.
    vpn.tick()
    if daemon {
        // Konsoldaki kullanıcı değiştiyse ona geç; permwatch kapalıysa boşta bekle.
        var cs = stat()
        if stat("/dev/console", &cs) == 0, cs.st_uid != owner, cs.st_uid != 0 {
            capture?.stop(); capture = nil; captureError = nil
            dnsWatch?.stop(); dnsWatch = nil; dnsError = nil
            vpn.shutdown()
            setOwner(cs.st_uid)
        }
        if !appAlive() {
            if capture != nil { capture?.stop(); capture = nil; captureError = nil }
            dnsWatch?.stop(); dnsWatch = nil; dnsError = nil
            tick = 0
            sleep(3)
            continue
        }
    } else if kill(parent, 0) != 0 && errno == ESRCH {
        // Başlatan uygulama kapandıysa çık.
        capture?.stop(); vpn.shutdown(); exit(0)
    }

    // Paket yakalama: kullanıcı "Yakalamayı Başlat" dediğinde capture.on oluşur.
    var st = stat()
    let wanted = daemon ? control.snapshot().capture : (lstat(flagPath, &st) == 0 && st.st_uid == owner)
    if wanted, capture == nil, captureError == nil {
        do { capture = try Capture(payload: true) } catch { captureError = (error as? CaptureError)?.message ?? "\(error)" }
    } else if !wanted {
        capture?.stop(); capture = nil; captureError = nil
    }
    capture?.flush()
    applyBlocklist()

    // DNS izleme: kullanıcı "Zararlı sunucu kontrolü"nü açık tuttuğunda dnswatch.on vardır.
    var dst = stat()
    let dnsWanted = daemon ? control.snapshot().dns : (lstat(dnsFlagPath, &dst) == 0 && dst.st_uid == owner)
    if dnsWanted, dnsWatch == nil, dnsError == nil {
        do { dnsWatch = try DNSWatch() } catch { dnsError = (error as? CaptureError)?.message ?? "\(error)" }
    } else if !dnsWanted, dnsWatch != nil || dnsError != nil {
        dnsWatch?.stop(); dnsWatch = nil; dnsError = nil
    }

    // Uygulama güncellendiyse eski sürümle kalma.
    if tick % 30 == 0, binaryReplaced() { capture?.stop(); dnsWatch?.stop(); vpn.shutdown(); exit(0) }

    // Yavaş değişenler dakikada bir, AYRI iş parçacığında: bu komutlar (özellikle 3 günlük günlük taraması)
    // dakikalarca sürebilir; ana döngüyü tutarlarsa durum dosyası bayatlar ve uygulama yardımcıyı
    // "çalışmıyor" sanar (paket yakalama ve VPN de o sırada yanıt vermez).
    slowLock.lock()
    let startSlow = tick % 60 == 0 && !slowBusy
    if startSlow { slowBusy = true }
    slowLock.unlock()
    if startSlow {
        let withLog = tick % 3600 == 0
        DispatchQueue.global(qos: .utility).async {
            var r: [String: String] = [:]
            r["btm"] = run("/usr/bin/sfltool", ["dumpbtm"])
            r["cron"] = run("/usr/bin/crontab", ["-l", "-u", "root"])
            r["profiles"] = run("/usr/bin/profiles", ["show", "-type", "configuration"])
            slowLock.lock(); slow.merge(r) { _, b in b }; slowLock.unlock()
            // Apple XProtect / XProtect Remediator: son 3 günün tespit ve temizleme kayıtları (saatte bir).
            if withLog {
                let log = run("/usr/bin/log", ["show", "--last", "3d", "--style", "compact", "--predicate",
                    "(subsystem BEGINSWITH \"com.apple.XProtect\" OR process BEGINSWITH \"XProtect\") AND (eventMessage CONTAINS[c] \"remediat\" OR eventMessage CONTAINS[c] \"detected\" OR eventMessage CONTAINS[c] \"malware found\")"])
                let x = String(log.split(separator: "\n").filter { !$0.hasPrefix("Timestamp") && !$0.contains("Filtering the log") }.suffix(200).joined(separator: "\n"))
                slowLock.lock(); slow["xprotect"] = x; slowLock.unlock()
            }
            slowLock.lock(); slowBusy = false; slowLock.unlock()
        }
    }
    // Süreçler ve bağlantılar 5 saniyede bir.
    if tick % 5 == 0 {
        var procs: [String: [String: [String]]] = [:]
        let n = proc_listallpids(nil, 0)
        var pids = [Int32](repeating: 0, count: Int(max(n, 0)) + 64)
        let got = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size)))
        for pid in pids.prefix(max(0, got)) where pid > 0 {
            if let a = procArgs(pid) { procs[String(pid)] = ["args": a.args, "dyld": a.dyld] }
        }
        medium["procs"] = procs
        let (ls, lsErr) = runWithError("/usr/sbin/lsof", ["-nP", "-i", "-F", "pcfPnT"])
        medium["lsof"] = ls
        lsofError = ls.isEmpty ? lsErr : ""
    }
    let sig = "\(capture?.device ?? "-")|\(captureError ?? "")|\(blockStatus["count"] ?? "-")"
    if tick % 5 == 0 || sig != lastSig {
        lastSig = sig
        slowLock.lock(); let sl = slow; slowLock.unlock()
        var doc: [String: Any] = [
            "ts": Date().timeIntervalSince1970,
            "btm": sl["btm"] ?? "", "cron": sl["cron"] ?? "", "profiles": sl["profiles"] ?? "",
            "xprotect": sl["xprotect"] ?? "",
        ]
        if !lsofError.isEmpty { doc["lsofError"] = lsofError }
        doc.merge(medium) { a, _ in a }
        var cap: [String: Any] = ["active": capture != nil]
        if let c = capture {
            cap["device"] = c.device; cap["skipped"] = c.skipped; cap["pcap"] = pcapPath; cap["packets"] = packetsPath
            cap["linktype"] = Int(c.linkType)
            if let pe = c.pktapError { cap["pktapError"] = pe }
        }
        if let e = captureError { cap["error"] = e }
        doc["capture"] = cap
        doc["block"] = blockStatus
        if let w = dnsWatch { doc["dns"] = w.snapshot }
        if let e = dnsError { doc["dnsError"] = e }
        if let data = try? JSONSerialization.data(withJSONObject: doc) { writeAtomic(data, to: outPath) }
    }
    tick += 1
    sleep(1)
}

var vpnGlobal: VPNRunner?
func vpnShutdown() { vpnGlobal?.shutdown() }
