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
var medium: [String: Any] = [:]
var capture: Capture?
var captureError: String?
var tick = 0
var lastSig = ""
var dnsWatch: DNSWatch?
var dnsError: String?
let vpn = VPNRunner()
vpnGlobal = vpn
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
    let wanted = lstat(flagPath, &st) == 0 && st.st_uid == owner
    if wanted, capture == nil, captureError == nil {
        do { capture = try Capture(payload: true) } catch { captureError = (error as? CaptureError)?.message ?? "\(error)" }
    } else if !wanted {
        capture?.stop(); capture = nil; captureError = nil
    }
    capture?.flush()
    applyBlocklist()

    // DNS izleme: kullanıcı "Zararlı sunucu kontrolü"nü açık tuttuğunda dnswatch.on vardır.
    var dst = stat()
    let dnsWanted = lstat(dnsFlagPath, &dst) == 0 && dst.st_uid == owner
    if dnsWanted, dnsWatch == nil, dnsError == nil {
        do { dnsWatch = try DNSWatch() } catch { dnsError = (error as? CaptureError)?.message ?? "\(error)" }
    } else if !dnsWanted, dnsWatch != nil || dnsError != nil {
        dnsWatch?.stop(); dnsWatch = nil; dnsError = nil
    }

    // Yavaş değişenler dakikada bir.
    if tick % 60 == 0 {
        slow["btm"] = run("/usr/bin/sfltool", ["dumpbtm"])
        slow["cron"] = run("/usr/bin/crontab", ["-l", "-u", "root"])
        slow["profiles"] = run("/usr/bin/profiles", ["show", "-type", "configuration"])
        // Apple XProtect / XProtect Remediator: son 3 günün tespit ve temizleme kayıtları (saatte bir).
        if tick % 3600 == 0 {
            let log = run("/usr/bin/log", ["show", "--last", "3d", "--style", "compact", "--predicate",
                "(subsystem BEGINSWITH \"com.apple.XProtect\" OR process BEGINSWITH \"XProtect\") AND (eventMessage CONTAINS[c] \"remediat\" OR eventMessage CONTAINS[c] \"detected\" OR eventMessage CONTAINS[c] \"malware found\")"])
            slow["xprotect"] = String(log.split(separator: "\n").filter { !$0.hasPrefix("Timestamp") && !$0.contains("Filtering the log") }.suffix(200).joined(separator: "\n"))
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
        medium["lsof"] = run("/usr/sbin/lsof", ["-nP", "-i", "-F", "pcfPnT"])
    }
    let sig = "\(capture?.device ?? "-")|\(captureError ?? "")|\(blockStatus["count"] ?? "-")"
    if tick % 5 == 0 || sig != lastSig {
        lastSig = sig
        var doc: [String: Any] = [
            "ts": Date().timeIntervalSince1970,
            "btm": slow["btm"] ?? "", "cron": slow["cron"] ?? "", "profiles": slow["profiles"] ?? "",
            "xprotect": slow["xprotect"] ?? "",
        ]
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
