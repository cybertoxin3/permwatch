// permwatch-root: yönetici modu yardımcısı (root olarak çalışır).
//
// Güvenlik tasarımı:
//  - Komut almaz (soket, argümanla komut yok); yalnızca sabit, salt-okunur bir komut listesini
//    çalıştırır ve sonuçları root'a ait klasöre, başlatan kullanıcıya ait 0600 dosyalar olarak yazar.
//  - Tek "girdi", kullanıcının kendi klasöründeki capture.on dosyasının var olup olmadığıdır:
//    yalnızca paket yakalamayı açar/kapatır, içeriği okunmaz.
//  - Başlatan permwatch süreci kapanınca kendiliğinden çıkar.
//
// Kullanım: permwatch-root <üst-pid>
import Darwin
import Foundation

let outDir = "/Library/Application Support/permwatch"
let outPath = outDir + "/root.json"
let packetsPath = outDir + "/packets.jsonl"
let pcapPath = outDir + "/capture.pcap"

guard CommandLine.arguments.count >= 2, let parent = Int32(CommandLine.arguments[1]) else {
    FileHandle.standardError.write(Data("kullanım: permwatch-root <üst-pid>\n".utf8))
    exit(64)
}
guard getuid() == 0 else {
    FileHandle.standardError.write(Data("root olarak çalışmalı\n".utf8))
    exit(77)
}

// Başlatan kullanıcı: çıktı dosyaları ona ait olur, başka kullanıcılar okuyamaz.
var bsd = proc_bsdinfo()
guard proc_pidinfo(parent, PROC_PIDTBSDINFO, 0, &bsd, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 else { exit(65) }
let owner = bsd.pbi_uid, ownerGid = bsd.pbi_gid
let home = getpwuid(owner).map { String(cString: $0.pointee.pw_dir) } ?? "/var/empty"
let flagPath = home + "/Library/Application Support/permwatch/capture.on"

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

    init() throws {
        var lastError = "pktap"
        for dev in ["pktap,all", "pktap"] {
            let e = CaptureEngine(device: dev)
            do {
                try e.open()
                engine = e
                device = dev
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
    }
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
while true {
    // Başlatan uygulama kapandıysa çık.
    if kill(parent, 0) != 0 && errno == ESRCH { capture?.stop(); exit(0) }

    // Paket yakalama: kullanıcı "Yakalamayı Başlat" dediğinde capture.on oluşur.
    var st = stat()
    let wanted = lstat(flagPath, &st) == 0 && st.st_uid == owner
    if wanted, capture == nil, captureError == nil {
        do { capture = try Capture() } catch { captureError = (error as? CaptureError)?.message ?? "\(error)" }
    } else if !wanted {
        capture?.stop(); capture = nil; captureError = nil
    }
    capture?.flush()

    // Yavaş değişenler dakikada bir.
    if tick % 60 == 0 {
        slow["btm"] = run("/usr/bin/sfltool", ["dumpbtm"])
        slow["cron"] = run("/usr/bin/crontab", ["-l", "-u", "root"])
        slow["profiles"] = run("/usr/bin/profiles", ["show", "-type", "configuration"])
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
    let sig = "\(capture?.device ?? "-")|\(captureError ?? "")"
    if tick % 5 == 0 || sig != lastSig {
        lastSig = sig
        var doc: [String: Any] = [
            "ts": Date().timeIntervalSince1970,
            "btm": slow["btm"] ?? "", "cron": slow["cron"] ?? "", "profiles": slow["profiles"] ?? "",
        ]
        doc.merge(medium) { a, _ in a }
        var cap: [String: Any] = ["active": capture != nil]
        if let c = capture { cap["device"] = c.device; cap["skipped"] = c.skipped; cap["pcap"] = pcapPath; cap["packets"] = packetsPath }
        if let e = captureError { cap["error"] = e }
        doc["capture"] = cap
        if let data = try? JSONSerialization.data(withJSONObject: doc) { writeAtomic(data, to: outPath) }
    }
    tick += 1
    sleep(1)
}
