import AppKit
import CoreServices
import Foundation

/// Gerçek zamanlı koruma (Endpoint Security izni gelene kadar dosya sistemi olaylarıyla):
///  - Zararlıların düştüğü yerlerde yeni ya da değişen her dosyayı saniyeler içinde tarar
///    (Apple XProtect + Elastic imzaları); bulursa uyarır, "Karantinaya al" kullanıcıya sorulur.
///  - Belgelerde fidye yazılımı belirtisi (kısa sürede çok sayıda dosyanın şifrelenmesi) arar;
///    sorumlu imzasız bir programsa onu askıya alır (geri alınabilir) ve kullanıcıya sorar.
@MainActor
final class RealtimeGuard: ObservableObject {
    static let shared = RealtimeGuard()
    static let enabledKey = "realtimeProtection"
    static let ransomKey = "ransomProtection"

    @Published var enabled: Bool = UserDefaults.standard.object(forKey: RealtimeGuard.enabledKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(enabled, forKey: Self.enabledKey); restart() }
    }
    @Published var ransomEnabled: Bool = UserDefaults.standard.object(forKey: RealtimeGuard.ransomKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(ransomEnabled, forKey: Self.ransomKey); restart() }
    }
    @Published private(set) var watching: [String] = []
    @Published private(set) var scannedCount = 0
    @Published private(set) var ransomAlerts: [RansomAlert] = []

    private var stream: FSEventStreamRef?
    private var pending = Set<String>()
    private var flush: DispatchWorkItem?
    private let ransom = RansomDetector()
    private var fdaTimer: Timer?

    private init() {}

    func start() {
        restart()
        // Tam Disk Erişimi sonradan verilirse İndirilenler/Masaüstü/Belgeler de izlenmeye başlasın.
        if !FullDisk.granted {
            fdaTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] t in
                MainActor.assumeIsolated {
                    guard FullDisk.granted else { return }
                    t.invalidate(); self?.restart()
                }
            }
        }
    }

    /// Zararlıların düştüğü/kalıcılaştığı yerler.
    nonisolated static func malwareRoots(fullDisk: Bool) -> [String] {
        let h = NSHomeDirectory()
        var r = ["/Applications", h + "/Applications", h + "/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons",
                 h + "/Library/Application Support", "/Library/Application Support", "/Users/Shared", "/private/tmp",
                 "/Library/PrivilegedHelperTools", h + "/Library/Scripts", "/usr/local/bin"]
        if fullDisk { r += [h + "/Downloads", h + "/Desktop", h + "/Documents"] }
        return r.filter { FileManager.default.fileExists(atPath: $0) }
    }

    /// Fidye yazılımının hedeflediği belgeler.
    nonisolated static func documentRoots(fullDisk: Bool) -> [String] {
        guard fullDisk else { return [] }
        let h = NSHomeDirectory()
        return [h + "/Documents", h + "/Desktop", h + "/Pictures", h + "/Downloads",
                h + "/Library/Mobile Documents/com~apple~CloudDocs"].filter { FileManager.default.fileExists(atPath: $0) }
    }

    private func restart() {
        if let s = stream { FSEventStreamStop(s); FSEventStreamInvalidate(s); FSEventStreamRelease(s); stream = nil }
        watching = []
        guard (enabled || ransomEnabled), Snapshot.section == nil else { return }
        let fda = FullDisk.granted
        var roots = enabled ? Self.malwareRoots(fullDisk: fda) : []
        if ransomEnabled { roots += Self.documentRoots(fullDisk: fda) }
        roots = Array(Set(roots)).sorted()
        guard !roots.isEmpty else { return }
        var ctx = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        let cb: FSEventStreamCallback = { _, info, n, paths, flags, _ in
            guard let info else { return }
            let me = Unmanaged<RealtimeGuard>.fromOpaque(info).takeUnretainedValue()
            let list = Unmanaged<CFArray>.fromOpaque(paths).takeUnretainedValue() as? [String] ?? []
            var evs: [(String, FSEventStreamEventFlags)] = []
            for i in 0..<min(n, list.count) { evs.append((list[i], flags[i])) }
            MainActor.assumeIsolated { me.handle(evs) }
        }
        let flags = UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagNoDefer)
        guard let s = FSEventStreamCreate(nil, cb, &ctx, roots as CFArray, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 0.5, flags) else { return }
        FSEventStreamSetDispatchQueue(s, .main)
        FSEventStreamStart(s)
        stream = s
        watching = roots
    }

    private static let skip = ["/Caches/", "/Logs/", "/.git/", "/node_modules/", "/permwatch/", "/CrashReporter/",
                               "/Google/Chrome/Default/", "/Code/User/", "/.Trash/"]

    private func handle(_ events: [(String, FSEventStreamEventFlags)]) {
        let fda = FullDisk.granted
        let docs = ransomEnabled ? Self.documentRoots(fullDisk: fda) : []
        var docEvents: [(String, Bool)] = []
        for (p, f) in events {
            let isFile = f & UInt32(kFSEventStreamEventFlagItemIsFile) != 0
            let changed = f & UInt32(kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemRenamed) != 0
            guard isFile, changed else { continue }
            if Self.skip.contains(where: p.contains) { continue }
            if docs.contains(where: { p.hasPrefix($0 + "/") }) {
                docEvents.append((p, f & UInt32(kFSEventStreamEventFlagItemRenamed) != 0))
            }
            if enabled { pending.insert(p) }
        }
        if !docEvents.isEmpty { ransom.observe(docEvents) { [weak self] alert in self?.raise(alert) } }
        guard !pending.isEmpty else { return }
        flush?.cancel()
        // İndirme/kopyalama bitsin diye kısa bekle.
        let w = DispatchWorkItem { [weak self] in MainActor.assumeIsolated { self?.scanPending() } }
        flush = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: w)
    }

    private func scanPending() {
        let paths = pending
        pending.removeAll()
        Task.detached(priority: .utility) {
            let engine = YaraEngine.shared
            guard engine.load() == nil else { return }
            var targets = Set<String>()
            for p in paths where FileManager.default.fileExists(atPath: p) {
                if p.hasSuffix(".plist"), p.contains("/Launch") {
                    // Yeni başlangıç öğesi: başlattığı programı da tara.
                    targets.insert(p)
                    if let d = NSDictionary(contentsOfFile: p),
                       let prog = (d["Program"] as? String) ?? (d["ProgramArguments"] as? [String])?.first { targets.insert(prog) }
                } else if Targets.isCandidate(p), Targets.isScannable(p) {
                    targets.insert(p)
                }
            }
            guard !targets.isEmpty else { return }
            let launch = Targets.launchItemPrograms()
            var hits: [Detection] = []
            for p in targets {
                for m in engine.scan(p) ?? [] {
                    hits.append(Detection(path: p, rule: m.rule, name: m.name, date: Date(),
                                          launchItems: launch.filter { $0.program == p }.map(\.plist)))
                }
            }
            let n = targets.count, found = hits
            await MainActor.run {
                self.scannedCount += n
                if !found.isEmpty { MalwareScanner.shared.add(found) }
            }
        }
    }

    // MARK: Fidye yazılımı

    private func raise(_ a: RansomAlert) {
        ransomAlerts.removeAll { $0.pid == a.pid }
        ransomAlerts.insert(a, at: 0)
        ThreatCenter.shared.report(Threat(
            id: "ransom.\(a.pid).\(Int(a.date.timeIntervalSince1970) / 600)", risk: .high,
            title: L("ransom.title"),
            detail: a.suspended ? L("ransom.detailSuspended", a.name, a.files.formatted()) : L("ransom.detail", a.name, a.files.formatted()),
            iconKey: a.path.map { PathUtil.appBundle($0) ?? $0 }, section: .scan, focus: .process(a.pid)))
    }

    func resume(_ a: RansomAlert) {
        Darwin.kill(a.pid, SIGCONT)
        ransomAlerts.removeAll { $0.id == a.id }
    }

    func terminate(_ a: RansomAlert) {
        Darwin.kill(a.pid, SIGKILL)
        ransomAlerts.removeAll { $0.id == a.id }
    }

    func dismiss(_ a: RansomAlert) { ransomAlerts.removeAll { $0.id == a.id } }
}

struct RansomAlert: Identifiable, Equatable {
    var id: String { "\(pid)-\(date.timeIntervalSince1970)" }
    let pid: Int32
    let name: String
    let path: String?
    let files: Int
    let examples: [String]
    let date: Date
    let suspended: Bool
}

/// Belgelerdeki değişikliklerden fidye yazılımı belirtisi çıkarır:
///  - içeriği uzantısıyla uyuşmayan dosya (ör. .pdf ama "%PDF" ile başlamıyor, .txt ama rastgele bayt)
///  - bilinen bir uzantının arkasına yeni uzantı eklenmesi (rapor.docx → rapor.docx.locked)
/// 30 saniyede 12 şüpheli dosya görülürse, en çok yazan süreci bulur.
@MainActor
final class RansomDetector {
    private var window: [(Date, String)] = []
    private var lastAlert = Date.distantPast
    private var writes: [Int32: UInt64] = [:]
    private var writesAt = Date.distantPast
    static let threshold = 12

    func observe(_ events: [(String, Bool)], alert: @escaping (RansomAlert) -> Void) {
        let paths = events
        Task.detached(priority: .utility) {
            var bad: [String] = []
            for (p, renamed) in paths where FileManager.default.fileExists(atPath: p) {
                if RansomDetector.suspicious(path: p, renamed: renamed) { bad.append(p) }
            }
            let found = bad
            await MainActor.run { self.add(found, alert: alert) }
        }
        // Yazma ölçümü için başlangıç noktası (olay yoğunken her 3 saniyede bir).
        if Date().timeIntervalSince(writesAt) > 3 { writes = Self.diskWrites(); writesAt = Date() }
    }

    private func add(_ bad: [String], alert: (RansomAlert) -> Void) {
        let now = Date()
        window.append(contentsOf: bad.map { (now, $0) })
        window.removeAll { now.timeIntervalSince($0.0) > 30 }
        guard window.count >= Self.threshold, now.timeIntervalSince(lastAlert) > 120 else { return }
        lastAlert = now
        let files = Array(Set(window.map(\.1)))
        window.removeAll()
        // En çok yazan (Apple'ın kendi servisleri dışındaki) süreç.
        let after = Self.diskWrites()
        var best: (Int32, UInt64)?
        for (pid, b) in after where pid != getpid() {
            let d = b &- (writes[pid] ?? b)
            guard d > 0, d < UInt64.max / 2, let path = Self.path(pid), !path.hasPrefix("/System/"), !path.hasPrefix("/usr/") else { continue }
            if best == nil || d > best!.1 { best = (pid, d) }
        }
        guard let (pid, _) = best else { return }
        let path = Self.path(pid)
        let sig = path.map { Signing.classify(path: PathUtil.appBundle($0) ?? $0).signature } ?? "unsigned"
        // Askıya alma geri alınabilir (Devam ettir); yalnızca imzasız/geçici imzalı programlarda kendiliğinden.
        var suspended = false
        if sig == "unsigned" || sig == "adhoc" { suspended = Darwin.kill(pid, SIGSTOP) == 0 }
        alert(RansomAlert(pid: pid, name: path.map { PathUtil.displayName(PathUtil.appBundle($0) ?? $0) } ?? "pid \(pid)",
                          path: path, files: files.count, examples: Array(files.prefix(5)), date: now, suspended: suspended))
    }

    nonisolated static func path(_ pid: Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
    }

    /// Süreçlerin şimdiye kadar diske yazdığı bayt (yalnızca okunabilen süreçler).
    nonisolated static func diskWrites() -> [Int32: UInt64] {
        let n = proc_listallpids(nil, 0)
        var pids = [Int32](repeating: 0, count: Int(max(n, 0)) + 64)
        let got = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size)))
        var out: [Int32: UInt64] = [:]
        for pid in pids.prefix(max(0, got)) where pid > 0 {
            var info = rusage_info_v4()
            let rc = withUnsafeMutablePointer(to: &info) {
                $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
            }
            if rc == 0 { out[pid] = info.ri_diskio_byteswritten }
        }
        return out
    }

    /// Uzantı → dosyanın başında olması gereken baytlar.
    nonisolated static let magic: [String: [[UInt8]]] = [
        "pdf": [Array("%PDF".utf8)],
        "docx": [[0x50, 0x4b]], "xlsx": [[0x50, 0x4b]], "pptx": [[0x50, 0x4b]], "zip": [[0x50, 0x4b]],
        "pages": [[0x50, 0x4b]], "numbers": [[0x50, 0x4b]], "key": [[0x50, 0x4b]], "odt": [[0x50, 0x4b]],
        "jpg": [[0xff, 0xd8, 0xff]], "jpeg": [[0xff, 0xd8, 0xff]], "png": [[0x89, 0x50, 0x4e, 0x47]],
        "gif": [Array("GIF8".utf8)], "doc": [[0xd0, 0xcf, 0x11, 0xe0]], "xls": [[0xd0, 0xcf, 0x11, 0xe0]],
        "psd": [Array("8BPS".utf8)], "rtf": [Array("{\\rtf".utf8)], "sqlite": [Array("SQLite format".utf8)],
    ]
    /// Düz metin olması gereken uzantılar (içerik rastgele baytsa şüpheli).
    nonisolated static let text: Set<String> = ["txt", "md", "csv", "json", "xml", "html", "htm", "swift", "py", "js", "c", "h", "tex"]
    nonisolated static let known: Set<String> = Set(magic.keys).union(text).union(["heic", "mov", "mp4", "mp3", "m4a", "wav"])

    nonisolated static func suspicious(path: String, renamed: Bool) -> Bool {
        let name = (path as NSString).lastPathComponent
        let ext = (name as NSString).pathExtension.lowercased()
        let inner = ((name as NSString).deletingPathExtension as NSString).pathExtension.lowercased()
        // rapor.docx.locked: bilinen uzantının arkasına bilinmeyen bir uzantı
        if renamed, !inner.isEmpty, known.contains(inner), !known.contains(ext), ext.count <= 12,
           !["icloud", "download", "crdownload", "part", "tmp", "bak", "sb", "orig"].contains(ext), !name.hasPrefix(".") {
            return true
        }
        guard let h = FileHandle(forReadingAtPath: path) else { return false }
        defer { try? h.close() }
        guard let d = try? h.read(upToCount: 4096), d.count >= 64 else { return false }
        let b = [UInt8](d)
        if let sigs = magic[ext] { return !sigs.contains { b.starts(with: $0) } && entropy(b) > 7.2 }
        if text.contains(ext) { return entropy(b) > 7.2 }
        return false
    }

    /// Bayt başına Shannon entropisi (0–8). Şifreli/sıkıştırılmış veri ~8'e yakındır.
    nonisolated static func entropy(_ b: [UInt8]) -> Double {
        var c = [Int](repeating: 0, count: 256)
        for x in b { c[Int(x)] += 1 }
        let n = Double(b.count)
        return c.reduce(0.0) { acc, k in k == 0 ? acc : acc - (Double(k) / n) * log2(Double(k) / n) }
    }
}
