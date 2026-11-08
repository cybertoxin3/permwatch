import AppKit
import Darwin
import Foundation
import UserNotifications

/// Çalışan bir süreç için şüphe kuralları.
enum ProcRule: String {
    case deletedBinary, masquerade, dyld, unsignedUserLocation, suspiciousLocation, lolbinFromUnsigned

    var risk: Risk {
        switch self {
        case .deletedBinary, .masquerade, .dyld: return .high
        case .unsignedUserLocation, .suspiciousLocation, .lolbinFromUnsigned: return .caution
        }
    }

    var text: String {
        switch self {
        case .dyld: return L("rule.dyld")
        case .lolbinFromUnsigned: return L("rule.lolbinFromUnsigned")
        default: return L("prule.\(rawValue)")
        }
    }
}

struct ProcRow: Identifiable, Hashable {
    var id: Int32 { pid }
    let pid: Int32
    let ppid: Int32
    let uid: UInt32
    let user: String
    let name: String
    let path: String?
    let appPath: String?          // içinde bulunduğu .app paketi
    let started: Date?
    var cpu: Double?              // yüzde; yalnızca kendi kullanıcının süreçleri
    var memory: UInt64?           // bayt
    let signature: String?
    let team: String?
    let args: [String]?
    let dyld: [String]
    let rules: [ProcRule]
    let risk: Risk
    let trusted: Bool

    var key: String { appPath ?? path ?? "pid:\(pid)" }
    var isOwn: Bool { uid == getuid() }

    static func == (a: ProcRow, b: ProcRow) -> Bool {
        a.pid == b.pid && a.cpu == b.cpu && a.memory == b.memory && a.risk == b.risk && a.trusted == b.trusted
    }
    func hash(into h: inout Hasher) { h.combine(pid) }

    // Table sıralaması için isteğe bağlı olmayan değerler
    var cpuSort: Double { cpu ?? -1 }
    var memSort: UInt64 { memory ?? 0 }
    var riskSort: Int { risk.rawValue }
    var sigSort: String { signature ?? "" }
}

@MainActor
final class ProcessMonitor: ObservableObject {
    @Published private(set) var rows: [ProcRow] = []
    @Published var visible = false { didSet { reschedule() } }

    var trusted: Set<String> = []
    private var timer: Timer?
    private var prevCPU: [Int32: (ns: UInt64, at: UInt64)] = [:]
    private var notified = Set<String>()
    private var first = true
    private var busy = false

    init() {
        refresh()
        reschedule()
    }

    var suspicious: Int { rows.filter { $0.risk >= .caution }.count }

    /// Görünürken 2 sn, arka planda 5 sn aralıkla (yeni şüpheli süreçler için) yeniler.
    private func reschedule() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: visible ? 2 : 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func refresh() {
        guard !busy else { return }
        busy = true
        let prev = prevCPU
        let trusted = self.trusted
        Task.detached(priority: .utility) {
            let (rows, cpu) = ProcessMonitor.collect(prev: prev, trusted: trusted)
            await MainActor.run {
                self.prevCPU = cpu
                self.rows = rows
                self.busy = false
                self.notifyNew()
            }
        }
    }

    private func notifyNew() {
        let high = rows.filter { $0.risk == .high }
        defer { first = false }
        for r in high {
            let k = "\(r.key)|\(r.rules.map(\.rawValue).joined())"
            if notified.contains(k) { continue }
            notified.insert(k)
            if first { continue }   // açılışta zaten çalışanlar için pencere yağdırma
            ThreatCenter.shared.report(Threat(
                id: "proc-\(k)", risk: .high, title: "\(Risk.high.label): \(L("alert.process"))",
                detail: "\(r.name) (pid \(r.pid)) · " + (r.rules.first?.text ?? ""),
                iconKey: r.appPath ?? r.path, section: .running, focus: .process(r.pid)))
        }
    }

    // MARK: - Eylemler

    /// Normal çıkış (SIGTERM ya da uygulamaysa nazikçe kapat). Hata mesajı döner.
    func quit(_ r: ProcRow, force: Bool) -> String? {
        if !force, let app = NSRunningApplication(processIdentifier: r.pid) {
            return app.terminate() ? nil : L("proc.killFailed", r.name)
        }
        if Darwin.kill(r.pid, force ? SIGKILL : SIGTERM) == 0 {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.refresh() }
            return nil
        }
        return L("proc.killFailed", String(cString: strerror(errno)))
    }

    /// Açık ağ bağlantıları (lsof; yalnızca kendi kullanıcının süreçleri için sonuç verir).
    nonisolated static func connections(pid: Int32) -> [String] {
        let (_, out) = Shell.run("/usr/sbin/lsof", ["-nP", "-a", "-p", "\(pid)", "-i"])
        return out.split(separator: "\n").dropFirst().compactMap { line in
            let cols = line.split(separator: " ", omittingEmptySubsequences: true)
            guard cols.count >= 9 else { return nil }
            return "\(cols[7]) " + cols[8...].joined(separator: " ")
        }
    }

    // MARK: - Toplama

    nonisolated private static let systemNames: Set<String> = [
        "launchd", "kernel_task", "WindowServer", "syslogd", "mds", "mds_stores", "mdworker", "cfprefsd",
        "trustd", "securityd", "loginwindow", "Finder", "Dock", "SystemUIServer", "coreaudiod", "bluetoothd",
        "sshd", "tccd", "notifyd", "distnoted", "opendirectoryd", "powerd", "configd", "logd", "UserEventAgent",
    ]
    nonisolated private static let systemPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/"]
    nonisolated private static let lolbins: Set<String> = [
        "/usr/bin/osascript", "/usr/bin/curl", "/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/python3",
        "/usr/bin/base64", "/usr/bin/openssl", "/usr/bin/nc", "/bin/launchctl", "/usr/bin/security",
    ]

    nonisolated private static let timebase: (numer: UInt64, denom: UInt64) = {
        var tb = mach_timebase_info_data_t()
        mach_timebase_info(&tb)
        return (UInt64(tb.numer), UInt64(tb.denom))
    }()

    nonisolated(unsafe) private static var sigCache: [String: (String, String?)] = [:]
    nonisolated private static let sigLock = NSLock()

    nonisolated private static func signature(_ path: String) -> (String, String?) {
        sigLock.lock(); defer { sigLock.unlock() }
        if let c = sigCache[path] { return c }
        let target = PathUtil.appBundle(path) ?? path
        var c = Signing.classify(path: target)
        if c.signature == "unsigned", let h = FileHandle(forReadingAtPath: path) {
            if h.readData(ofLength: 2) == Data("#!".utf8) { c.signature = "script" }
            try? h.close()
        }
        let v = (c.signature, c.team)
        sigCache[path] = v
        return v
    }

    nonisolated static func collect(prev: [Int32: (ns: UInt64, at: UInt64)], trusted: Set<String>)
        -> ([ProcRow], [Int32: (ns: UInt64, at: UInt64)]) {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return ([], [:]) }
        var pids = [Int32](repeating: 0, count: Int(count) + 64)
        let n = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size)))
        let now = mach_absolute_time()
        let home = NSHomeDirectory()
        var cpuOut: [Int32: (ns: UInt64, at: UInt64)] = [:]

        struct Base { var pid: Int32; var ppid: Int32; var uid: UInt32; var name: String; var path: String?; var started: Date? }
        var bases: [Int32: Base] = [:]
        for pid in pids.prefix(max(0, n)) where pid > 0 {
            var info = proc_bsdinfo()
            let sz = Int32(MemoryLayout<proc_bsdinfo>.size)
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sz) == sz else { continue }
            var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            let path = proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
            let name = withUnsafeBytes(of: info.pbi_name) { raw -> String in
                let s = String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
                return s.isEmpty ? withUnsafeBytes(of: info.pbi_comm) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) } : s
            }
            let started = info.pbi_start_tvsec > 0 ? Date(timeIntervalSince1970: TimeInterval(info.pbi_start_tvsec)) : nil
            // Çekirdekteki ad 32 karakterde kesilir; yol varsa tam adı ondan al.
            let fullName = path.map { ($0 as NSString).lastPathComponent } ?? name
            bases[pid] = Base(pid: pid, ppid: Int32(info.pbi_ppid), uid: info.pbi_uid, name: fullName, path: path, started: started)
        }

        var rows: [ProcRow] = []
        for b in bases.values {
            // CPU / bellek: yalnızca izin verilen süreçlerde dolar.
            var cpu: Double?
            var mem: UInt64?
            var ti = proc_taskinfo()
            let tsz = Int32(MemoryLayout<proc_taskinfo>.size)
            if proc_pidinfo(b.pid, PROC_PIDTASKINFO, 0, &ti, tsz) == tsz {
                mem = ti.pti_resident_size
                let ns = (ti.pti_total_user + ti.pti_total_system) * timebase.numer / timebase.denom
                cpuOut[b.pid] = (ns, now)
                if let p = prev[b.pid], now > p.at, ns >= p.ns {
                    let wall = (now - p.at) * timebase.numer / timebase.denom
                    cpu = wall > 0 ? Double(ns - p.ns) / Double(wall) * 100 : nil
                } else {
                    cpu = 0
                }
            }
            let full = procArgsFull(b.pid)
            let args = full.args
            let dyld = full.env.filter { $0.hasPrefix("DYLD_") }
            // Dosyası silinmiş süreçlerde proc_pidpath boş döner; başlatılan yolu kullan.
            let b = b.path == nil && full.exec?.hasPrefix("/") == true
                ? Base(pid: b.pid, ppid: b.ppid, uid: b.uid, name: b.name, path: full.exec, started: b.started) : b

            var rules: [ProcRule] = []
            var sig: String?
            var team: String?
            if let p = b.path {
                let exists = FileManager.default.fileExists(atPath: p)
                if !exists { rules.append(.deletedBinary) }
                let underSystem = systemPrefixes.contains { p.hasPrefix($0) }
                if systemNames.contains(b.name) && !underSystem && !p.hasPrefix("/Applications/") { rules.append(.masquerade) }
                if exists {
                    (sig, team) = signature(p)
                    let userWritable = p.hasPrefix(home) || p.hasPrefix("/tmp/") || p.hasPrefix("/private/tmp/")
                        || p.hasPrefix("/private/var/folders/") || p.hasPrefix("/Users/Shared/")
                    let odd = p.contains("/Downloads/") || p.hasPrefix("/tmp/") || p.hasPrefix("/private/tmp/")
                        || p.hasPrefix("/private/var/folders/") || PathUtil.isHidden(p)
                    if sig == "unsigned" && userWritable { rules.append(.unsignedUserLocation) }
                    if odd && (sig == "unsigned" || sig == "adhoc" || sig == "script") { rules.append(.suspiciousLocation) }
                    if lolbins.contains(p), let parent = bases[b.ppid], let pp = parent.path {
                        let ps = signature(pp).0
                        if ps == "unsigned" || ps == "adhoc" { rules.append(.lolbinFromUnsigned) }
                    }
                }
            }
            if !dyld.isEmpty { rules.append(.dyld) }

            let appPath = b.path.flatMap(PathUtil.appBundle)
            let key = appPath ?? b.path ?? ""
            let isTrusted = trusted.contains(key)
            let risk = isTrusted ? .normal : (rules.map(\.risk).max() ?? .normal)
            let user = getpwuid(b.uid).map { String(cString: $0.pointee.pw_name) } ?? "\(b.uid)"
            rows.append(ProcRow(pid: b.pid, ppid: b.ppid, uid: b.uid, user: user, name: b.name, path: b.path,
                                appPath: appPath, started: b.started, cpu: cpu, memory: mem, signature: sig, team: team,
                                args: args, dyld: dyld, rules: rules, risk: risk, trusted: isTrusted))
        }
        return (rows, cpuOut)
    }

    /// KERN_PROCARGS2: argümanlar ve ortam değişkenleri (yalnızca kendi süreçlerimiz).
    nonisolated static func procArgs(_ pid: Int32) -> ([String]?, [String]) {
        let r = procArgsFull(pid)
        return (r.args, r.env)
    }

    /// Başlatılan yol + argümanlar + ortam. Yol, dosya silinmiş olsa da burada kalır.
    nonisolated static func procArgsFull(_ pid: Int32) -> (exec: String?, args: [String]?, env: [String]) {
        var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
        var argmax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctl(&mib, 2, &argmax, &size, nil, 0) == 0 else { return (nil, nil, []) }
        var buf = [UInt8](repeating: 0, count: Int(argmax))
        size = buf.count
        mib = [CTL_KERN, KERN_PROCARGS2, pid]
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return (nil, nil, []) }
        let argc = Int(buf.withUnsafeBytes { $0.load(as: Int32.self) })
        var i = 4
        while i < size && buf[i] != 0 { i += 1 }      // çalıştırılabilir yol
        let exec = String(decoding: buf[4..<i], as: UTF8.self)
        while i < size && buf[i] == 0 { i += 1 }      // dolgu
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
        let args = Array(strings.prefix(argc))
        let env = Array(strings.dropFirst(argc))
        return (exec.isEmpty ? nil : exec, args, env)
    }
}
