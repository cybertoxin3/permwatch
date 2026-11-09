import AppKit
import AVFoundation
import CoreWLAN
import Foundation
import LocalAuthentication
import UserNotifications

/// İzlenen uzaktan erişim yolları.
enum RemoteKind: String, Codable { case tool, screenSharing, ssh, capture }

/// Bir sürecin bir yoklamadaki gözlemi.
struct RemoteObservation: Equatable {
    let pid: Int32
    let name: String          // gösterilecek ad (AnyDesk, Ekran Paylaşımı…)
    let path: String?
    let kind: RemoteKind
    /// Giden bayt (toplam); bilinmiyorsa -1. Yalnızca giden trafik sayılır: ekranı izlenen bilgisayar görüntüyü
    /// gönderir, izleyen alır. Böylece kullanıcının kendisi başka bir bilgisayara bağlandığında uyarı çıkmaz.
    let bytes: Int64
}

/// Etkin bir uzaktan oturum.
struct RemoteSession: Equatable, Identifiable {
    var id: String { name }
    let name: String
    let kind: RemoteKind
    var pids: [Int32]
    var paths: [String]
    let start: Date
    var rate: Double          // bayt/sn
}

/// Saf (test edilebilir) oturum tespiti: her yoklamada gözlemler verilir, etkin oturumlar döner.
struct SessionDetector {
    /// Uzaktan erişim programı için oturum eşiği (giden bayt/sn): ekran görüntüsü akışı bunun çok üstündedir;
    /// boşta bekleyen bir program birkaç yüz bayt/sn gönderir.
    var activeRate: Double = 30_000
    /// Bu kadar ardışık yoklama eşiğin üstündeyse oturum başladı sayılır.
    var confirmPolls = 2
    /// Oturum bu kadar saniye düşük trafikle sürerse bitti sayılır.
    var idleEnd: TimeInterval = 20

    private var last: [Int32: (bytes: Int64, at: Date)] = [:]
    private var hot: [String: Int] = [:]          // ad → art arda yüksek yoklama
    private var lastHot: [String: Date] = [:]
    private(set) var sessions: [String: RemoteSession] = [:]

    mutating func update(_ obs: [RemoteObservation], now: Date) -> [RemoteSession] {
        // Ada göre topla: bir programın birden fazla süreci olabilir.
        var byName: [String: (kind: RemoteKind, pids: [Int32], paths: [String], rate: Double)] = [:]
        var seen = Set<Int32>()
        for o in obs {
            seen.insert(o.pid)
            var rate = 0.0
            if o.bytes >= 0, let p = last[o.pid], o.bytes >= p.bytes {
                let dt = now.timeIntervalSince(p.at)
                if dt > 0.2 { rate = Double(o.bytes - p.bytes) / dt }
            }
            if o.bytes >= 0 { last[o.pid] = (o.bytes, now) }
            var e = byName[o.name] ?? (o.kind, [], [], 0)
            e.pids.append(o.pid)
            if let p = o.path, !e.paths.contains(p) { e.paths.append(p) }
            e.rate += rate
            byName[o.name] = e
        }
        last = last.filter { seen.contains($0.key) }

        for (name, e) in byName {
            let isHot: Bool
            switch e.kind {
            case .ssh, .capture: isHot = true
            case .screenSharing: isHot = e.rate > activeRate / 3 || sessions[name] != nil
            case .tool: isHot = e.rate > activeRate
            }
            if isHot {
                hot[name, default: 0] += 1
                lastHot[name] = now
            } else {
                hot[name] = 0
            }
            let needed = e.kind == .tool ? confirmPolls : 1
            if var s = sessions[name] {
                s.pids = e.pids; s.paths = e.paths; s.rate = e.rate
                sessions[name] = s
            } else if hot[name, default: 0] >= needed {
                sessions[name] = RemoteSession(name: name, kind: e.kind, pids: e.pids, paths: e.paths, start: now, rate: e.rate)
            }
        }
        // Biten oturumlar: süreç kalmadı ya da uzun süre trafik yok.
        for (name, s) in sessions {
            if byName[name] == nil { sessions[name] = nil; hot[name] = nil; continue }
            if s.kind == .tool, let h = lastHot[name], now.timeIntervalSince(h) > idleEnd { sessions[name] = nil }
        }
        return sessions.values.sorted { $0.start < $1.start }
    }
}

/// Banka, ödeme ve kimlik siteleri: uzaktan oturum açıkken bunlara girilmesi dolandırıcılığın en tehlikeli anıdır.
enum SensitiveSites {
    static let domains: [String] = [
        // Türkiye: bankalar, katılım bankaları, ödeme
        "ziraatbank.com.tr", "isbank.com.tr", "garantibbva.com.tr", "akbank.com", "yapikredi.com.tr", "halkbank.com.tr",
        "vakifbank.com.tr", "qnb.com.tr", "qnbfinansbank.com", "denizbank.com", "teb.com.tr", "ing.com.tr", "ingbank.com.tr",
        "enpara.com", "kuveytturk.com.tr", "albaraka.com.tr", "albarakaturk.com.tr", "sekerbank.com.tr", "odeabank.com.tr",
        "hsbc.com.tr", "fibabanka.com.tr", "turkiyefinans.com.tr", "ziraatkatilim.com.tr", "vakifkatilim.com.tr",
        "emlakkatilim.com.tr", "anadolubank.com.tr", "burgan.com.tr", "icbc.com.tr", "alternatifbank.com.tr",
        "papara.com", "ininal.com", "param.com.tr", "tosla.com", "colendi.com", "turkiye.gov.tr",
        // Kripto
        "binance.com", "binance.tr", "btcturk.com", "paribu.com", "bitlo.com", "icrypex.com", "okx.com", "bybit.com",
        "coinbase.com", "kraken.com", "kucoin.com",
        // Rusya, Ukrayna
        "sberbank.ru", "online.sberbank.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru", "gazprombank.ru",
        "raiffeisen.ru", "sovcombank.ru", "pochtabank.ru", "gosuslugi.ru", "privatbank.ua", "monobank.ua", "diia.gov.ua",
        // Avrupa ve dünya
        "paypal.com", "wise.com", "revolut.com", "n26.com", "deutsche-bank.de", "sparkasse.de", "commerzbank.de",
        "ing.de", "dkb.de", "bnpparibas", "credit-agricole.fr", "societegenerale.fr", "santander.com", "bbva.es",
        "caixabank.es", "intesasanpaolo.com", "unicredit.it", "hsbc.com", "barclays.co.uk", "lloydsbank.com",
        "natwest.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "capitalone.com",
        "appleid.apple.com", "icloud.com",
    ]

    /// host ya da üst alan adlarından biri listede mi? ("online.isbank.com.tr" → isbank.com.tr)
    static func match(_ host: String) -> String? {
        var h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        while h.contains(".") {
            if domains.contains(h) { return h }
            h = String(h.drop { $0 != "." }.dropFirst())
        }
        return nil
    }
}

/// Ekranı şu an paylaşan ya da kaydeden bir uygulama.
struct ScreenCapture: Identifiable, Equatable {
    var id: String { key }
    /// Uygulama kimliği (paket kimliği ya da yol); "Tanıyorum" bu anahtarla saklanır.
    let key: String
    let name: String
    let path: String?
    var pids: [Int32]
    let start: Date
    let kind: RemoteKind        // tool: uzaktan kontrol programı (fareyi de kontrol edebilir); capture: kayıt/paylaşım
    var isRemoteControl: Bool { kind == .tool || kind == .screenSharing }
}

/// Bir uyarının kaydı: ekran paylaşılırken banka sitesine girildi.
struct ShareIncident: Codable, Identifiable, Equatable {
    var id: String
    var date: Date
    var apps: [String]
    var sites: [String]
    var actions: [String]
    var outcome: Outcome
    enum Outcome: String, Codable { case open, stopped, acknowledged, ended }
}

// MARK: - Ekran Paylaşımı Koruması

/// Ekranı kaydeden ya da paylaşan uygulamayı bulur ve ekranda küçük bir göstergeyle bildirir.
/// "Tanıyorum" denmemiş bir paylaşım sürerken banka/ödeme/kimlik sitesine girilirse ekranı kaplayan bir uyarı gösterir.
/// Bunun dışında hiçbir şey yapmaz: Zoom'da derse ya da toplantıya katılmak, birine AnyDesk ile yardım etmek etkilenmez.
@MainActor
final class ShareGuard: ObservableObject {
    static let shared = ShareGuard()
    static let enabledKey = "shareGuard"
    static let speakKey = "shareGuardSpeak"
    static let trustKey = "shareGuardTrusted"

    @Published var enabled: Bool = UserDefaults.standard.object(forKey: ShareGuard.enabledKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(enabled, forKey: Self.enabledKey); restart() }
    }
    @Published var speak: Bool = UserDefaults.standard.object(forKey: ShareGuard.speakKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(speak, forKey: Self.speakKey) }
    }
    /// Şu an ekranı paylaşan/kaydeden uygulamalar.
    @Published private(set) var captures: [ScreenCapture] = []
    /// "Her zaman güven" denen uygulamalar (anahtar → ad).
    @Published private(set) var trusted: [String: String] = [:]
    /// Bu paylaşım için "Tanıyorum" denenler (paylaşım bitince silinir).
    @Published private(set) var acknowledged: Set<String> = []
    @Published private(set) var incidents: [ShareIncident] = []
    @Published private(set) var current: ShareIncident?
    @Published private(set) var lastActions: [String] = []

    private let log = CaptureLogWatcher()
    private var detector = SessionDetector()
    private var timer: Timer?
    private var busy = false
    private var dnsBaseline: Set<String> = []
    private let speech = AVSpeechSynthesizer()
    private var warnedSites: Set<String> = []

    /// Deneme: uyarılar normal pencerede açılır; PERMWATCH_SHARE_TEST_HOST ile banka sitesi taklit edilir.
    nonisolated static let testMode = ProcessInfo.processInfo.environment["PERMWATCH_SHARE_TEST"] != nil

    private init() {
        incidents = Self.loadIncidents()
        trusted = UserDefaults.standard.dictionary(forKey: Self.trustKey) as? [String: String] ?? [:]
        restart()
    }

    private func restart() {
        timer?.invalidate(); timer = nil
        log.stop()
        guard enabled, Snapshot.section == nil || Self.testMode else {
            captures = []; CaptureHUD.shared.update([]); return
        }
        log.start()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.poll() }
        }
    }

    // MARK: Yoklama

    private func poll() {
        guard !busy else { return }
        busy = true
        let logPIDs = log.activePIDs
        Task.detached(priority: .utility) {
            let obs = ShareGuard.observeRemoteTools()
            let caps = ShareGuard.describe(pids: logPIDs)
            await MainActor.run {
                let remote = self.detector.update(obs, now: Date())
                self.busy = false
                self.apply(caps, remote: remote)
            }
        }
    }

    /// Sistem kaydından gelen PID'leri uygulamalara çevirir (aynı uygulamanın birden fazla süreci tek satır).
    nonisolated static func describe(pids: Set<Int32>) -> [(key: String, name: String, path: String?, pid: Int32)] {
        var buf = [CChar](repeating: 0, count: 4096)
        return pids.compactMap { pid in
            guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return nil }
            let path = String(cString: buf)
            // Yardımcı süreçler (ör. Chrome Helper) ana uygulamaya bağlanır: en dıştaki .app
            let app = outermostApp(path)
            let key = app.flatMap { Bundle(path: $0)?.bundleIdentifier } ?? app ?? path
            let name = app.map { PathUtil.displayName($0) } ?? (path as NSString).lastPathComponent
            return (key, name, app ?? path, pid)
        }
    }

    nonisolated static func outermostApp(_ path: String) -> String? {
        guard let r = path.range(of: ".app/") else { return path.hasSuffix(".app") ? path : nil }
        return String(path[..<r.lowerBound]) + ".app"
    }

    private func apply(_ caps: [(key: String, name: String, path: String?, pid: Int32)], remote: [RemoteSession]) {
        var list: [String: ScreenCapture] = [:]
        for c in caps {
            if var e = list[c.key] { e.pids.append(c.pid); list[c.key] = e; continue }
            let start = log.startedAt(c.pid) ?? captures.first { $0.key == c.key }?.start ?? Date()
            let isTool = Checks.remoteTools.contains { Checks.matchesTool(c.name, $0.match) }
            list[c.key] = ScreenCapture(key: c.key, name: c.name, path: c.path, pids: [c.pid], start: start, kind: isTool ? .tool : .capture)
        }
        // Sistem kaydına düşmeyen eski yöntemli uzaktan kontrol programları ve macOS Ekran Paylaşımı
        for r in remote where r.kind != .ssh {
            let key = r.paths.first.flatMap(Self.outermostApp).flatMap { Bundle(path: $0)?.bundleIdentifier } ?? r.name
            if list[key] == nil {
                list[key] = ScreenCapture(key: key, name: r.name, path: r.paths.first, pids: r.pids, start: r.start, kind: r.kind)
            }
        }
        let now = list.values.sorted { $0.start < $1.start }
        if now != captures {
            captures = now
            if Self.testMode { FileHandle.standardError.write(Data("koruma: ekranı kullanan: \(now.map { "\($0.name) [\($0.kind.rawValue)]" })\n".utf8)) }
        }
        // Biten paylaşımların "Tanıyorum"u silinir (bir sonraki paylaşımda yeniden sorulur).
        acknowledged = acknowledged.filter { k in now.contains { $0.key == k } }
        if now.isEmpty { dnsBaseline = []; warnedSites = [] }
        CaptureHUD.shared.update(unacknowledged)
        if !unacknowledged.isEmpty { checkSensitiveSites() } else if let c = current, c.outcome == .open {
            var d = c; d.outcome = .ended; finish(d); ShareAlertController.shared.hide()
        }
    }

    /// Gösterge ve banka uyarısı için: tanınmamış paylaşımlar.
    var unacknowledged: [ScreenCapture] { captures.filter { trusted[$0.key] == nil && !acknowledged.contains($0.key) } }

    /// Uzaktan kontrol programlarının giden trafiği (eski yöntemle ekran yakalayanlar için yedek).
    nonisolated static func observeRemoteTools() -> [RemoteObservation] {
        let n = proc_listallpids(nil, 0)
        var pids = [Int32](repeating: 0, count: Int(max(n, 0)) + 64)
        let got = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size)))
        var buf = [CChar](repeating: 0, count: 4096)
        var found: [(Int32, String, String?, RemoteKind)] = []
        let me = getpid()
        var alive = Set<UInt64>()
        for pid in pids.prefix(max(0, got)) where pid > 0 && pid != me {
            var info = proc_bsdshortinfo()
            let key: UInt64
            if proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdshortinfo>.size)) > 0 {
                key = UInt64(UInt32(bitPattern: pid)) << 32 | UInt64(info.pbsi_ppid)
            } else { key = UInt64(UInt32(bitPattern: pid)) << 32 }
            alive.insert(key)
            let hit: (String, String?, RemoteKind)?
            if let c = classCache.get(key) { hit = c.hit } else {
                var path: String?
                if proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 { path = String(cString: buf) }
                var nameBuf = [CChar](repeating: 0, count: 256)
                let pname = proc_name(pid, &nameBuf, UInt32(nameBuf.count)) > 0 ? String(cString: nameBuf) : ""
                hit = classify(path: path, name: pname).map { ($0.name, path, $0.kind) }
                classCache.set(key, hit)
            }
            if let h = hit { found.append((pid, h.0, h.1, h.2)) }
        }
        classCache.retain(alive)
        guard !found.isEmpty else { return [] }
        let bytes = traffic(found.map(\.0))
        return found.map { RemoteObservation(pid: $0.0, name: $0.1, path: $0.2, kind: $0.3, bytes: bytes[$0.0] ?? -1) }
    }

    final class ClassCache: @unchecked Sendable {
        private let lock = NSLock()
        private var map: [UInt64: (String, String?, RemoteKind)?] = [:]
        func get(_ k: UInt64) -> (hit: (String, String?, RemoteKind)?, Void)? {
            lock.lock(); defer { lock.unlock() }
            guard let v = map[k] else { return nil }
            return (v, ())
        }
        func set(_ k: UInt64, _ v: (String, String?, RemoteKind)?) { lock.lock(); map[k] = .some(v); lock.unlock() }
        func retain(_ keys: Set<UInt64>) { lock.lock(); map = map.filter { keys.contains($0.key) }; lock.unlock() }
    }
    nonisolated static let classCache = ClassCache()

    /// Bir süreç uzaktan kontrol yolu mu? (ad, tür)
    nonisolated static func classify(path: String?, name: String) -> (name: String, kind: RemoteKind)? {
        if name == "screensharingd" || path == "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd" {
            return (L("sg.kind.screenSharing"), .screenSharing)
        }
        guard let path, !path.hasPrefix("/System/"), !path.hasPrefix("/usr/") else { return nil }
        let app = PathUtil.appBundle(path).map { ($0 as NSString).lastPathComponent } ?? ""
        let exe = (path as NSString).lastPathComponent
        for t in Checks.remoteTools where Checks.matchesTool(app, t.match) || Checks.matchesTool(exe, t.match) {
            return (t.name, .tool)
        }
        return nil
    }

    /// Süreçlerin giden ağ trafiği (bayt). Yalnızca giden: ekranı izlenen bilgisayar görüntüyü gönderir.
    nonisolated static func traffic(_ pids: [Int32]) -> [Int32: Int64] {
        guard !pids.isEmpty else { return [:] }
        var args = ["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"]
        for p in pids { args += ["-p", String(p)] }
        let out = Shell.run("/usr/bin/nettop", args).1
        var r: [Int32: Int64] = [:]
        for line in out.split(separator: "\n").dropFirst() {
            let cols = line.split(separator: ",", omittingEmptySubsequences: false)
            guard cols.count >= 3, let dot = cols[0].lastIndex(of: "."), let pid = Int32(cols[0][cols[0].index(after: dot)...]) else { continue }
            r[pid, default: 0] += Int64(cols[2]) ?? 0
        }
        return r
    }

    // MARK: Bilgi girişi: şifre alanı ya da banka/ödeme/kimlik sitesi

    /// Uyarıyı tetikleyen şey: "secure:<uygulama>" (şifre alanı) ya da alan adı.
    private func checkSensitiveSites() {
        // 1) Şifre alanı: macOS bir şifre alanına odaklanıldığında "güvenli klavye girişi"ni açar
        //    (Safari, Chrome, uygulamalar). Hangi uygulama açtıysa onun adı gösterilir.
        if let owner = SecureInput.owner() {
            let tag = "secure:" + owner.name
            if !warnedSites.contains(tag) {
                warnedSites.insert(tag)
                trigger(L("sg.trigger.password", owner.name))
            }
        }
        checkSites()
    }

    private func checkSites() {
        if dnsBaseline.isEmpty { dnsBaseline = Set((RootBridge.shared.data?.dns ?? [:]).keys) }
        var hosts: [String] = []
        if let dns = RootBridge.shared.data?.dns {
            for (ip, e) in dns where !dnsBaseline.contains(ip) { hosts.append(e.host) }
        }
        if let t = ProcessInfo.processInfo.environment["PERMWATCH_SHARE_TEST_HOST"] { hosts.append(t) }
        if let tab = BrowserTab.frontmostURLHost() { hosts.append(tab) }
        let sites = Array(Set(hosts.compactMap(SensitiveSites.match))).sorted()
        let fresh = sites.filter { !warnedSites.contains($0) }
        guard !fresh.isEmpty else { return }
        warnedSites.formUnion(fresh)
        trigger(L("sg.trigger.site", fresh.joined(separator: ", ")))
    }

    /// Ekranı kaplayan uyarı: paylaşım sürerken bilgi girişi.
    private func trigger(_ what: String) {
        let apps = unacknowledged.map(\.name)
        if var c = current, c.outcome == .open {
            if !c.sites.contains(what) { c.sites.append(what) }
            current = c; saveIncident(c)
        } else {
            current = ShareIncident(id: UUID().uuidString, date: Date(), apps: apps, sites: [what], actions: [], outcome: .open)
            if let c = current { saveIncident(c) }
        }
        ThreatCenter.shared.notifyShareSensitive(apps: apps.joined(separator: ", "), what: what)
        if speak { say(L("sg.speech")) }
        ShareAlertController.shared.show(self)
        if Self.testMode { FileHandle.standardError.write(Data("koruma: uyarı: \(what) (paylaşan: \(apps))\n".utf8)) }
    }

    private func say(_ text: String) {
        guard !Self.testMode else { FileHandle.standardError.write(Data("koruma: konuş: \(text)\n".utf8)); return }
        speech.stopSpeaking(at: .immediate)
        let u = AVSpeechUtterance(string: text)
        u.voice = AVSpeechSynthesisVoice(language: Locale.preferredLanguages.first)
        speech.speak(u)
    }

    // MARK: Eylemler

    /// "Tanıyorum": bu paylaşım için (always: bu uygulamaya her zaman) güven. Uzaktan kontrol programlarında
    /// Touch ID ya da Mac parolası istenir: uzaktaki kişi fareyle "Tanıyorum"a basamasın.
    func acknowledge(_ keys: [String], always: Bool, completion: ((Bool) -> Void)? = nil) {
        let needsAuth = captures.contains { keys.contains($0.key) && $0.isRemoteControl }
        let done: (Bool) -> Void = { ok in
            DispatchQueue.main.async {
                defer { completion?(ok) }
                guard ok else { return }
                for k in keys {
                    self.acknowledged.insert(k)
                    if always, let c = self.captures.first(where: { $0.key == k }) { self.trusted[k] = c.name }
                }
                UserDefaults.standard.set(self.trusted, forKey: Self.trustKey)
                CaptureHUD.shared.update(self.unacknowledged)
                if self.unacknowledged.isEmpty {
                    if var c = self.current, c.outcome == .open { c.outcome = .acknowledged; self.finish(c) }
                    self.speech.stopSpeaking(at: .immediate)
                    ShareAlertController.shared.hide()
                }
            }
        }
        if !needsAuth || Self.testMode { done(true); return }
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else { done(false); return }
        ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: L("sg.authReason")) { ok, _ in done(ok) }
    }

    func untrust(_ key: String) {
        trusted[key] = nil
        UserDefaults.standard.set(trusted, forKey: Self.trustKey)
    }

    /// "Paylaşımı Durdur": paylaşan uygulamayı kapatır. Uzaktan kontrol programlarında ayrıca sunucularını
    /// engeller, ekran kaydı ve kontrol izinlerini ve başlangıç öğelerini kaldırır.
    func stopSharing(_ keys: [String]? = nil) {
        let targets = captures.filter { (keys ?? unacknowledged.map(\.key)).contains($0.key) }
        var actions: [String] = []
        for c in targets {
            switch c.kind {
            case .screenSharing:
                actions.append(L("sg.act.sharingSettings"))
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")!)
                continue
            default: break
            }
            let remotes = c.kind == .tool ? Self.remoteIPs(pids: c.pids) : []
            // Önce nazikçe kapat (uygulama ise), olmazsa zorla.
            var closed = false
            if let app = c.path, app.hasSuffix(".app"),
               let running = NSWorkspace.shared.runningApplications.first(where: { $0.bundleURL?.path == app }) {
                closed = running.forceTerminate()
            }
            for pid in c.pids where Darwin.kill(pid, SIGKILL) == 0 { closed = true }
            actions.append(closed ? L("sg.act.closed", c.name) : L("sg.act.closeFailed", c.name))
            guard c.kind == .tool else { continue }
            if RootBridge.shared.active {
                for ip in remotes where !BlockList.shared.contains(ip) { BlockList.shared.toggle(ip) }
                if !remotes.isEmpty { actions.append(L("sg.act.blocked", remotes.count.formatted())) }
            }
            if let app = c.path, let bid = Bundle(path: app)?.bundleIdentifier {
                var ok = 0
                for svc in ["ScreenCapture", "Accessibility", "PostEvent", "ListenEvent"] where TCCReset.reset(service: svc, bundleID: bid).0 { ok += 1 }
                if ok > 0 { actions.append(L("sg.act.revoked", c.name)) }
            }
            let agents = NSHomeDirectory() + "/Library/LaunchAgents"
            for f in (try? FileManager.default.contentsOfDirectory(atPath: agents)) ?? [] where Checks.remoteTools.contains(where: { Checks.matchesTool(c.name, $0.match) && Checks.matchesTool(f, $0.match) }) {
                if Checks.disableLaunchItem(agents + "/" + f) == L("fix.done") { actions.append(L("sg.act.loginItem", f)) }
            }
        }
        lastActions = actions
        if var c = current { c.actions += actions; c.outcome = .stopped; finish(c) }
        speech.stopSpeaking(at: .immediate)
        detector = SessionDetector()
        captures.removeAll { c in targets.contains { $0.key == c.key } }
        CaptureHUD.shared.update(unacknowledged)
        if Self.testMode { FileHandle.standardError.write(Data("koruma: durdur \(targets.map(\.name)) → \(actions)\n".utf8)) }
    }

    /// "İnterneti Kes": Wi-Fi'yi kapatır; her uzaktan oturum anında düşer.
    func cutInternet() -> Bool {
        let ok: Bool
        if Self.testMode { ok = true } else {
            do { try CWWiFiClient.shared().interface()?.setPower(false); ok = true } catch { ok = false }
        }
        let msg = ok ? L("sg.act.wifiOff") : L("sg.act.wifiFailed")
        lastActions.append(msg)
        if var c = current { c.actions.append(msg); current = c; saveIncident(c) }
        return ok
    }

    // MARK: Kayıtlar

    private func finish(_ c: ShareIncident) {
        current = c.outcome == .open ? c : nil
        saveIncident(c)
        if Self.testMode { FileHandle.standardError.write(Data("koruma: olay \(c.outcome.rawValue) \(c.apps) \(c.sites) \(c.actions)\n".utf8)) }
    }

    private func saveIncident(_ c: ShareIncident) {
        incidents.removeAll { $0.id == c.id }
        incidents.insert(c, at: 0)
        if incidents.count > 30 { incidents.removeLast(incidents.count - 30) }
        Self.saveIncidents(incidents)
    }

    func deleteIncident(_ i: ShareIncident) { incidents.removeAll { $0.id == i.id }; Self.saveIncidents(incidents) }

    nonisolated static var incidentsPath: String { NSHomeDirectory() + "/Library/Application Support/permwatch/share-incidents.json" }

    nonisolated static func loadIncidents() -> [ShareIncident] {
        guard let d = FileManager.default.contents(atPath: incidentsPath) else { return [] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return (try? dec.decode([ShareIncident].self, from: d)) ?? []
    }

    nonisolated static func saveIncidents(_ list: [ShareIncident]) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        guard let d = try? enc.encode(list) else { return }
        try? FileManager.default.createDirectory(atPath: (incidentsPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try? d.write(to: URL(fileURLWithPath: incidentsPath), options: .atomic)
    }

    nonisolated static func remoteIPs(pids: [Int32]) -> [String] {
        var ips = Set<String>()
        for pid in pids {
            for line in Shell.run("/usr/sbin/lsof", ["-nP", "-a", "-p", String(pid), "-i"]).1.split(separator: "\n").dropFirst() {
                guard let arrow = line.range(of: "->") else { continue }
                let rest = line[arrow.upperBound...].split(separator: " ").first.map(String.init) ?? ""
                let host = BlockList.host(of: rest)
                if BlockList.isIP(host), !Conversation.isLocal(host) { ips.insert(host) }
            }
        }
        return Array(ips).sorted()
    }

    /// Uyarıdan bu yana Mac'te değişenler: yeni uygulamalar, başlangıç öğeleri, tarayıcı uzantıları.
    nonisolated static func changes(since: Date) -> [String] {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        var out: [String] = []
        func newer(_ path: String) -> Bool {
            guard let a = try? fm.attributesOfItem(atPath: path) else { return false }
            let d = (a[.creationDate] as? Date) ?? (a[.modificationDate] as? Date) ?? .distantPast
            return d >= since
        }
        for dir in ["/Applications", home + "/Applications"] {
            for f in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] where f.hasSuffix(".app") && newer(dir + "/" + f) {
                out.append(L("sg.change.app", (f as NSString).deletingPathExtension))
            }
        }
        for dir in [home + "/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"] {
            for f in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] where f.hasSuffix(".plist") && newer(dir + "/" + f) {
                out.append(L("sg.change.launch", f))
            }
        }
        for (dir, browser) in [("Google/Chrome", "Chrome"), ("BraveSoftware/Brave-Browser", "Brave"), ("Microsoft Edge", "Edge"), ("Arc/User Data", "Arc")] {
            let base = home + "/Library/Application Support/" + dir
            for prof in ((try? fm.contentsOfDirectory(atPath: base)) ?? []) where prof == "Default" || prof.hasPrefix("Profile ") {
                let ext = base + "/" + prof + "/Extensions"
                for id in (try? fm.contentsOfDirectory(atPath: ext)) ?? [] where newer(ext + "/" + id) {
                    out.append(L("sg.change.extension", browser, id))
                }
            }
        }
        return out
    }
}

/// macOS "güvenli klavye girişi": bir şifre alanına odaklanıldığında açılır. İzin gerekmez.
enum SecureInput {
    @_silgen_name("IsSecureEventInputEnabled") private static func isEnabled() -> DarwinBoolean

    /// Açıksa açan uygulama (ad, PID); kapalıysa nil. Paylaşım sürmüyorsa hiç çağrılmaz.
    static func owner() -> (name: String, pid: Int32)? {
        if ProcessInfo.processInfo.environment["PERMWATCH_SHARE_TEST_SECURE"] != nil { return ("Safari", 1) }
        guard isEnabled().boolValue else { return nil }
        // Sahibi: WindowServer oturum bilgisindeki kCGSSessionSecureInputPID
        let out = Shell.run("/usr/sbin/ioreg", ["-l", "-w", "0", "-d", "1", "-k", "IOConsoleUsers"]).1
        var pid: Int32 = 0
        if let r = out.range(of: "\"kCGSSessionSecureInputPID\"=") {
            pid = Int32(out[r.upperBound...].prefix { $0.isNumber }) ?? 0
        }
        var buf = [CChar](repeating: 0, count: 4096)
        var name = "?"
        if pid > 0, proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 {
            let path = String(cString: buf)
            name = ShareGuard.outermostApp(path).map { PathUtil.displayName($0) } ?? (path as NSString).lastPathComponent
        }
        return (name, pid)
    }
}

/// Öndeki tarayıcının etkin sekmesinin alan adı (yalnızca oturum sırasında, AppleScript ile).
/// İlk kullanımda macOS "permwatch, Chrome'u denetlemek istiyor" izni sorar.
enum BrowserTab {
    static let scripts: [String: String] = [
        "com.apple.Safari": "tell application id \"com.apple.Safari\" to return URL of front document",
        "com.google.Chrome": "tell application id \"com.google.Chrome\" to return URL of active tab of front window",
        "com.brave.Browser": "tell application id \"com.brave.Browser\" to return URL of active tab of front window",
        "com.microsoft.edgemac": "tell application id \"com.microsoft.edgemac\" to return URL of active tab of front window",
        "company.thebrowser.Browser": "tell application id \"company.thebrowser.Browser\" to return URL of active tab of front window",
        "com.operasoftware.Opera": "tell application id \"com.operasoftware.Opera\" to return URL of active tab of front window",
        "com.vivaldi.Vivaldi": "tell application id \"com.vivaldi.Vivaldi\" to return URL of active tab of front window",
    ]

    @MainActor
    static func frontmostURLHost() -> String? {
        guard let bid = NSWorkspace.shared.frontmostApplication?.bundleIdentifier, let src = scripts[bid] else { return nil }
        var err: NSDictionary?
        guard let s = NSAppleScript(source: src)?.executeAndReturnError(&err).stringValue, let u = URL(string: s) else { return nil }
        return u.host
    }

    /// Ayarlardan "Tarayıcı iznini ver": kurulu tarayıcılar için izin sorusunu önceden çıkarır.
    @MainActor
    static func requestPermissions() {
        for (bid, src) in scripts where NSWorkspace.shared.urlForApplication(withBundleIdentifier: bid) != nil {
            guard NSRunningApplication.runningApplications(withBundleIdentifier: bid).first != nil else { continue }
            var err: NSDictionary?
            _ = NSAppleScript(source: src)?.executeAndReturnError(&err)
        }
    }
}
