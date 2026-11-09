import AppKit
import AVFoundation
import CoreWLAN
import Foundation
import LocalAuthentication
import UserNotifications

// MARK: - Dolandırıcılık Kalkanı
//
// "Polisiz / savcıyız / bankadan arıyoruz" dolandırıcılığının ortak adımı: kurbana bir uzaktan erişim
// programı kurdurulur, sonra kurban banka sitesine girerken ekranı izlenir ya da kontrol edilir.
// Kalkan, gerçek bir uzaktan oturum başladığı anda ekranın tamamını kaplayan bir uyarı gösterir ve
// bağlantıyı tek tuşla keser. Antivirüsler bunu yakalamaz: uzaktan erişim programları zararlı değildir.
//
// Tespit:
//  - Bilinen uzaktan erişim programları (AnyDesk, TeamViewer, ToDesk…): program çalışıyor VE ekran
//    görüntüsü dışarı akıyor (birkaç saniye boyunca yüksek trafik). Boştaki bağlantı (yalnızca sunucuya
//    bağlı bekleme) oturum sayılmaz.
//  - Apple Ekran Paylaşımı: screensharingd yalnızca bağlantı varken çalışır ve trafik üretir.
//  - SSH: her uzak oturum için ayrı bir sshd-session süreci açılır.

/// İzlenen uzaktan erişim yolları.
enum RemoteKind: String, Codable { case tool, screenSharing, ssh }

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
            case .ssh: isHot = true                                   // her sshd-session bir uzak oturumdur
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

/// Bir dolandırıcılık uyarısının kaydı (raporda ve geçmişte gösterilir).
struct ScamIncident: Codable, Identifiable, Equatable {
    var id: String
    var start: Date
    var end: Date?
    var tools: [String]
    var kind: RemoteKind
    var sensitiveSites: [String]
    var actions: [String]
    var outcome: Outcome

    enum Outcome: String, Codable { case open, disconnected, allowed, ended }
}

// MARK: - Kalkan

@MainActor
final class ScamShield: ObservableObject {
    static let shared = ScamShield()
    static let enabledKey = "scamShield"
    static let speakKey = "scamShieldSpeak"
    static let allowKey = "scamShieldAllowed"

    @Published var enabled: Bool = UserDefaults.standard.object(forKey: ScamShield.enabledKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(enabled, forKey: Self.enabledKey); reschedule() }
    }
    @Published var speak: Bool = UserDefaults.standard.object(forKey: ScamShield.speakKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(speak, forKey: Self.speakKey) }
    }
    @Published private(set) var sessions: [RemoteSession] = []
    @Published private(set) var installedTools: [String] = []
    @Published private(set) var incidents: [ScamIncident] = []
    @Published private(set) var current: ScamIncident?
    @Published private(set) var lastActions: [String] = []
    /// Kullanıcının Touch ID/parolayla onayladığı araçlar: ad → bitiş zamanı (nil: her zaman).
    @Published private(set) var allowed: [String: Date?] = [:]

    private var detector = SessionDetector()
    private var timer: Timer?
    private var busy = false
    private var dnsBaseline: Set<String> = []
    private let speech = AVSpeechSynthesizer()
    private var spokenFor: String?

    /// Deneme: uyarı normal pencerede açılır, "Bağlantıyı Kes" kendiliğinden seçilir (gerçek programlar yok).
    nonisolated static let testMode = ProcessInfo.processInfo.environment["PERMWATCH_SCAM_TEST"] != nil

    private init() {
        incidents = Self.loadIncidents()
        if let d = UserDefaults.standard.dictionary(forKey: Self.allowKey) {
            for (k, v) in d { allowed[k] = (v as? Date) ?? (v as? Bool == true ? Date?.none : Date.distantPast) }
        }
        refreshInstalled()
        reschedule()
    }

    private func reschedule() {
        timer?.invalidate(); timer = nil
        guard enabled, Snapshot.section == nil || Self.testMode else { sessions = []; return }
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.poll() }
        }
    }

    func refreshInstalled() {
        Task.detached(priority: .utility) {
            let names = Checks.remoteApps().map { String($0.id.dropFirst("remote.".count)) }.sorted()
            await MainActor.run { self.installedTools = names }
        }
    }

    // MARK: Yoklama

    private func poll() {
        guard !busy else { return }
        busy = true
        Task.detached(priority: .userInitiated) {
            let obs = ScamShield.observe()
            await MainActor.run {
                let s = self.detector.update(obs, now: Date())
                self.busy = false
                self.apply(s)
            }
        }
    }

    /// Uzaktan erişimle ilgili süreçler ve (gerekiyorsa) trafikleri.
    nonisolated static func observe() -> [RemoteObservation] {
        let n = proc_listallpids(nil, 0)
        var pids = [Int32](repeating: 0, count: Int(max(n, 0)) + 64)
        let got = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size)))
        var buf = [CChar](repeating: 0, count: 4096)
        var found: [(Int32, String, String?, RemoteKind)] = []
        let me = getpid()
        var alive = Set<UInt64>()
        for pid in pids.prefix(max(0, got)) where pid > 0 && pid != me {
            // Süreç kimliği: pid + başlangıç zamanı (pid yeniden kullanılabilir). Sınıflandırma süreç başına bir kez.
            var info = proc_bsdshortinfo()
            let key: UInt64
            if proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdshortinfo>.size)) > 0 {
                key = UInt64(UInt32(bitPattern: pid)) << 32 | UInt64(info.pbsi_ppid)
            } else { key = UInt64(UInt32(bitPattern: pid)) << 32 }
            alive.insert(key)
            let cached = classCache.get(key)
            let hit: (String, String?, RemoteKind)?
            if let c = cached { hit = c.hit } else {
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
        // Trafik yalnızca aday süreçler için ölçülür (nettop, yönetici izni gerektirmez).
        let bytes = traffic(found.filter { $0.3 != .ssh }.map(\.0))
        return found.map { RemoteObservation(pid: $0.0, name: $0.1, path: $0.2, kind: $0.3, bytes: bytes[$0.0] ?? -1) }
    }

    /// Süreç sınıflandırma önbelleği (yoklama başına yalnızca yeni süreçler incelenir).
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

    /// Bir süreç uzaktan erişim yolu mu? (ad, tür)
    nonisolated static func classify(path: String?, name: String) -> (name: String, kind: RemoteKind)? {
        if name == "screensharingd" || path == "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd" {
            return (L("scam.kind.screenSharing"), .screenSharing)
        }
        if name == "sshd-session" { return ("SSH", .ssh) }
        guard let path, !path.hasPrefix("/System/"), !path.hasPrefix("/usr/") else { return nil }
        // Uygulama paketi adı ya da program adı katalogdaki bir araçla ayrı kelime olarak eşleşmeli.
        let app = PathUtil.appBundle(path).map { ($0 as NSString).lastPathComponent } ?? ""
        let exe = (path as NSString).lastPathComponent
        for t in Checks.remoteTools where Checks.matchesTool(app, t.match) || Checks.matchesTool(exe, t.match) {
            return (t.name, .tool)
        }
        return nil
    }

    /// Süreçlerin giden ağ trafiği (bayt) — nettop -p ile yalnızca istenen süreçler.
    nonisolated static func traffic(_ pids: [Int32]) -> [Int32: Int64] {
        guard !pids.isEmpty else { return [:] }
        var args = ["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"]
        for p in pids { args += ["-p", String(p)] }
        let out = Shell.run("/usr/bin/nettop", args).1
        var r: [Int32: Int64] = [:]
        for line in out.split(separator: "\n").dropFirst() {
            let cols = line.split(separator: ",", omittingEmptySubsequences: false)
            guard cols.count >= 3, let dot = cols[0].lastIndex(of: "."), let pid = Int32(cols[0][cols[0].index(after: dot)...]) else { continue }
            r[pid, default: 0] += Int64(cols[2]) ?? 0   // bytes_out
        }
        return r
    }

    // MARK: Uyarı

    private func isAllowed(_ name: String) -> Bool {
        guard let e = allowed[name] else { return false }
        guard let until = e else { return true }
        return until > Date()
    }

    private func apply(_ s: [RemoteSession]) {
        let live = s.filter { !isAllowed($0.name) }
        if sessions != live { sessions = live }
        if live.isEmpty {
            if var c = current, c.outcome == .open {
                c.end = Date(); c.outcome = .ended
                finish(c)
            }
            ScamAlertController.shared.hide()
            return
        }
        if current == nil {
            let first = live[0]
            current = ScamIncident(id: UUID().uuidString, start: first.start, end: nil, tools: live.map(\.name), kind: first.kind,
                                   sensitiveSites: [], actions: [], outcome: .open)
            dnsBaseline = Set((RootBridge.shared.data?.dns ?? [:]).keys)
            ThreatCenter.shared.notifyScam(tools: live.map(\.name).joined(separator: ", "))
            if speak { say(L("scam.speech")) }
        } else if var c = current {
            for n in live.map(\.name) where !c.tools.contains(n) { c.tools.append(n) }
            current = c
        }
        checkSensitiveSites()
        ScamAlertController.shared.show(self)
    }

    /// Oturum açıkken banka/ödeme/kimlik sitesine girildi mi? (DNS izleme ve etkin tarayıcı sekmesi)
    private func checkSensitiveSites() {
        guard var c = current else { return }
        var hosts: [String] = []
        if let dns = RootBridge.shared.data?.dns {
            for (ip, e) in dns where !dnsBaseline.contains(ip) { hosts.append(e.host) }
        }
        if let test = ProcessInfo.processInfo.environment["PERMWATCH_SCAM_TEST_HOST"] { hosts.append(test) }
        let tab = BrowserTab.frontmostURLHost()
        if let tab { hosts.append(tab) }
        var added = false
        for h in hosts { if let m = SensitiveSites.match(h), !c.sensitiveSites.contains(m) { c.sensitiveSites.append(m); added = true } }
        if added {
            current = c
            if speak { say(L("scam.speechBank")) }
        }
    }

    private func say(_ text: String) {
        guard !Self.testMode else { FileHandle.standardError.write(Data("kalkan: konuş: \(text)\n".utf8)); return }
        speech.stopSpeaking(at: .immediate)
        let u = AVSpeechUtterance(string: text)
        u.voice = AVSpeechSynthesisVoice(language: Locale.preferredLanguages.first)
        speech.speak(u)
    }

    // MARK: Eylemler

    /// "Bağlantıyı Kes": programları kapatır, sunucularını engeller, izinlerini ve başlangıç öğelerini kaldırır.
    func disconnect() {
        if Self.testMode { FileHandle.standardError.write(Data("kalkan: kes (olay: \(current != nil), oturumlar: \(sessions.map(\.name)))\n".utf8)) }
        var actions: [String] = []
        let live = sessions
        for s in live {
            switch s.kind {
            case .tool:
                // Uzak adresleri öldürmeden önce topla (engellemek için).
                let remotes = Self.remoteIPs(pids: s.pids)
                var killed = 0, failed = 0
                for pid in s.pids { if Darwin.kill(pid, SIGKILL) == 0 { killed += 1 } else { failed += 1 } }
                // Aynı aracın sonradan açılan diğer süreçleri de
                for o in Self.observe() where o.name == s.name && !s.pids.contains(o.pid) { _ = Darwin.kill(o.pid, SIGKILL) }
                actions.append(killed > 0 ? L("scam.act.killed", s.name) : L("scam.act.killFailed", s.name))
                if failed > 0 && killed == 0 { actions.append(L("scam.act.needWifi")) }
                if RootBridge.shared.active {
                    for ip in remotes where !BlockList.shared.contains(ip) { BlockList.shared.toggle(ip) }
                    if !remotes.isEmpty { actions.append(L("scam.act.blocked", remotes.count.formatted())) }
                }
                // Ekran kaydı, erişilebilirlik ve klavye izinleri
                for bid in Self.bundleIDs(paths: s.paths) {
                    var ok = 0
                    for svc in ["ScreenCapture", "Accessibility", "PostEvent", "ListenEvent"] where TCCReset.reset(service: svc, bundleID: bid).0 { ok += 1 }
                    if ok > 0 { actions.append(L("scam.act.revoked", s.name)) }
                }
                // Kullanıcının başlangıç öğeleri (yeniden açılmasın)
                let agents = NSHomeDirectory() + "/Library/LaunchAgents"
                for f in (try? FileManager.default.contentsOfDirectory(atPath: agents)) ?? [] where Checks.remoteTools.contains(where: { $0.name == s.name && Checks.matchesTool(f, $0.match) }) {
                    if Checks.disableLaunchItem(agents + "/" + f) == L("fix.done") { actions.append(L("scam.act.loginItem", f)) }
                }
            case .screenSharing, .ssh:
                // Sistem servisleri root olarak çalışır: en güvenilir kesme internet bağlantısını kapatmak.
                actions.append(L(s.kind == .ssh ? "scam.act.sshSettings" : "scam.act.sharingSettings"))
            }
        }
        if live.contains(where: { $0.kind != .tool }) {
            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")!)
        }
        lastActions = actions
        if var c = current {
            c.actions += actions; c.outcome = .disconnected; c.end = Date()
            finish(c)
        }
        speech.stopSpeaking(at: .immediate)
        sessions = []
        detector = SessionDetector()
        ScamAlertController.shared.showReport()
    }

    /// "İnterneti Kes": Wi-Fi'yi kapatır (her uzaktan oturum anında düşer).
    func cutInternet() -> Bool {
        let ok: Bool
        if Self.testMode { ok = true } else {
            do { try CWWiFiClient.shared().interface()?.setPower(false); ok = true } catch { ok = false }
        }
        let msg = ok ? L("scam.act.wifiOff") : L("scam.act.wifiFailed")
        lastActions.append(msg)
        if var c = current { c.actions.append(msg); current = c }
        return ok
    }

    /// "Bu bağlantıyı tanıyorum": Touch ID ya da Mac parolası ister (uzaktaki kişi fareyle basamasın).
    func allowCurrent(always: Bool) {
        let names = sessions.map(\.name)
        let ctx = LAContext()
        let done: (Bool) -> Void = { ok in
            DispatchQueue.main.async {
                guard ok else { return }
                for n in names { self.allowed[n] = always ? Date?.none : Date().addingTimeInterval(3600) }
                self.saveAllowed()
                if var c = self.current { c.outcome = .allowed; c.end = Date(); self.finish(c) }
                self.speech.stopSpeaking(at: .immediate)
                ScamAlertController.shared.hide()
            }
        }
        if Self.testMode { done(true); return }
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else { done(false); return }
        ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: L("scam.authReason")) { ok, _ in done(ok) }
    }

    func removeAllowed(_ name: String) { allowed[name] = nil; saveAllowed() }

    private func saveAllowed() {
        var d: [String: Any] = [:]
        for (k, v) in allowed { d[k] = v ?? true }
        UserDefaults.standard.set(d, forKey: Self.allowKey)
    }

    // MARK: Olay kaydı

    private func finish(_ c: ScamIncident) {
        incidents.removeAll { $0.id == c.id }
        incidents.insert(c, at: 0)
        if incidents.count > 30 { incidents.removeLast(incidents.count - 30) }
        current = c.outcome == .open ? c : nil
        Self.saveIncidents(incidents)
        if Self.testMode { FileHandle.standardError.write(Data("kalkan: olay \(c.outcome.rawValue) \(c.tools) siteler=\(c.sensitiveSites) eylemler=\(c.actions)\n".utf8)) }
    }

    nonisolated static var incidentsPath: String { NSHomeDirectory() + "/Library/Application Support/permwatch/scam-incidents.json" }

    nonisolated static func loadIncidents() -> [ScamIncident] {
        guard let d = FileManager.default.contents(atPath: incidentsPath) else { return [] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return (try? dec.decode([ScamIncident].self, from: d)) ?? []
    }

    nonisolated static func saveIncidents(_ list: [ScamIncident]) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        guard let d = try? enc.encode(list) else { return }
        try? FileManager.default.createDirectory(atPath: (incidentsPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try? d.write(to: URL(fileURLWithPath: incidentsPath), options: .atomic)
    }

    func deleteIncident(_ i: ScamIncident) {
        incidents.removeAll { $0.id == i.id }
        Self.saveIncidents(incidents)
    }

    // MARK: Yardımcılar

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

    nonisolated static func bundleIDs(paths: [String]) -> [String] {
        var out = Set<String>()
        for p in paths {
            if let app = PathUtil.appBundle(p), let id = Bundle(path: app)?.bundleIdentifier { out.insert(id) }
        }
        return Array(out)
    }

    /// Kullanıcıya gösterilecek "Son bir saatte neler değişti" listesi (olay başlangıcından 15 dk önce itibaren).
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
                out.append(L("scam.change.app", (f as NSString).deletingPathExtension))
            }
        }
        for dir in [home + "/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"] {
            for f in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] where f.hasSuffix(".plist") && newer(dir + "/" + f) {
                out.append(L("scam.change.launch", f))
            }
        }
        // Chromium tabanlı tarayıcılara yeni eklenen uzantılar
        for (dir, browser) in [("Google/Chrome", "Chrome"), ("BraveSoftware/Brave-Browser", "Brave"), ("Microsoft Edge", "Edge"), ("Arc/User Data", "Arc")] {
            let base = home + "/Library/Application Support/" + dir
            for prof in ((try? fm.contentsOfDirectory(atPath: base)) ?? []) where prof == "Default" || prof.hasPrefix("Profile ") {
                let ext = base + "/" + prof + "/Extensions"
                for id in (try? fm.contentsOfDirectory(atPath: ext)) ?? [] where newer(ext + "/" + id) {
                    out.append(L("scam.change.extension", browser, id))
                }
            }
        }
        return out
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
