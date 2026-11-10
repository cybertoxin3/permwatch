import Foundation

/// Açık tehdit kaynakları: bilinen zararlı sunucular ve ek zararlı imzaları. Günde bir kez indirilir;
/// hiçbir şey gönderilmez (yalnızca listeler indirilir). Ayarlar'dan kapatılabilir.
///
/// - Zararlı alan adları: URLhaus (abuse.ch) listesinin malware-filter aynası (CC0)
/// - Zararlı IP adresleri: Feodo Tracker (abuse.ch) önerilen engel listesi (CC0)
/// - Ek YARA kuralları: Elastic Security'nin macOS kuralları (Elastic License 2.0)
@MainActor
final class ThreatIntel: ObservableObject {
    static let shared = ThreatIntel()
    static let enabledKey = "threatIntel"
    static let allowKey = "intelAllowed"
    static let lastKey = "intelLastUpdate"

    nonisolated static let dir = NSHomeDirectory() + "/Library/Application Support/permwatch/intel"
    nonisolated static let rulesDir = dir + "/rules"
    nonisolated static let bundledRules = Bundle.main.resourcePath.map { $0 + "/rules/elastic" } ?? ""
    nonisolated static let dnsFlag = NSHomeDirectory() + "/Library/Application Support/permwatch/dnswatch.on"

    static let hostsURL = URL(string: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt")!
    static let phishURL = URL(string: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt")!
    static let ipsURL = URL(string: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")!
    static let treeURL = URL(string: "https://api.github.com/repos/elastic/protections-artifacts/git/trees/main?recursive=1")!
    static let rawBase = "https://raw.githubusercontent.com/elastic/protections-artifacts/main/"

    @Published var enabled: Bool = UserDefaults.standard.object(forKey: ThreatIntel.enabledKey) as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(enabled, forKey: Self.enabledKey)
            syncFlag()
            if enabled { update(force: true) }
        }
    }
    @Published private(set) var updating = false
    @Published private(set) var lastUpdate: Date? = UserDefaults.standard.object(forKey: ThreatIntel.lastKey) as? Date
    @Published private(set) var domainCount = 0
    @Published private(set) var ipCount = 0
    @Published private(set) var error: String?
    @Published private(set) var allowed: Set<String> = Set(UserDefaults.standard.stringArray(forKey: ThreatIntel.allowKey) ?? [])

    private init() {
        Self.store.load()
        domainCount = Self.store.counts.domains
        ipCount = Self.store.counts.ips
        Self.store.setAllowed(allowed)
        syncFlag()
        // Uygulama günlerce açık kalabilir: saatte bir "bir gün geçti mi" diye bak.
        timer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.update() }
        }
    }
    private var timer: Timer?

    /// Yönetici yardımcısına "DNS yanıtlarını izle" bayrağı (yalnızca bu özellik açıkken).
    func syncFlag() {
        let fm = FileManager.default
        if enabled {
            try? fm.createDirectory(atPath: (Self.dnsFlag as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            if !fm.fileExists(atPath: Self.dnsFlag) { fm.createFile(atPath: Self.dnsFlag, contents: nil, attributes: [.posixPermissions: 0o600]) }
        } else {
            try? fm.removeItem(atPath: Self.dnsFlag)
        }
    }

    /// "Bu sunucuyu tanıyorum": bir daha uyarma.
    func allow(_ key: String) {
        allowed.insert(key)
        UserDefaults.standard.set(Array(allowed), forKey: Self.allowKey)
        Self.store.setAllowed(allowed)
    }

    func update(force: Bool = false) {
        guard enabled, !updating, Snapshot.section == nil else { return }
        if !force, let l = lastUpdate, Date().timeIntervalSince(l) < 86_400 { return }
        updating = true
        error = nil
        Task.detached(priority: .utility) {
            let err = await ThreatIntel.download()
            Self.store.load()
            let reload = YaraEngine.shared.load(force: true)
            await MainActor.run {
                self.updating = false
                self.domainCount = Self.store.counts.domains
                self.ipCount = Self.store.counts.ips
                self.error = err ?? reload
                if err == nil {
                    self.lastUpdate = Date()
                    UserDefaults.standard.set(self.lastUpdate, forKey: Self.lastKey)
                }
            }
        }
    }

    // MARK: İndirme

    nonisolated private static func fetch(_ url: URL) async -> Data? {
        var req = URLRequest(url: url, timeoutInterval: 30)
        req.setValue("permwatch/\(UpdateChecker.current)", forHTTPHeaderField: "User-Agent")
        guard let (d, r) = try? await URLSession.shared.data(for: req), (r as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        return d
    }

    /// Hata varsa açıklaması döner; eski listeler yerinde kalır.
    nonisolated static func download() async -> String? {
        let fm = FileManager.default
        try? fm.createDirectory(atPath: rulesDir, withIntermediateDirectories: true)
        var failed: [String] = []
        if let d = await fetch(hostsURL), let t = String(data: d, encoding: .utf8) {
            let hosts = parseHosts(t)
            if hosts.count > 50 { try? hosts.joined(separator: "\n").write(toFile: dir + "/hosts.txt", atomically: true, encoding: .utf8) }
        } else { failed.append("URLhaus") }
        if let d = await fetch(phishURL), let t = String(data: d, encoding: .utf8) {
            let hosts = parseHosts(t)
            if hosts.count > 50 { try? hosts.joined(separator: "\n").write(toFile: dir + "/phish.txt", atomically: true, encoding: .utf8) }
        } else { failed.append("phishing-filter") }
        if let d = await fetch(ipsURL), let t = String(data: d, encoding: .utf8) {
            let ips = parseIPs(t)
            try? ips.joined(separator: "\n").write(toFile: dir + "/ips.txt", atomically: true, encoding: .utf8)
        } else { failed.append("Feodo") }
        if await updateRules() == false { failed.append("Elastic") }
        return failed.isEmpty ? nil : L("intel.failed", failed.joined(separator: ", "))
    }

    /// Elastic kurallarından yalnızca macOS ve çok platformlu olanları, yalnızca değişenleri indirir.
    nonisolated static func updateRules() async -> Bool {
        guard let d = await fetch(treeURL),
              let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let tree = j["tree"] as? [[String: Any]] else { return false }
        let manifestPath = rulesDir + "/manifest.json"
        var manifest = (try? JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: manifestPath)))) as? [String: String] ?? [:]
        var wanted = Set<String>()
        for e in tree {
            guard let path = e["path"] as? String, let sha = e["sha"] as? String, path.hasPrefix("yara/rules/") else { continue }
            let name = (path as NSString).lastPathComponent
            guard name.hasSuffix(".yar"), name.hasPrefix("MacOS_") || name.hasPrefix("Multi_") else { continue }
            wanted.insert(name)
            if manifest[name] == sha, FileManager.default.fileExists(atPath: rulesDir + "/" + name) { continue }
            guard let body = await fetch(URL(string: rawBase + path)!) else { return false }
            try? body.write(to: URL(fileURLWithPath: rulesDir + "/" + name))
            manifest[name] = sha
        }
        guard !wanted.isEmpty else { return false }
        for name in manifest.keys where !wanted.contains(name) {
            try? FileManager.default.removeItem(atPath: rulesDir + "/" + name)
            manifest[name] = nil
        }
        if let m = try? JSONSerialization.data(withJSONObject: manifest) { try? m.write(to: URL(fileURLWithPath: manifestPath)) }
        return true
    }

    nonisolated static func parseHosts(_ t: String) -> [String] {
        t.components(separatedBy: .newlines).compactMap { line in
            let l = line.trimmingCharacters(in: .whitespaces)
            guard !l.isEmpty, !l.hasPrefix("#") else { return nil }
            let parts = l.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let h = parts.last.map({ String($0).lowercased() }), h.contains("."), h != "0.0.0.0", h != "localhost" else { return nil }
            return h
        }
    }

    nonisolated static func parseIPs(_ t: String) -> [String] {
        t.components(separatedBy: .newlines).compactMap { line in
            let l = line.trimmingCharacters(in: .whitespaces)
            return !l.isEmpty && !l.hasPrefix("#") && BlockList.isIP(l) ? l : nil
        }
    }

    // MARK: Eşleştirme (her iş parçacığından)

    nonisolated static let store = Store()

    final class Store: @unchecked Sendable {
        private let lock = NSLock()
        private var domains = Set<String>()
        private var ips = Set<String>()
        private var allowed = Set<String>()
        private var phish = Set<String>()

        var counts: (domains: Int, ips: Int) { lock.lock(); defer { lock.unlock() }; return (domains.count, ips.count) }

        func load() {
            let h = (try? String(contentsOfFile: ThreatIntel.dir + "/hosts.txt", encoding: .utf8)) ?? ""
            let i = (try? String(contentsOfFile: ThreatIntel.dir + "/ips.txt", encoding: .utf8)) ?? ""
            set(domains: h.split(separator: "\n").map(String.init), ips: i.split(separator: "\n").map(String.init))
            let p = (try? String(contentsOfFile: ThreatIntel.dir + "/phish.txt", encoding: .utf8)) ?? ""
            let ps = Set(p.split(separator: "\n").map(String.init))
            lock.lock(); phish = ps; lock.unlock()
        }

        /// Sahte site listesinde mi (üst alan adlarıyla)? Kaynak adı döner.
        func phishSource(_ host: String) -> String? {
            lock.lock(); defer { lock.unlock() }
            var h = host.lowercased()
            if allowed.contains(h) { return nil }
            while h.contains(".") {
                if phish.contains(h) { return "OpenPhish / PhishTank" }
                h = String(h.drop { $0 != "." }.dropFirst())
            }
            return nil
        }

        func set(domains d: [String], ips i: [String]) {
            lock.lock(); domains = Set(d); ips = Set(i); lock.unlock()
        }

        func setAllowed(_ a: Set<String>) { lock.lock(); allowed = a; lock.unlock() }

        /// Eşleşme: (eşleşen alan adı ya da adres, kaynak). Alan adında üst alan adları da denenir
        /// (a.b.evil.com → evil.com listedeyse).
        func match(ip: String?, host: String?) -> (String, String)? {
            lock.lock(); defer { lock.unlock() }
            if let ip, !allowed.contains(ip), ips.contains(ip) { return (ip, "Feodo Tracker") }
            if var h = host?.lowercased(), !allowed.contains(h) {
                while h.contains(".") {
                    if domains.contains(h) { return (h, "URLhaus") }
                    if phish.contains(h) { return (h, "OpenPhish / PhishTank") }
                    h = String(h.drop { $0 != "." }.dropFirst())
                }
            }
            return nil
        }
    }
}
