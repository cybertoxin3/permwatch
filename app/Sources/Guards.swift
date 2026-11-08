import AppKit
import CoreAudio
import CoreMediaIO
import CryptoKit
import Darwin
import Foundation

// MARK: - VirusTotal (yalnızca kullanıcı isteyince; dışarı sadece SHA-256 çıkar)

enum Lookup {
    static func sha256(path: String) -> String? {
        let target = Bundle(path: path)?.executablePath ?? path
        guard let h = FileHandle(forReadingAtPath: target) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        while let chunk = try? h.read(upToCount: 1 << 20), !chunk.isEmpty { hasher.update(data: chunk) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func virusTotal(path: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            guard let hash = sha256(path: path),
                  let url = URL(string: "https://www.virustotal.com/gui/file/\(hash)") else { return }
            DispatchQueue.main.async { NSWorkspace.shared.open(url) }
        }
    }
}

// MARK: - Güvenlik durumu

struct PostureCheck: Identifiable {
    enum State { case on, off, warn, unknown }
    let id: String
    let title: String
    let state: State
    let detail: String?
    let settingsURL: String?
}

@MainActor
final class SecurityPosture: ObservableObject {
    @Published private(set) var checks: [PostureCheck] = []

    init() { refresh() }

    var issues: Int { checks.filter { $0.state == .off || $0.state == .warn }.count }
    var score: (on: Int, total: Int) { (checks.filter { $0.state == .on }.count, checks.count) }

    func refresh() {
        Task.detached(priority: .utility) {
            let c = SecurityPosture.evaluate()
            await MainActor.run { self.checks = c }
        }
    }

    nonisolated static func evaluate() -> [PostureCheck] {
        func has(_ tool: String, _ args: [String], _ needle: String) -> PostureCheck.State {
            let (code, out) = Shell.run(tool, args)
            if code != 0 && out.isEmpty { return .unknown }
            return out.lowercased().contains(needle) ? .on : .off
        }
        var out: [PostureCheck] = []
        out.append(PostureCheck(id: "sip", title: L("sec.sip"),
                                state: has("/usr/bin/csrutil", ["status"], "enabled"), detail: nil, settingsURL: nil))
        out.append(PostureCheck(id: "gatekeeper", title: L("sec.gatekeeper"),
                                state: has("/usr/sbin/spctl", ["--status"], "assessments enabled"), detail: nil,
                                settingsURL: "x-apple.systempreferences:com.apple.preference.security?General"))
        out.append(PostureCheck(id: "filevault", title: L("sec.filevault"),
                                state: has("/usr/bin/fdesetup", ["status"], "filevault is on"), detail: nil,
                                settingsURL: "x-apple.systempreferences:com.apple.preference.security?FDE"))
        out.append(PostureCheck(id: "firewall", title: L("sec.firewall"),
                                state: has("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], "enabled"),
                                detail: nil, settingsURL: "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall"))

        // XProtect: sürüm ve son güncelleme; 30 günden eskiyse uyar.
        let xp = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
        if let info = NSDictionary(contentsOfFile: xp + "/Contents/Info.plist"),
           let ver = info["CFBundleShortVersionString"] as? String {
            let mod = (try? FileManager.default.attributesOfItem(atPath: xp + "/Contents/Info.plist")[.modificationDate]) as? Date
            let old = mod.map { Date().timeIntervalSince($0) > 30 * 86_400 } ?? false
            out.append(PostureCheck(id: "xprotect", title: L("sec.xprotect"), state: old ? .warn : .on,
                                    detail: L("sec.xprotectAge", ver, mod.map { Fmt.relative($0) } ?? "?"),
                                    settingsURL: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"))
        } else {
            out.append(PostureCheck(id: "xprotect", title: L("sec.xprotect"), state: .unknown, detail: nil, settingsURL: nil))
        }

        // Otomatik güvenlik yanıtları ve sistem veri dosyaları (XProtect bunlarla güncellenir).
        let su = UserDefaults(suiteName: "/Library/Preferences/com.apple.SoftwareUpdate")
        let critical = su?.object(forKey: "CriticalUpdateInstall") as? Bool ?? true
        let config = su?.object(forKey: "ConfigDataInstall") as? Bool ?? true
        out.append(PostureCheck(id: "updates", title: L("sec.updates"), state: (critical && config) ? .on : .off,
                                detail: nil, settingsURL: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"))
        return out
    }
}

// MARK: - İndirilenler bekçisi

struct DownloadItem: Identifiable, Equatable {
    var id: String { path }
    let path: String
    let name: String
    let date: Date
    let accepted: Bool?        // Gatekeeper kararı
    let source: String?        // "Notarized Developer ID" vb.
    let quarantined: Bool
    let risk: Risk
}

/// Tam Disk Erişimi: tek izin, her klasör. Verilmeden İndirilenler/Masaüstü/Belgeler'e dokunmak
/// macOS'un her klasör için ayrı ayrı izin sormasına yol açar; o yüzden önce bu denetlenir.
enum FullDisk {
    nonisolated static var granted: Bool {
        let fd = Darwin.open(NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db", O_RDONLY)
        if fd >= 0 { Darwin.close(fd); return true }
        return false
    }
    static func openSettings() {
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
    }
}

@MainActor
final class DownloadGuard: ObservableObject {
    @Published private(set) var items: [DownloadItem] = []
    @Published private(set) var needsFullDisk = !FullDisk.granted
    private var fdaTimer: Timer?
    @Published private(set) var folders: [(path: String, source: String)] = []

    static let customKey = "watchFolders"
    private var watchers: [DispatchSourceFileSystemObject] = []
    private var pending: DispatchWorkItem?
    private var cache: [String: DownloadItem] = [:]   // yol+tarih → sonuç
    private var initialDone = false
    private var query: NSMetadataQuery?
    private var spotlightPaths = Set<String>()
    nonisolated private static let kinds: Set<String> = ["app", "pkg", "mpkg", "dmg"]

    init() {
        if needsFullDisk {
            // İzin gelene kadar korumalı klasörlere dokunma; gelince kendiliğinden başla.
            fdaTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.checkFullDisk() }
            }
        } else {
            begin()
        }
    }

    private func checkFullDisk() {
        guard FullDisk.granted else { return }
        fdaTimer?.invalidate(); fdaTimer = nil
        needsFullDisk = false
        begin()
    }

    private func begin() {
        rebuildFolders()
        startSpotlight()
        scan()
    }

    var risky: Int { items.filter { $0.risk >= .caution }.count }

    var customFolders: [String] { UserDefaults.standard.stringArray(forKey: Self.customKey) ?? [] }

    func addFolder(_ path: String) {
        var c = customFolders
        guard !c.contains(path) else { return }
        c.append(path)
        UserDefaults.standard.set(c, forKey: Self.customKey)
        rebuildFolders()
        scan()
    }

    func removeFolder(_ path: String) {
        UserDefaults.standard.set(customFolders.filter { $0 != path }, forKey: Self.customKey)
        rebuildFolders()
        scan()
    }

    // MARK: Klasörler: İndirilenler, Masaüstü, tarayıcıların ayarlı klasörleri, kullanıcının ekledikleri

    private func rebuildFolders() {
        guard !needsFullDisk else { folders = []; return }
        let h = NSHomeDirectory()
        var list: [(String, String)] = [(h + "/Downloads", "macOS"), (h + "/Desktop", "macOS"), (h + "/Documents", "macOS"),
                                        (h + "/Library/Mobile Documents/com~apple~CloudDocs", "iCloud Drive"),
                                        (h + "/Library/Mobile Documents/com~apple~CloudDocs/Downloads", "iCloud Drive"),
                                        (h + "/Library/Containers/com.apple.mail/Data/Library/Mail Downloads", "Mail")]
        // Takılı diskler (USB vb.) kök klasörü
        for v in (try? FileManager.default.contentsOfDirectory(atPath: "/Volumes")) ?? [] {
            let p = "/Volumes/" + v
            if (try? FileManager.default.destinationOfSymbolicLink(atPath: p)) == nil { list.append((p, L("dl.volume"))) }
        }
        for (p, src) in Self.browserDownloadFolders() where !list.contains(where: { $0.0 == p }) { list.append((p, src)) }
        for p in customFolders where !list.contains(where: { $0.0 == p }) { list.append((p, "")) }
        folders = list.filter { FileManager.default.fileExists(atPath: $0.0) }.map { (path: $0.0, source: $0.1) }

        watchers.forEach { $0.cancel() }
        watchers = []
        for f in folders {
            let fd = Darwin.open(f.path, O_EVTONLY)
            guard fd >= 0 else { continue }
            let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .rename, .delete],
                                                                queue: .main)
            src.setEventHandler { [weak self] in MainActor.assumeIsolated { self?.schedule() } }
            src.setCancelHandler { Darwin.close(fd) }
            src.resume()
            watchers.append(src)
        }
    }

    /// Tarayıcıların ayarlarındaki indirme klasörleri.
    nonisolated static func browserDownloadFolders() -> [(String, String)] {
        let home = NSHomeDirectory()
        var out: [(String, String)] = []
        // Safari (sandbox içindeki tercih dosyası; Tam Disk Erişimi ile okunur)
        for plist in [home + "/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist",
                      home + "/Library/Preferences/com.apple.Safari.plist"] {
            if let d = NSDictionary(contentsOfFile: plist), let p = d["DownloadsPath"] as? String {
                out.append(((p as NSString).expandingTildeInPath, "Safari"))
                break
            }
        }
        // Chromium tabanlılar: Preferences içindeki download.default_directory
        for (dir, name) in [("Google/Chrome", "Chrome"), ("BraveSoftware/Brave-Browser", "Brave"),
                            ("Microsoft Edge", "Edge"), ("Arc/User Data", "Arc")] {
            let base = home + "/Library/Application Support/" + dir
            for prof in ((try? FileManager.default.contentsOfDirectory(atPath: base)) ?? [])
            where prof == "Default" || prof.hasPrefix("Profile ") {
                guard let data = FileManager.default.contents(atPath: base + "/" + prof + "/Preferences"),
                      let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let dl = j["download"] as? [String: Any],
                      let p = dl["default_directory"] as? String else { continue }
                out.append((p, name))
            }
        }
        // Firefox: prefs.js içindeki browser.download.dir
        let ff = home + "/Library/Application Support/Firefox/Profiles"
        for prof in (try? FileManager.default.contentsOfDirectory(atPath: ff)) ?? [] {
            guard let text = try? String(contentsOfFile: ff + "/" + prof + "/prefs.js", encoding: .utf8),
                  let r = text.range(of: "user_pref(\"browser.download.dir\", \"") else { continue }
            let rest = text[r.upperBound...]
            if let e = rest.firstIndex(of: "\"") { out.append((String(rest[..<e]), "Firefox")) }
        }
        return out
    }

    // MARK: Spotlight: indirme klasörü nerede olursa olsun "nereden indirildi" bilgisi olan dosyalar

    private func startSpotlight() {
        let q = NSMetadataQuery()
        // mdfind ile birebir aynı Spotlight sorgusu (dış diskler dahil bütün yerel birimler).
        q.predicate = NSPredicate(fromMetadataQueryString: Self.spotlightQuery)
        q.searchScopes = [NSMetadataQueryLocalComputerScope]
        let nc = NotificationCenter.default
        for n in [NSNotification.Name.NSMetadataQueryDidFinishGathering, .NSMetadataQueryDidUpdate] {
            nc.addObserver(forName: n, object: q, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.collectSpotlight() }
            }
        }
        q.start()
        query = q
    }

    nonisolated static let spotlightQuery = """
        kMDItemWhereFroms == "*" && kMDItemFSCreationDate >= $time.today(-30) && \
        (kMDItemContentTypeTree == "com.apple.application-bundle" || \
         kMDItemContentTypeTree == "com.apple.installer-package*" || \
         kMDItemContentTypeTree == "public.disk-image" || kMDItemContentTypeTree == "com.apple.disk-image*")
        """

    private func collectSpotlight() {
        guard let q = query else { return }
        q.disableUpdates()
        var paths = Set<String>()
        for i in 0..<q.resultCount {
            if let item = q.result(at: i) as? NSMetadataItem, let p = item.value(forAttribute: NSMetadataItemPathKey) as? String {
                paths.insert(p)
            }
        }
        q.enableUpdates()
        if paths != spotlightPaths {
            spotlightPaths = paths
            schedule()
        }
    }

    private func schedule() {
        pending?.cancel()
        // İndirme bitince dosya yeniden adlandırılır; kısa bir bekleme yeterli.
        let w = DispatchWorkItem { [weak self] in MainActor.assumeIsolated { self?.scan() } }
        pending = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5, execute: w)
    }

    func scan() {
        guard !needsFullDisk else { return }
        let dirs = folders.map(\.path)
        let extra = spotlightPaths
        let cache = self.cache
        Task.detached(priority: .utility) {
            let fm = FileManager.default
            let limit = Date().addingTimeInterval(-30 * 86_400)
            var candidates = extra
            for dir in dirs {
                for n in (try? fm.contentsOfDirectory(atPath: dir)) ?? []
                where DownloadGuard.kinds.contains((n as NSString).pathExtension.lowercased()) {
                    candidates.insert(dir + "/" + n)
                }
            }
            var out: [DownloadItem] = []
            for p in candidates {
                guard let attrs = try? fm.attributesOfItem(atPath: p),
                      let date = (attrs[.creationDate] as? Date) ?? (attrs[.modificationDate] as? Date),
                      date > limit else { continue }
                let ck = "\(p)|\(date.timeIntervalSince1970)"
                if let c = cache[ck] { out.append(c); continue }
                out.append(DownloadGuard.assess(path: p, date: date))
            }
            let result = out
            await MainActor.run { self.apply(result) }
        }
    }

    private func apply(_ list: [DownloadItem]) {
        let known = Set(items.map(\.id))
        items = list.sorted { $0.date > $1.date }
        for i in list { cache["\(i.path)|\(i.date.timeIntervalSince1970)"] = i }
        if initialDone {
            for i in list where !known.contains(i.id) && i.risk >= .caution {
                ThreatCenter.shared.report(Threat(
                    id: "dl-\(i.path)", risk: i.risk, title: "\(i.risk.label): \(L("dl.threatTitle"))",
                    detail: "\(i.name) · \(i.accepted == false ? L("dl.rejected") : L("dl.notNotarized"))",
                    iconKey: i.path, section: .downloads, focus: .download(i.path)))
            }
        }
        initialDone = true
    }

    nonisolated static func assess(path: String, date: Date) -> DownloadItem {
        let ext = (path as NSString).pathExtension.lowercased()
        let args: [String]
        switch ext {
        case "pkg", "mpkg": args = ["--assess", "--type", "install", "-vv", path]
        case "dmg": args = ["--assess", "--type", "open", "--context", "context:primary-signature", "-vv", path]
        default: args = ["--assess", "--type", "execute", "-vv", path]
        }
        let (code, out) = Shell.run("/usr/sbin/spctl", args)
        let accepted: Bool? = out.contains("accepted") ? true : (out.contains("rejected") || code == 3 ? false : nil)
        let source = out.split(separator: "\n").first { $0.hasPrefix("source=") }.map { String($0.dropFirst(7)) }
        let quarantined = getxattr(path, "com.apple.quarantine", nil, 0, 0, 0) > 0
        var risk: Risk = .normal
        if accepted == false {
            // Reddedilen ve karantinası da kaldırılmış dosya: Gatekeeper'ı atlatma girişimi.
            risk = quarantined ? .caution : .high
        } else if let s = source, !s.lowercased().contains("notarized") {
            risk = .caution
        }
        return DownloadItem(path: path, name: (path as NSString).lastPathComponent, date: date,
                            accepted: accepted, source: source, quarantined: quarantined, risk: risk)
    }
}

// MARK: - Mikrofon ve kamera

struct MediaSession: Identifiable {
    let id = UUID()
    let mic: Bool
    let name: String
    let pid: Int32?
    let path: String?
    let start: Date
    var end: Date?
}

@MainActor
final class MediaMonitor: ObservableObject {
    @Published private(set) var micUsers: [(pid: Int32, name: String, path: String?)] = []
    @Published private(set) var cameraOn = false
    @Published private(set) var history: [MediaSession] = []

    private var timer: Timer?

    init() {
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.poll() }
        }
    }

    var inUse: Bool { cameraOn || !micUsers.isEmpty }

    private func poll() {
        let pids = Self.micPIDs()
        let users: [(pid: Int32, name: String, path: String?)] = pids.map { pid in
            var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            let path = proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
            let name = path.map { PathUtil.displayName(PathUtil.appBundle($0) ?? $0) } ?? "pid \(pid)"
            return (pid, name, path)
        }
        let cam = Self.cameraRunning()

        // Oturum geçmişi: başlayanları ekle, bitenleri kapat.
        let now = Date()
        let activePIDs = Set(users.map(\.pid))
        for i in history.indices where history[i].end == nil {
            if history[i].mic, let p = history[i].pid, !activePIDs.contains(p) { history[i].end = now }
            if !history[i].mic && !cam { history[i].end = now }
        }
        let open = Set(history.filter { $0.end == nil && $0.mic }.compactMap(\.pid))
        for u in users where !open.contains(u.pid) {
            history.insert(MediaSession(mic: true, name: u.name, pid: u.pid, path: u.path, start: now), at: 0)
            // İmzasız ya da ad-hoc bir program mikrofonu kullanıyorsa tehdit.
            if let p = u.path {
                let sig = Signing.classify(path: PathUtil.appBundle(p) ?? p).signature
                if sig == "unsigned" || sig == "adhoc" {
                    ThreatCenter.shared.report(Threat(
                        id: "mic-\(u.pid)-\(Int(now.timeIntervalSince1970))", risk: .high,
                        title: "\(Risk.high.label): \(L("media.threat"))",
                        detail: "\(u.name) · \(Text10n.signature(sig, team: nil) ?? sig)",
                        iconKey: PathUtil.appBundle(p) ?? p, section: .category(.micCamera), focus: .media))
                }
            }
        }
        if cam && !history.contains(where: { !$0.mic && $0.end == nil }) {
            history.insert(MediaSession(mic: false, name: L("media.camera"), pid: nil, path: nil, start: now), at: 0)
        }
        if history.count > 200 { history.removeLast(history.count - 200) }
        micUsers = users
        cameraOn = cam
    }

    /// macOS 14+: CoreAudio süreç nesneleri, hangi sürecin mikrofonu kullandığını söyler.
    nonisolated static func micPIDs() -> [Int32] {
        var addr = AudioObjectPropertyAddress(mSelector: kAudioHardwarePropertyProcessObjectList,
                                              mScope: kAudioObjectPropertyScopeGlobal,
                                              mElement: kAudioObjectPropertyElementMain)
        var size: UInt32 = 0
        let sys = AudioObjectID(kAudioObjectSystemObject)
        guard AudioObjectGetPropertyDataSize(sys, &addr, 0, nil, &size) == noErr, size > 0 else { return [] }
        var ids = [AudioObjectID](repeating: 0, count: Int(size) / MemoryLayout<AudioObjectID>.size)
        guard AudioObjectGetPropertyData(sys, &addr, 0, nil, &size, &ids) == noErr else { return [] }
        var out: [Int32] = []
        for id in ids {
            var running: UInt32 = 0
            var rs = UInt32(MemoryLayout<UInt32>.size)
            var ra = AudioObjectPropertyAddress(mSelector: kAudioProcessPropertyIsRunningInput,
                                                mScope: kAudioObjectPropertyScopeGlobal,
                                                mElement: kAudioObjectPropertyElementMain)
            guard AudioObjectGetPropertyData(id, &ra, 0, nil, &rs, &running) == noErr, running != 0 else { continue }
            var pid: pid_t = 0
            var ps = UInt32(MemoryLayout<pid_t>.size)
            var pa = AudioObjectPropertyAddress(mSelector: kAudioProcessPropertyPID,
                                                mScope: kAudioObjectPropertyScopeGlobal,
                                                mElement: kAudioObjectPropertyElementMain)
            if AudioObjectGetPropertyData(id, &pa, 0, nil, &ps, &pid) == noErr { out.append(pid) }
        }
        return out
    }

    /// Kamera açık mı? (CoreMediaIO; hangi sürecin açtığını söylemez.)
    nonisolated static func cameraRunning() -> Bool {
        var addr = CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(kCMIOHardwarePropertyDevices),
                                             mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                                             mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
        var size: UInt32 = 0
        let sys = CMIOObjectID(kCMIOObjectSystemObject)
        guard CMIOObjectGetPropertyDataSize(sys, &addr, 0, nil, &size) == 0, size > 0 else { return false }
        var devs = [CMIOObjectID](repeating: 0, count: Int(size) / MemoryLayout<CMIOObjectID>.size)
        var used: UInt32 = 0
        guard CMIOObjectGetPropertyData(sys, &addr, 0, nil, size, &used, &devs) == 0 else { return false }
        for d in devs {
            var ra = CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsRunningSomewhere),
                                               mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeWildcard),
                                               mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementWildcard))
            var running: UInt32 = 0
            var u: UInt32 = 0
            if CMIOObjectGetPropertyData(d, &ra, 0, nil, UInt32(MemoryLayout<UInt32>.size), &u, &running) == 0, running != 0 {
                return true
            }
        }
        return false
    }
}

// MARK: - Ağ

struct ConnRow: Identifiable, Hashable {
    let id: String
    let pid: Int32
    let name: String
    let path: String?
    let proto: String
    let local: String
    let remote: String?
    let state: String
    let signature: String?
    let rules: [String]          // nrule.* anahtarları
    let ruleArgs: [String]
    let risk: Risk

    var riskSort: Int { risk.rawValue }
    var remoteSort: String { remote ?? "" }
}

@MainActor
final class NetworkMonitor: ObservableObject {
    @Published private(set) var rows: [ConnRow] = []
    @Published var visible = false { didSet { reschedule() } }
    private var timer: Timer?
    private var busy = false
    private var first = true

    nonisolated static let badPorts: Set<Int> = [4444, 1337, 31337, 6666, 6667, 9001, 9050, 5555, 12345, 54321, 2222]

    init() {
        refresh()
        reschedule()
    }

    var risky: Int { rows.filter { $0.risk >= .caution }.count }

    private func reschedule() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: visible ? 3 : 10, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func refresh() {
        guard !busy else { return }
        busy = true
        let rootLsof = RootBridge.shared.active ? RootBridge.shared.data?.lsof : nil
        Task.detached(priority: .utility) {
            let r = NetworkMonitor.collect(rootLsof: rootLsof)
            await MainActor.run {
                self.rows = r
                self.busy = false
                for c in r where c.risk == .high {
                    let t = Threat(id: "net-\(c.name)-\(c.remote ?? c.local)", risk: .high,
                                   title: "\(Risk.high.label): \(L("alert.network"))",
                                   detail: "\(c.name) · \(c.remote ?? c.local)",
                                   iconKey: c.path.map { PathUtil.appBundle($0) ?? $0 }, section: .network,
                                   focus: .connection(c.id))
                    if self.first { ThreatCenter.shared.markSeen([t.id]) } else { ThreatCenter.shared.report(t) }
                }
                self.first = false
            }
        }
    }

    /// lsof -F: yönetici yetkisi olmadan yalnızca kendi kullanıcının süreçleri görünür.
    /// rootLsof: yönetici modu açıksa yardımcının root olarak aldığı çıktı (bütün süreçler).
    nonisolated static func collect(rootLsof: String? = nil) -> [ConnRow] {
        let out = rootLsof ?? Shell.run("/usr/sbin/lsof", ["-nP", "-i", "-F", "pcfPnT"]).1
        var rows: [ConnRow] = []
        var pid: Int32 = 0, cmd = "", proto = "", name = "", state = "", fd = ""
        var sigCache: [Int32: (String?, String?)] = [:]
        func flush() {
            guard !name.isEmpty else { return }
            let parts = name.components(separatedBy: "->")
            let local = parts[0]
            let remote = parts.count > 1 ? parts[1] : nil
            let st = state.isEmpty ? (remote == nil ? "LISTEN/UDP" : "") : state
            if sigCache[pid] == nil {
                var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
                let path = proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
                let sig = path.map { Signing.classify(path: PathUtil.appBundle($0) ?? $0).signature }
                sigCache[pid] = (path, sig)
            }
            let (path, sig) = sigCache[pid]!
            let brew = PathUtil.homebrewFormula(path) != nil
            let weak = (sig == "unsigned" || sig == "adhoc") && !brew
            var rules: [String] = []
            var args: [String] = []
            var risk: Risk = .normal
            let loopback = local.hasPrefix("127.") || local.hasPrefix("[::1]") || local.hasPrefix("localhost")
            if remote != nil && weak && !(remote!.hasPrefix("127.") || remote!.hasPrefix("[::1]")) {
                rules.append("nrule.unsignedOutbound"); args.append(""); risk = max(risk, .caution)
            }
            if st.contains("LISTEN") && weak && !loopback {
                rules.append("nrule.unsignedListener"); args.append(""); risk = .high
            } else if st.contains("LISTEN") && brew && !loopback {
                // Homebrew sunucusu ağa açık dinliyor: genelde bilinçli (ör. veritabanı), yine de görünsün.
                rules.append("nrule.unsignedListener"); args.append(""); risk = .caution
            }
            if let r = remote, let port = Int(r.split(separator: ":").last ?? ""), badPorts.contains(port) {
                rules.append("nrule.badPort"); args.append("\(port)"); risk = .high
            }
            let display = path.map { PathUtil.displayName(PathUtil.appBundle($0) ?? $0) } ?? cmd
            rows.append(ConnRow(id: "\(pid)-\(fd)-\(name)", pid: pid, name: display, path: path, proto: proto,
                                local: local, remote: remote, state: st, signature: sig, rules: rules, ruleArgs: args,
                                risk: risk))
            name = ""; state = ""; proto = ""
        }
        for line in out.split(separator: "\n") {
            guard let tag = line.first else { continue }
            let v = String(line.dropFirst())
            switch tag {
            case "p": flush(); pid = Int32(v) ?? 0
            case "c": cmd = v
            case "f": flush(); fd = v
            case "P": proto = v
            case "n": name = v
            case "T": if v.hasPrefix("ST=") { state = String(v.dropFirst(3)) }
            default: break
            }
        }
        flush()
        return rows
    }
}
