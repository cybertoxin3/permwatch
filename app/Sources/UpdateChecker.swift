import AppKit
import Foundation
import Sparkle

/// Güncellemeler (Sparkle): günde bir kez imzalı güncelleme listesine (appcast) bakar; yeni sürümü
/// Apple'ın notarize ettiği ve bizim EdDSA anahtarımızla imzalanmış haliyle indirip kurar.
/// Hiçbir veri gönderilmez (sistem profili kapalı). Ayarlar'dan kapatılabilir.
///
/// Sparkle anahtarı olmadan derlenen sürümlerde (Info.plist'te SUPublicEDKey yok) eski davranış:
/// GitHub'dan yalnızca en son sürüm numarasını sorar ve indirme sayfasını açar.
@MainActor
final class UpdateChecker: NSObject, ObservableObject, SPUUpdaterDelegate {
    static let enabledKey = "checkForUpdates"
    static let lastKey = "lastUpdateCheck"
    static let api = URL(string: "https://api.github.com/repos/cybertoxin3/permwatch/releases/latest")!
    static let releasesPage = URL(string: "https://github.com/cybertoxin3/permwatch/releases/latest")!

    @Published private(set) var latest: String?
    @Published private(set) var releaseURL: URL?
    @Published var enabled: Bool = UserDefaults.standard.object(forKey: UpdateChecker.enabledKey) as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(enabled, forKey: Self.enabledKey)
            sparkle?.updater.automaticallyChecksForUpdates = enabled
            if enabled { check(force: true) }
        }
    }
    @Published var autoInstall = false {
        didSet { sparkle?.updater.automaticallyDownloadsUpdates = autoInstall }
    }

    private var sparkle: SPUStandardUpdaterController?
    /// Sparkle bu derlemede etkin mi (imza anahtarı ve güncelleme listesi adresi tanımlı).
    var usesSparkle: Bool { sparkle != nil }

    nonisolated static var current: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0" }

    var updateAvailable: Bool { latest.map { Self.isNewer($0, than: Self.current) } ?? false }

    override init() {
        super.init()
        let info = Bundle.main.infoDictionary ?? [:]
        guard Snapshot.section == nil, info["SUPublicEDKey"] is String, info["SUFeedURL"] is String else { return }
        let c = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: nil)
        c.updater.automaticallyChecksForUpdates = enabled
        autoInstall = c.updater.automaticallyDownloadsUpdates
        do { try c.updater.start() } catch { return }
        sparkle = c
    }

    /// "v0.10.1" > "0.9.3" gibi sayısal karşılaştırma.
    nonisolated static func isNewer(_ a: String, than b: String) -> Bool {
        func parts(_ s: String) -> [Int] {
            s.trimmingCharacters(in: CharacterSet(charactersIn: "vV ")).split(separator: ".").map { Int($0.prefix { $0.isNumber }) ?? 0 }
        }
        let x = parts(a), y = parts(b)
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0, r = i < y.count ? y[i] : 0
            if l != r { return l > r }
        }
        return false
    }

    /// Menüdeki "Güncellemeleri Denetle…": Sparkle'ın kendi penceresiyle.
    func checkNow() {
        if let s = sparkle { s.checkForUpdates(nil) } else { check(force: true) }
    }

    /// Genel Bakış'taki güncelleme kartının düğmesi: Sparkle varsa indirip kurar, yoksa sayfayı açar.
    func install() {
        if let s = sparkle { s.checkForUpdates(nil) } else { NSWorkspace.shared.open(releaseURL ?? Self.releasesPage) }
    }

    func check(force: Bool = false) {
        guard enabled, Snapshot.section == nil else { return }
        if let s = sparkle {
            // Pencere açmadan bak; bulunursa delegate Genel Bakış'taki kartı gösterir.
            if s.updater.canCheckForUpdates { s.updater.checkForUpdateInformation() }
            return
        }
        let last = UserDefaults.standard.object(forKey: Self.lastKey) as? Date ?? .distantPast
        guard force || Date().timeIntervalSince(last) > 86_400 else { return }
        var req = URLRequest(url: Self.api, timeoutInterval: 15)
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("permwatch/\(Self.current)", forHTTPHeaderField: "User-Agent")
        URLSession.shared.dataTask(with: req) { data, _, _ in
            guard let data, let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let tag = j["tag_name"] as? String else { return }
            let url = (j["html_url"] as? String).flatMap(URL.init(string:))
            DispatchQueue.main.async {
                UserDefaults.standard.set(Date(), forKey: Self.lastKey)
                self.latest = tag
                self.releaseURL = url
            }
        }.resume()
    }

    // MARK: SPUUpdaterDelegate

    nonisolated func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        let v = item.displayVersionString
        Task { @MainActor in self.latest = v }
    }

    nonisolated func updaterDidNotFindUpdate(_ updater: SPUUpdater) {
        Task { @MainActor in self.latest = nil }
    }
}
