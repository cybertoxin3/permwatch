import AppKit
import Foundation
import Sparkle

/// Güncellemeler (Sparkle, kendi arayüzümüzle): her gün güncelleme listesine (appcast) bakar. Yeni
/// sürüm bulununca Genel Bakış'ta notlarıyla birlikte bir kart gösterir; "Güncelle"ye basılınca uygulamanın
/// içinde yüzdeli indirir (kullanıcı başka bölümlere geçse de indirme sürer), sonra yeniden başlatıp kurar.
/// Güncelleme yalnızca Apple'ın notarize ettiği ve permwatch'ın EdDSA anahtarıyla imzalanmışsa kurulur.
/// Hiçbir veri gönderilmez (sistem profili kapalı). Ayarlar'dan kapatılabilir.
///
/// Sparkle anahtarı olmadan derlenen sürümlerde (Info.plist'te SUPublicEDKey yok): GitHub'dan yalnızca
/// en son sürüm numarasını sorar ve indirme sayfasını açar.
@MainActor
final class UpdateChecker: NSObject, ObservableObject, SPUUpdaterDelegate, SPUUserDriver {
    static let enabledKey = "checkForUpdates"
    static let lastKey = "lastUpdateCheck"
    static let api = URL(string: "https://api.github.com/repos/cybertoxin3/permwatch/releases/latest")!
    static let releasesPage = URL(string: "https://github.com/cybertoxin3/permwatch/releases/latest")!

    enum Phase: Equatable {
        case idle, checking, upToDate
        case available          // yeni sürüm var, kullanıcının kararı bekleniyor
        case downloading, extracting
        case ready              // indirildi, yeniden başlatınca kurulacak
        case installing
        case failed(String)
    }

    @Published private(set) var phase: Phase = .idle {
        didSet { if Self.testMode { FileHandle.standardError.write(Data("güncelleme: \(phase) \(received)/\(expected)\n".utf8)) } }
    }
    @Published private(set) var latest: String?
    @Published private(set) var releaseURL: URL?
    @Published private(set) var notes: String?
    @Published private(set) var releaseDate: Date?
    @Published private(set) var size: Int64 = 0
    @Published private(set) var received: Int64 = 0
    @Published private(set) var expected: Int64 = 0
    @Published private(set) var extractProgress: Double = 0

    @Published var enabled: Bool = UserDefaults.standard.object(forKey: UpdateChecker.enabledKey) as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(enabled, forKey: Self.enabledKey)
            updater?.automaticallyChecksForUpdates = enabled
            if enabled { check(force: true) }
        }
    }

    private var updater: SPUUpdater?
    private var foundReply: ((SPUUserUpdateChoice) -> Void)?
    private var readyReply: ((SPUUserUpdateChoice) -> Void)?
    private var cancelDownload: (() -> Void)?
    private var userInitiated = false

    /// Sparkle bu derlemede etkin mi (imza anahtarı ve güncelleme listesi adresi tanımlı).
    var usesSparkle: Bool { updater != nil }

    nonisolated static var current: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0" }

    var updateAvailable: Bool { latest.map { Self.isNewer($0, than: Self.current) } ?? false }

    /// İndirme ilerlemesi (0…1); toplam boyut bilinmiyorsa nil.
    var downloadFraction: Double? { expected > 0 ? min(1, Double(received) / Double(expected)) : nil }

    override init() {
        super.init()
        let info = Bundle.main.infoDictionary ?? [:]
        guard Snapshot.section == nil, info["SUPublicEDKey"] is String, info["SUFeedURL"] is String else { return }
        let u = SPUUpdater(hostBundle: .main, applicationBundle: .main, userDriver: self, delegate: self)
        do { try u.start() } catch { return }
        u.automaticallyChecksForUpdates = enabled
        // Sessiz indirme yok: güncelleme her zaman Genel Bakış'ta kartla gelir, indirme yüzdeyle görünür.
        u.automaticallyDownloadsUpdates = false
        updater = u
        // Uçtan uca deneme: PERMWATCH_FEED_URL'deki listeye hemen bak, bulunca indir ve kur.
        if Self.testMode { DispatchQueue.main.asyncAfter(deadline: .now() + 3) { u.checkForUpdatesInBackground() } }
    }

    nonisolated static let testMode = ProcessInfo.processInfo.environment["PERMWATCH_UPDATE_TEST"] == "1"
    nonisolated static let testFeed = ProcessInfo.processInfo.environment["PERMWATCH_FEED_URL"]

    nonisolated func feedURLString(for updater: SPUUpdater) -> String? { Self.testFeed }

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

    // MARK: Kullanıcının eylemleri

    /// Menüdeki "Güncellemeleri Denetle…".
    func checkNow() {
        if let u = updater {
            guard u.canCheckForUpdates else { return }
            userInitiated = true
            u.checkForUpdates()
        } else { check(force: true) }
    }

    /// Arka planda, pencere açmadan bak (Genel Bakış açılınca).
    func check(force: Bool = false) {
        guard enabled, Snapshot.section == nil else { return }
        if let u = updater {
            if phase == .idle || phase == .upToDate, u.canCheckForUpdates { u.checkForUpdatesInBackground() }
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
            let body = j["body"] as? String
            DispatchQueue.main.async {
                UserDefaults.standard.set(Date(), forKey: Self.lastKey)
                self.latest = tag
                self.releaseURL = url
                self.notes = body
                if Self.isNewer(tag, than: Self.current) { self.phase = .available }
            }
        }.resume()
    }

    /// "Güncelle": indirmeyi başlatır (Sparkle yoksa indirme sayfasını açar).
    func install() {
        if let r = foundReply {
            foundReply = nil
            received = 0; expected = 0
            phase = .downloading
            r(.install)
        } else if updater == nil {
            NSWorkspace.shared.open(releaseURL ?? Self.releasesPage)
        } else {
            checkNow()
        }
    }

    /// "Sonra": bu oturumda kartı gizler; Sparkle bir sonraki kontrolde yeniden hatırlatır.
    func later() {
        foundReply?(.dismiss); foundReply = nil
        phase = .idle
    }

    /// "Bu sürümü atla".
    func skip() {
        foundReply?(.skip); foundReply = nil
        phase = .idle
    }

    func cancel() {
        cancelDownload?(); cancelDownload = nil
        phase = .idle
    }

    /// İndirilen güncellemeyi şimdi kur ve yeniden başlat.
    func relaunch() {
        readyReply?(.install); readyReply = nil
        phase = .installing
    }

    /// Kurulumu çıkışa bırak (Sparkle uygulama kapanınca kurar).
    func installOnQuit() {
        readyReply?(.dismiss); readyReply = nil
    }

    // MARK: SPUUserDriver (Sparkle bunları ana iş parçacığında çağırır)

    nonisolated func show(_ request: SPUUpdatePermissionRequest, reply: @escaping (SUUpdatePermissionResponse) -> Void) {
        reply(SUUpdatePermissionResponse(automaticUpdateChecks: true, sendSystemProfile: false))
    }

    nonisolated func showUserInitiatedUpdateCheck(cancellation: @escaping () -> Void) {
        MainActor.assumeIsolated { phase = .checking }
    }

    nonisolated func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState, reply: @escaping (SPUUserUpdateChoice) -> Void) {
        let version = appcastItem.displayVersionString
        let desc = appcastItem.itemDescription
        let date = appcastItem.date
        let length = Int64(appcastItem.contentLength)
        let link = appcastItem.fullReleaseNotesURL ?? appcastItem.infoURL
        let downloaded = state.stage == .downloaded
        MainActor.assumeIsolated {
            latest = version
            notes = desc.map(Self.plainText)
            releaseDate = date
            size = length
            releaseURL = link
            userInitiated = false
            foundReply = reply
            phase = .available
            // Önceden (arka planda) indirilmişse "Güncelle" doğrudan kuruluma geçer.
            if downloaded { received = length; expected = length }
            if Self.testMode { DispatchQueue.main.asyncAfter(deadline: .now() + 6) { self.install() } }
        }
    }

    nonisolated func showUpdateReleaseNotes(with downloadData: SPUDownloadData) {
        let text = String(data: downloadData.data, encoding: .utf8).map(Self.plainText)
        MainActor.assumeIsolated { if notes == nil { notes = text } }
    }

    nonisolated func showUpdateReleaseNotesFailedToDownloadWithError(_ error: Error) {}

    nonisolated func showUpdateNotFoundWithError(_ error: Error, acknowledgement: @escaping () -> Void) {
        MainActor.assumeIsolated {
            phase = .upToDate
            latest = nil
            if userInitiated {
                userInitiated = false
                let a = NSAlert()
                a.messageText = L("upd.upToDate")
                a.informativeText = L("upd.upToDateBody", Self.current)
                a.runModal()
            }
        }
        acknowledgement()
    }

    nonisolated func showUpdaterError(_ error: Error, acknowledgement: @escaping () -> Void) {
        let msg = error.localizedDescription
        if Self.testMode { FileHandle.standardError.write(Data("sparkle hata: \(error)\n".utf8)) }
        MainActor.assumeIsolated {
            phase = .failed(msg)
            userInitiated = false
        }
        acknowledgement()
    }

    nonisolated func showDownloadInitiated(cancellation: @escaping () -> Void) {
        MainActor.assumeIsolated {
            cancelDownload = cancellation
            received = 0
            phase = .downloading
        }
    }

    nonisolated func showDownloadDidReceiveExpectedContentLength(_ expectedContentLength: UInt64) {
        MainActor.assumeIsolated { expected = Int64(expectedContentLength) }
    }

    nonisolated func showDownloadDidReceiveData(ofLength length: UInt64) {
        MainActor.assumeIsolated { received += Int64(length) }
    }

    nonisolated func showDownloadDidStartExtractingUpdate() {
        MainActor.assumeIsolated {
            cancelDownload = nil
            extractProgress = 0
            phase = .extracting
        }
    }

    nonisolated func showExtractionReceivedProgress(_ progress: Double) {
        MainActor.assumeIsolated { extractProgress = progress }
    }

    nonisolated func showReady(toInstallAndRelaunch reply: @escaping (SPUUserUpdateChoice) -> Void) {
        MainActor.assumeIsolated {
            readyReply = reply
            phase = .ready
            if Self.testMode { DispatchQueue.main.asyncAfter(deadline: .now() + 6) { self.relaunch() } }
            ThreatCenter.shared.notifyUpdateReady(version: latest ?? "")
        }
    }

    nonisolated func showInstallingUpdate(withApplicationTerminated applicationTerminated: Bool, retryTerminatingApplication: @escaping () -> Void) {
        MainActor.assumeIsolated { phase = .installing }
    }

    nonisolated func showUpdateInstalledAndRelaunched(_ relaunched: Bool, acknowledgement: @escaping () -> Void) {
        acknowledgement()
    }

    nonisolated func showUpdateInFocus() {
        MainActor.assumeIsolated { NSApp.activate(ignoringOtherApps: true) }
    }

    nonisolated func dismissUpdateInstallation() {
        MainActor.assumeIsolated {
            cancelDownload = nil
            // Kullanıcı karar verirken ya da kurulum hazırken kartı kaybetme; hata ve "güncel" mesajı kalsın.
            guard foundReply == nil && readyReply == nil else { return }
            switch phase {
            case .failed, .upToDate: break
            default: phase = .idle
            }
        }
    }

    // MARK: SPUUpdaterDelegate

    nonisolated func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        let v = item.displayVersionString
        MainActor.assumeIsolated { latest = v }
    }

    /// Güncelleme notlarındaki HTML etiketlerini atar (notlar düz metin/Markdown olarak yazılır).
    nonisolated static func plainText(_ s: String) -> String {
        var t = s.replacingOccurrences(of: "<br\\s*/?>|</p>|</li>", with: "\n", options: .regularExpression)
        t = t.replacingOccurrences(of: "<li>", with: "• ")
        t = t.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
        return t.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
