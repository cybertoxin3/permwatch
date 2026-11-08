import AppKit
import Foundation

/// Günde en fazla bir kez GitHub'dan en son sürüm numarasını sorar. Hiçbir veri gönderilmez
/// (yalnızca standart bir HTTPS isteği); Ayarlar'dan kapatılabilir.
@MainActor
final class UpdateChecker: ObservableObject {
    static let enabledKey = "checkForUpdates"
    static let lastKey = "lastUpdateCheck"
    static let api = URL(string: "https://api.github.com/repos/cybertoxin3/permwatch/releases/latest")!

    @Published private(set) var latest: String?
    @Published private(set) var releaseURL: URL?
    @Published var enabled: Bool = UserDefaults.standard.object(forKey: UpdateChecker.enabledKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(enabled, forKey: Self.enabledKey); if enabled { check(force: true) } }
    }

    nonisolated static var current: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0" }

    var updateAvailable: Bool { latest.map { Self.isNewer($0, than: Self.current) } ?? false }

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

    func check(force: Bool = false) {
        guard enabled, Snapshot.section == nil else { return }
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
}
