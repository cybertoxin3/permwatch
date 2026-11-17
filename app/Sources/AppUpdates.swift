import AppKit
import Foundation
import SwiftUI

/// Güncel olmayan uygulamalar. Eski sürümler bilinen güvenlik açıklarının en yaygın kapısıdır. Kaynak:
/// Homebrew'un herkese açık uygulama listesi (en son sürümler; 3 günde bir indirilir, hiçbir şey gönderilmez).
/// Yalnızca listede bulunan uygulamalar karşılaştırılabilir.
struct AppUpdate: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let name: String
    let installed: String
    let latest: String
    let token: String
    let homepage: String?
    /// Tarayıcı, mesajlaşma, parola yöneticisi, cüzdan gibi saldırıya en açık uygulamalar.
    let critical: Bool
    /// Homebrew ile kurulmuşsa güncelleme komutu.
    let viaBrew: Bool
    let appStore: Bool
}

@MainActor
final class AppUpdates: ObservableObject {
    static let shared = AppUpdates()
    nonisolated static let url = URL(string: "https://formulae.brew.sh/api/cask.json")!
    nonisolated static var path: String { ThreatIntel.dir + "/cask.json" }

    @Published private(set) var outdated: [AppUpdate] = []
    @Published private(set) var lastCheck: Date?
    @Published private(set) var checking = false

    nonisolated static let criticalTokens: Set<String> = [
        "google-chrome", "firefox", "brave-browser", "microsoft-edge", "opera", "arc", "vivaldi", "tor-browser", "chromium",
        "telegram", "whatsapp", "signal", "discord", "zoom", "slack", "microsoft-teams", "skype", "viber",
        "keepassxc", "1password", "bitwarden", "dashlane", "lastpass", "proton-pass",
        "trezor-suite", "ledger-live", "exodus", "electrum", "monero-wallet", "wasabi-wallet",
        "visual-studio-code", "docker", "vlc", "adobe-acrobat-reader", "microsoft-word", "microsoft-excel",
        "openvpn-connect", "wireguard", "tunnelblick", "teamviewer", "anydesk", "zoom", "thunderbird",
    ]

    private init() {
        guard Snapshot.section == nil else { return }
        check()
    }

    func check() {
        guard !checking else { return }
        checking = true
        Task.detached(priority: .utility) {
            let list = await AppUpdates.compute()
            await MainActor.run {
                self.outdated = list
                self.lastCheck = Date()
                self.checking = false
            }
        }
    }

    nonisolated static func compute() async -> [AppUpdate] {
        let fm = FileManager.default
        let age = ((try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date).map { Date().timeIntervalSince($0) } ?? .infinity
        if age > 3 * 86400 {
            var req = URLRequest(url: url, timeoutInterval: 90)
            req.setValue("permwatch", forHTTPHeaderField: "User-Agent")
            if let (d, r) = try? await URLSession.shared.data(for: req), (r as? HTTPURLResponse)?.statusCode == 200, d.count > 1_000_000 {
                try? fm.createDirectory(atPath: ThreatIntel.dir, withIntermediateDirectories: true)
                try? d.write(to: URL(fileURLWithPath: path), options: .atomic)
            }
        }
        guard let d = fm.contents(atPath: path), let casks = (try? JSONSerialization.jsonObject(with: d)) as? [[String: Any]] else { return [] }
        // Uygulama dosya adı → (en son sürüm, kimlik, ana sayfa)
        var byApp: [String: (String, String, String?)] = [:]
        for c in casks {
            guard let token = c["token"] as? String, let v = c["version"] as? String, v != "latest" else { continue }
            for a in (c["artifacts"] as? [Any]) ?? [] {
                guard let dict = a as? [String: Any], let apps = dict["app"] as? [Any] else { continue }
                for x in apps {
                    let name = (x as? String) ?? ((x as? [String: Any])?["target"] as? String)
                    guard let n = name, n.hasSuffix(".app") else { continue }
                    let file = (n as NSString).lastPathComponent
                    if byApp[file] == nil { byApp[file] = (v.components(separatedBy: ",").first ?? v, token, c["homepage"] as? String) }
                }
            }
        }
        var out: [AppUpdate] = []
        let caskroom = ["/opt/homebrew/Caskroom", "/usr/local/Caskroom"]
        for dir in ["/Applications", NSHomeDirectory() + "/Applications"] {
            for n in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] where n.hasSuffix(".app") {
                let p = dir + "/" + n
                guard let hit = byApp[n], let mine = Bundle(path: p)?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
                      isOlder(mine, than: hit.0) else { continue }
                out.append(AppUpdate(path: p, name: (n as NSString).deletingPathExtension, installed: mine, latest: hit.0, token: hit.1,
                                     homepage: hit.2, critical: criticalTokens.contains(hit.1),
                                     viaBrew: caskroom.contains { fm.fileExists(atPath: $0 + "/" + hit.1) },
                                     appStore: fm.fileExists(atPath: p + "/Contents/_MASReceipt/receipt")))
            }
        }
        return out.sorted { ($0.critical ? 0 : 1, $0.name.lowercased()) < ($1.critical ? 0 : 1, $1.name.lowercased()) }
    }

    /// Sayısal sürüm karşılaştırması ("Build 4215" → 4215). Ortak uzunluk kadar bakılır (3.7.0 = 3.7).
    nonisolated static func isOlder(_ a: String, than b: String) -> Bool {
        func parts(_ s: String) -> [Int] {
            s.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }.prefix(4).map { $0 }
        }
        let x = parts(a), y = parts(b)
        guard !x.isEmpty, !y.isEmpty else { return false }
        for i in 0..<min(x.count, y.count) where x[i] != y[i] { return x[i] < y[i] }
        return false
    }
}

struct AppUpdatesSheet: View {
    @ObservedObject var updates = AppUpdates.shared
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(L("upd.apps.title", updates.outdated.count)).font(.system(size: 16, weight: .bold))
            Text(L("upd.apps.body")).font(.system(size: 12)).foregroundStyle(.secondary)
            List(updates.outdated) { u in
                HStack(spacing: 10) {
                    AppIcon(name: u.name, risk: .normal, key: u.path, size: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(u.name).font(.system(size: 13, weight: .semibold))
                            if u.critical {
                                Text(L("upd.apps.critical")).font(.system(size: 10, weight: .semibold)).padding(.horizontal, 6).padding(.vertical, 1)
                                    .foregroundStyle(.orange).background(Color.orange.opacity(0.15), in: Capsule())
                            }
                        }
                        Text("\(u.installed)  →  \(u.latest)").font(.system(size: 11.5, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if u.viaBrew {
                        Button(L("upd.apps.copyBrew")) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString("brew upgrade --cask \(u.token)", forType: .string)
                        }
                        .help("brew upgrade --cask \(u.token)")
                    }
                    if u.appStore {
                        Button(L("upd.apps.appStore")) { NSWorkspace.shared.open(URL(string: "macappstore://showUpdatesPage")!) }
                    } else {
                        Button(L("upd.apps.open")) { NSWorkspace.shared.open(URL(fileURLWithPath: u.path)) }
                            .help(L("upd.apps.openHelp"))
                    }
                    if let h = u.homepage, let url = URL(string: h) {
                        Button { NSWorkspace.shared.open(url) } label: { Image(systemName: "safari") }.help(h)
                    }
                }
                .padding(.vertical, 3)
            }
            .listStyle(.inset)
            HStack {
                if let d = updates.lastCheck { Text(L("disk.scannedAt", Fmt.relative(d))).font(.system(size: 11)).foregroundStyle(.secondary) }
                Spacer()
                Button(L("common.ok")) { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(18)
        .frame(width: 640, height: 520)
    }
}
