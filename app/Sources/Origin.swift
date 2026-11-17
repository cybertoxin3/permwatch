import AppKit
import Foundation
import SwiftUI

/// Yeni bir kalıcılık öğesinin (giriş öğesi, LaunchAgent/Daemon…) muhtemel kaynağı: öğenin oluştuğu zamana
/// yakın kurulan paketler, eklenen uygulamalar ve indirilen kurulum dosyaları. Kesin değil, ipucudur.
struct OriginHint: Identifiable, Hashable {
    enum Kind { case package, app, download, owner }
    var id: String { "\(kind)|\(title)|\(date.timeIntervalSince1970)" }
    let kind: Kind
    let title: String
    let detail: String
    let date: Date
    let path: String?
}

enum Origin {
    /// Zaman penceresi: öğeden en çok 45 dk önce ile 2 dk sonrası.
    static let before: TimeInterval = 45 * 60, after: TimeInterval = 120

    static func hints(itemDate: Date, plist: String?, appKey: String) -> [OriginHint] {
        let fm = FileManager.default
        // Öğenin gerçek oluşma zamanı: plist dosyasının oluşturulma tarihi (taramadan daha doğru).
        var t = itemDate
        if let p = plist, let c = (try? fm.attributesOfItem(atPath: p))?[.creationDate] as? Date, c < t { t = c }
        let lo = t.addingTimeInterval(-before), hi = t.addingTimeInterval(after)
        var out: [OriginHint] = []

        // 0) Programın ait olduğu uygulama
        if appKey.hasSuffix(".app"), fm.fileExists(atPath: appKey) {
            let added = NSMetadataItem(url: URL(fileURLWithPath: appKey))?.value(forAttribute: "kMDItemDateAdded") as? Date
            out.append(OriginHint(kind: .owner, title: PathUtil.displayName(appKey),
                                  detail: L("origin.owner", added.map { Fmt.relativeDay.string(from: $0) } ?? "—"),
                                  date: added ?? .distantPast, path: appKey))
        }

        // 1) Kurulum geçmişi (paket kurulumları, App Store, sistem güncellemeleri)
        if let arr = NSArray(contentsOfFile: "/Library/Receipts/InstallHistory.plist") as? [[String: Any]] {
            for e in arr {
                guard let d = e["date"] as? Date, d >= lo, d <= hi else { continue }
                let name = e["displayName"] as? String ?? "?"
                let ver = e["displayVersion"] as? String ?? ""
                let via = e["processName"] as? String ?? ""
                out.append(OriginHint(kind: .package, title: ver.isEmpty ? name : "\(name) \(ver)",
                                      detail: L("origin.package", via, Fmt.relativeDay.string(from: d)), date: d, path: nil))
            }
        }

        // 2) O sırada eklenen uygulamalar
        for dir in ["/Applications", NSHomeDirectory() + "/Applications"] {
            for n in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] where n.hasSuffix(".app") {
                let p = dir + "/" + n
                guard let d = NSMetadataItem(url: URL(fileURLWithPath: p))?.value(forAttribute: "kMDItemDateAdded") as? Date
                        ?? (try? fm.attributesOfItem(atPath: p))?[.creationDate] as? Date,
                      d >= lo, d <= hi, p != appKey else { continue }
                out.append(OriginHint(kind: .app, title: PathUtil.displayName(p),
                                      detail: L("origin.app", Fmt.relativeDay.string(from: d)), date: d, path: p))
            }
        }

        // 3) Öncesinde indirilen kurulum dosyaları (macOS indirme adresini kaydeder)
        let dl = NSHomeDirectory() + "/Downloads"
        let kinds: Set<String> = ["dmg", "pkg", "mpkg", "zip", "app", "sh", "command"]
        for n in (try? fm.contentsOfDirectory(atPath: dl)) ?? [] where kinds.contains((n as NSString).pathExtension.lowercased()) {
            let p = dl + "/" + n
            let md = NSMetadataItem(url: URL(fileURLWithPath: p))
            guard let d = md?.value(forAttribute: "kMDItemDateAdded") as? Date ?? (try? fm.attributesOfItem(atPath: p))?[.creationDate] as? Date,
                  d >= lo, d <= hi else { continue }
            let from = (md?.value(forAttribute: "kMDItemWhereFroms") as? [String])?.compactMap { URL(string: $0)?.host }.first
            out.append(OriginHint(kind: .download, title: n,
                                  detail: from.map { L("origin.downloadFrom", $0, Fmt.relativeDay.string(from: d)) }
                                      ?? L("origin.download", Fmt.relativeDay.string(from: d)), date: d, path: p))
        }
        // Öğeye zamanca en yakın olan üstte (sahibi uygulama her zaman ilk).
        return out.sorted { a, b in
            if (a.kind == .owner) != (b.kind == .owner) { return a.kind == .owner }
            return abs(a.date.timeIntervalSince(t)) < abs(b.date.timeIntervalSince(t))
        }
    }
}

struct OriginSection: View {
    let item: Item
    @State private var hints: [OriginHint]?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("origin.title").uppercased(with: .current)).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
            if let hints {
                if hints.isEmpty {
                    Text(L("origin.none")).font(.system(size: 12)).foregroundStyle(.secondary)
                } else {
                    ForEach(hints.prefix(6)) { h in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: icon(h.kind)).foregroundStyle(.secondary).frame(width: 16)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(h.title).font(.system(size: 12, weight: .medium)).lineLimit(1).truncationMode(.middle)
                                Text(h.detail).font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if let p = h.path {
                                Button { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: p)]) } label: {
                                    Image(systemName: "magnifyingglass")
                                }
                                .buttonStyle(.borderless).help(L("action.showInFinder"))
                            }
                        }
                    }
                    Text(L("origin.note")).font(.system(size: 10.5)).foregroundStyle(.tertiary)
                }
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .task(id: item.id) {
            let (d, p, k) = (item.date, item.removablePlist ?? item.revealPath, item.appKey)
            hints = await Task.detached(priority: .userInitiated) { Origin.hints(itemDate: d, plist: p, appKey: k) }.value
        }
    }

    private func icon(_ k: OriginHint.Kind) -> String {
        switch k {
        case .owner: return "app"
        case .package: return "shippingbox"
        case .app: return "square.and.arrow.down.on.square"
        case .download: return "arrow.down.circle"
        }
    }
}
