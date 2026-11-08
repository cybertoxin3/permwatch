import AppKit
import Foundation

/// Karantinadaki bir öğe: zararlı dosya (ya da uygulama) ve onu başlatan başlangıç öğeleri.
struct QuarantineItem: Identifiable, Codable, Hashable {
    let id: String
    let name: String           // zararlının adı, ör. MacOS.Trojan.Amcleaner
    let rule: String
    let date: Date
    /// Asıl yol → karantinadaki yol
    let files: [String: String]
    /// Çalıştırma izni kaldırılan dosyalar (karantinadaki yol → asıl izinler); geri yüklenince geri verilir.
    let executables: [String: Int]
}

/// Zararlıları çalıştırılamaz hale getirip ayrı bir klasörde tutar; istenirse geri yükler ya da siler.
/// Çöp Sepeti'nden farkı: dosyalar yanlışlıkla açılamaz ve nereden geldikleri kaydedilir.
@MainActor
final class QuarantineStore: ObservableObject {
    static let shared = QuarantineStore()
    nonisolated static let dir = NSHomeDirectory() + "/Library/Application Support/permwatch/Quarantine"
    private var indexPath: String { Self.dir + "/index.json" }

    @Published private(set) var items: [QuarantineItem] = []

    private init() {
        if let d = FileManager.default.contents(atPath: indexPath), let l = try? JSONDecoder().decode([QuarantineItem].self, from: d) {
            items = l
        }
    }

    private func save() {
        try? FileManager.default.createDirectory(atPath: Self.dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let d = try? JSONEncoder().encode(items) { try? d.write(to: URL(fileURLWithPath: indexPath)) }
    }

    /// Karantinaya alır. Başarısız olan yollar (ör. yönetici izni gereken) döner.
    func quarantine(paths: [String], launchItems: [String], name: String, rule: String) -> [String] {
        let fm = FileManager.default
        // Önce başlatan öğeleri durdur, sonra dosyaları taşı.
        for plist in launchItems {
            let label = (NSDictionary(contentsOfFile: plist)?["Label"] as? String)
                ?? ((plist as NSString).lastPathComponent as NSString).deletingPathExtension
            if plist.hasPrefix(NSHomeDirectory()) { Shell.run("/bin/launchctl", ["bootout", "gui/\(getuid())/\(label)"]) }
        }
        let id = UUID().uuidString
        let box = Self.dir + "/" + id
        try? fm.createDirectory(atPath: box, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var moved: [String: String] = [:]
        var execs: [String: Int] = [:]
        var failed: [String] = []
        for (i, src) in (paths + launchItems).enumerated() where fm.fileExists(atPath: src) {
            let dst = box + "/\(i)-" + (src as NSString).lastPathComponent
            do {
                try fm.moveItem(atPath: src, toPath: dst)
                moved[src] = dst
                execs.merge(Self.disarm(dst)) { a, _ in a }
            } catch {
                failed.append(src)
            }
        }
        if moved.isEmpty { try? fm.removeItem(atPath: box); return failed }
        items.insert(QuarantineItem(id: id, name: name, rule: rule, date: Date(), files: moved, executables: execs), at: 0)
        save()
        return failed
    }

    /// Çalıştırma izinlerini kaldırır; kaldırılanları (yol → asıl izinler) döner.
    nonisolated static func disarm(_ root: String) -> [String: Int] {
        var out: [String: Int] = [:]
        let fm = FileManager.default
        var all = [root]
        if let e = fm.enumerator(atPath: root) { for case let rel as String in e { all.append(root + "/" + rel) } }
        for p in all {
            guard let a = try? fm.attributesOfItem(atPath: p), (a[.type] as? FileAttributeType) == .typeRegular,
                  let mode = (a[.posixPermissions] as? NSNumber)?.uint16Value else { continue }
            if mode & 0o111 != 0 {
                out[p] = Int(mode)
                try? fm.setAttributes([.posixPermissions: NSNumber(value: mode & ~0o111)], ofItemAtPath: p)
            }
        }
        return out
    }

    /// Geri yükler (kullanıcı "bu dosyayı tanıyorum" dediğinde). Hata mesajı döner.
    func restore(_ item: QuarantineItem) -> String? {
        let fm = FileManager.default
        for (p, mode) in item.executables { try? fm.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: p) }
        var failed: [String] = []
        for (orig, stored) in item.files {
            if fm.fileExists(atPath: orig) { failed.append(orig); continue }
            try? fm.createDirectory(atPath: (orig as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            do { try fm.moveItem(atPath: stored, toPath: orig) } catch { failed.append(orig) }
        }
        guard failed.isEmpty else { return L("q.restoreFailed", failed.map(PathUtil.abbreviate).joined(separator: ", ")) }
        try? fm.removeItem(atPath: Self.dir + "/" + item.id)
        items.removeAll { $0.id == item.id }
        save()
        return nil
    }

    /// Kalıcı olarak siler (geri alınamaz).
    func delete(_ item: QuarantineItem) {
        try? FileManager.default.removeItem(atPath: Self.dir + "/" + item.id)
        items.removeAll { $0.id == item.id }
        save()
    }
}
