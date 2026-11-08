import Foundation

/// permwatch'ın macOS tarafından kaydedilen çökme raporları (~/Library/Logs/DiagnosticReports/*.ips).
/// Rapor dosyasının kendisi kullanıcı adı, dosya yolları ve cihaz kimlikleri içerir; bu yüzden e-postaya
/// yalnızca arındırılmış bir özet (sürüm, hata türü, çöken iş parçacığının çağrıları) eklenir.
enum CrashReports {
    static let seenKey = "crashSeenUntil"
    static var dir: String { NSHomeDirectory() + "/Library/Logs/DiagnosticReports" }

    /// Son 30 günün permwatch çökmeleri, en yenisi önce. (Root yardımcısının raporları
    /// /Library/Logs altında ve yalnızca yöneticiye açık; onlar burada yok.)
    static func recent(days: Double = 30) -> [(url: URL, date: Date)] {
        let fm = FileManager.default
        let limit = Date().addingTimeInterval(-days * 86_400)
        let names = (try? fm.contentsOfDirectory(atPath: dir)) ?? []
        return names.filter { isOurs($0) }.compactMap { n -> (URL, Date)? in
            let u = URL(fileURLWithPath: dir + "/" + n)
            guard let d = (try? fm.attributesOfItem(atPath: u.path))?[.modificationDate] as? Date, d > limit else { return nil }
            return (u, d)
        }.sorted { $0.1 > $1.1 }
    }

    /// "permwatch-2026-11-09-101500.ips" gibi; başka programların (ör. permwatch-crashtest) raporları değil.
    static func isOurs(_ name: String) -> Bool {
        name.range(of: #"^permwatch-\d{4}-\d{2}-\d{2}-\d{6}(\.\d+)?\.ips$"#, options: .regularExpression) != nil
    }

    /// Henüz kullanıcıya sorulmamış yeni bir çökme var mı?
    static func unseen() -> (url: URL, date: Date)? {
        guard let newest = recent(days: 14).first else { return nil }
        let seen = UserDefaults.standard.object(forKey: seenKey) as? Date ?? .distantPast
        return newest.date > seen ? newest : nil
    }

    static func markSeen() { UserDefaults.standard.set(Date(), forKey: seenKey) }

    /// Arındırılmış özet: kullanıcı adı, ev klasörü ve yollar çıkarılır.
    static func summary(_ url: URL) -> String? {
        guard let text = try? String(contentsOf: url, encoding: .utf8), let nl = text.firstIndex(of: "\n"),
              let head = try? JSONSerialization.jsonObject(with: Data(text[..<nl].utf8)) as? [String: Any],
              let body = try? JSONSerialization.jsonObject(with: Data(text[text.index(after: nl)...].utf8)) as? [String: Any]
        else { return nil }
        var out: [String] = []
        let date = (head["timestamp"] as? String) ?? (body["captureTime"] as? String) ?? "?"
        out.append("Crash: \(head["app_version"] as? String ?? "?") (\(head["build_version"] as? String ?? "?")) · \(date)")
        out.append("OS: \(head["os_version"] as? String ?? "?")")
        if let ex = body["exception"] as? [String: Any] {
            out.append("Exception: \(ex["type"] as? String ?? "?") \(ex["signal"] as? String ?? "") \(ex["subtype"] as? String ?? "")")
        }
        if let t = body["termination"] as? [String: Any], let ind = t["indicator"] as? String { out.append("Termination: \(ind)") }
        if let asi = body["asi"] as? [String: [String]] {
            for (_, msgs) in asi { for m in msgs.prefix(3) { out.append("Message: \(m.prefix(300))") } }
        }
        let images = (body["usedImages"] as? [[String: Any]]) ?? []
        if let threads = body["threads"] as? [[String: Any]],
           let crashed = threads.first(where: { $0["triggered"] as? Bool == true }),
           let frames = crashed["frames"] as? [[String: Any]] {
            out.append("Crashed thread\((crashed["queue"] as? String).map { " (\($0))" } ?? ""):")
            for (i, f) in frames.prefix(20).enumerated() {
                let idx = f["imageIndex"] as? Int ?? -1
                let img = idx >= 0 && idx < images.count ? (images[idx]["name"] as? String ?? "?") : "?"
                let sym = (f["symbol"] as? String) ?? "0x" + String(f["imageOffset"] as? Int ?? 0, radix: 16)
                out.append("  \(i) \(img) \(sym.prefix(160))")
            }
        }
        return scrub(out.joined(separator: "\n"))
    }

    /// Kişisel bilgileri çıkarır: ev klasörü, kullanıcı adı.
    static func scrub(_ s: String) -> String {
        var t = s.replacingOccurrences(of: NSHomeDirectory(), with: "~")
        let user = NSUserName()
        if user.count >= 3 { t = t.replacingOccurrences(of: user, with: "<user>") }
        return t
    }
}
