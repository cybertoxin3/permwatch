import AppKit
import Foundation

/// Bir uygulamayı ve ona ait dosyaları bulur ve Çöp Sepeti'ne taşır (geri alınabilir).
/// Kalıcı silme kullanıcının Çöp Sepeti'ni boşaltmasıyla olur.
enum Uninstaller {
    struct Candidate: Identifiable, Hashable {
        var id: String { path }
        let path: String
        let size: Int64
        let isApp: Bool
    }

    enum Blocked { case system, apple, permwatch, missing }

    /// Kaldırılamayacak uygulamalar: sistem/Apple uygulamaları ve permwatch'ın kendisi.
    static func blockReason(_ appPath: String) -> Blocked? {
        guard appPath.hasSuffix(".app"), FileManager.default.fileExists(atPath: appPath) else { return .missing }
        if appPath.hasPrefix("/System/") { return .system }
        if appPath == Bundle.main.bundlePath { return .permwatch }
        if Signing.classify(path: appPath).signature == "apple" { return .apple }
        return nil
    }

    static func bundleID(_ appPath: String) -> String? {
        Bundle(path: appPath)?.bundleIdentifier
    }

    /// Uygulama paketi + kullanıcı Library'sindeki ilgili dosyalar + uygulamanın içindeki
    /// programları çalıştıran başlangıç öğeleri.
    static func candidates(appPath: String, launchPlists: [String]) -> [Candidate] {
        let fm = FileManager.default
        let home = NSHomeDirectory() + "/Library"
        var paths = [appPath]
        let name = PathUtil.displayName(appPath)
        if let id = bundleID(appPath) {
            paths += [
                "\(home)/Application Support/\(id)", "\(home)/Caches/\(id)", "\(home)/Preferences/\(id).plist",
                "\(home)/Containers/\(id)", "\(home)/Saved Application State/\(id).savedState",
                "\(home)/HTTPStorages/\(id)", "\(home)/HTTPStorages/\(id).binarycookies",
                "\(home)/WebKit/\(id)", "\(home)/Cookies/\(id).binarycookies",
            ]
            if let agents = try? fm.contentsOfDirectory(atPath: "\(home)/LaunchAgents") {
                paths += agents.filter { $0.hasPrefix(id) }.map { "\(home)/LaunchAgents/\($0)" }
            }
        }
        // Ada göre klasörler yalnızca genel olmayan, en az 4 harfli adlar için.
        if name.count >= 4 {
            paths += ["\(home)/Application Support/\(name)", "\(home)/Caches/\(name)", "\(home)/Logs/\(name)"]
        }
        // "Üretici Ürün" adlı uygulamalar verilerini çoğu zaman "Üretici/Ürün" altında tutar (ör. Google/Chrome).
        let words = name.split(separator: " ", maxSplits: 1).map(String.init)
        if words.count == 2, words[0].count >= 3, words[1].count >= 3 {
            paths += ["\(home)/Application Support/\(words[0])/\(words[1])", "\(home)/Caches/\(words[0])/\(words[1])"]
        }
        paths += launchPlists
        var seen = Set<String>()
        return paths.compactMap { p in
            guard !seen.contains(p), fm.fileExists(atPath: p) else { return nil }
            seen.insert(p)
            return Candidate(path: p, size: size(of: p), isApp: p == appPath)
        }
    }

    static func size(of path: String) -> Int64 {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else { return 0 }
        if !isDir.boolValue {
            return (try? fm.attributesOfItem(atPath: path)[.size] as? Int64) ?? 0
        }
        var total: Int64 = 0
        let keys: [URLResourceKey] = [.totalFileAllocatedSizeKey]
        if let e = fm.enumerator(at: URL(fileURLWithPath: path), includingPropertiesForKeys: keys, options: [], errorHandler: nil) {
            for case let u as URL in e {
                total += Int64((try? u.resourceValues(forKeys: Set(keys)).totalFileAllocatedSize) ?? 0)
            }
        }
        return total
    }

    /// 1) Çalışıyorsa uygulamayı kapatır, 2) kullanıcı LaunchAgent'larını durdurur,
    /// 3) istenirse izinlerini sıfırlar, 4) seçilenleri Çöp Sepeti'ne taşır.
    static func run(_ items: [Candidate], bundleID: String?, resetPermissions: Bool,
                    completion: @escaping (_ failed: [String]) -> Void) {
        if let id = bundleID {
            for app in NSRunningApplication.runningApplications(withBundleIdentifier: id) { app.terminate() }
        }
        let uid = getuid()
        for c in items where c.path.hasSuffix(".plist") && c.path.contains("/LaunchAgents/") && c.path.hasPrefix(NSHomeDirectory()) {
            _ = Shell.run("/bin/launchctl", ["bootout", "gui/\(uid)", c.path])
        }
        if resetPermissions, let id = bundleID {
            _ = Shell.run("/usr/bin/tccutil", ["reset", "All", id])
        }
        // Uygulamanın kapanmasına kısa bir süre tanı.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            let urls = items.map { URL(fileURLWithPath: $0.path) }
            NSWorkspace.shared.recycle(urls) { _, _ in
                // recycle, root'a ait uygulamalarda (çoğu /Applications uygulaması) ve macOS'un
                // "Uygulama Yönetimi" korumasında yetki isteyemeden başarısız olur. Gerçekten
                // yerinde kalanları Finder'a devret: Finder gerekirse yönetici şifresini sorar.
                let fm = FileManager.default
                let left = items.map(\.path).filter { fm.fileExists(atPath: $0) }
                guard !left.isEmpty else { completion([]); return }
                DispatchQueue.main.async {
                    let errors = trashWithFinder(left)
                    let still = left.filter { fm.fileExists(atPath: $0) }
                    completion(still.map { p in errors[p].map { "\(p) (\($0))" } ?? p })
                }
            }
        }
    }

    /// Finder ile Çöp Sepeti'ne taşır (sürükle-bırak ile aynı; gerektiğinde yetki ister).
    /// Dönen sözlük: yol → hata mesajı.
    @discardableResult
    static func trashWithFinder(_ paths: [String]) -> [String: String] {
        var errors: [String: String] = [:]
        for p in paths {
            let escaped = p.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            let src = "tell application \"Finder\" to delete (POSIX file \"\(escaped)\" as alias)"
            var err: NSDictionary?
            NSAppleScript(source: src)?.executeAndReturnError(&err)
            if let e = err {
                errors[p] = (e[NSAppleScript.errorMessage] as? String) ?? "\(e[NSAppleScript.errorNumber] ?? "?")"
            }
        }
        return errors
    }
}

enum Shell {
    /// Komutu çalıştırır; (çıkış kodu, stderr+stdout) döner.
    @discardableResult
    static func run(_ tool: String, _ args: [String]) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (-1, error.localizedDescription) }
        // Önce oku, sonra bekle: çıktı boru tamponunu (64 KB) aşarsa aksi halde ikisi de kilitlenir.
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let out = String(data: data, encoding: .utf8) ?? ""
        return (p.terminationStatus, out.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}

/// Uygulama ikonları (önbellekli).
enum IconCache {
    private static var cache: [String: NSImage] = [:]

    static func resolve(_ key: String) -> String? {
        if key.hasPrefix("bundle:") { return Signing.appPath(bundleID: String(key.dropFirst(7))) }
        return FileManager.default.fileExists(atPath: key) ? key : nil
    }

    static func icon(for key: String) -> NSImage? {
        if let c = cache[key] { return c }
        guard let path = resolve(key) else { return nil }
        let img = NSWorkspace.shared.icon(forFile: path)
        cache[key] = img
        return img
    }
}
