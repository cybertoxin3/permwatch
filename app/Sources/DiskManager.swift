import AppKit
import Foundation

// MARK: - Boyut ölçümü

enum DiskSize {
    /// Yolların diskte kapladığı alanı (ayrılmış bloklar, bayt) `du -sk` ile toplu ölçer.
    /// Okunamayan yollar 0 sayılır. du, FileManager ile tek tek gezmekten çok daha hızlıdır.
    static func sizes(_ paths: [String]) -> [String: Int64] {
        var out: [String: Int64] = [:]
        let unique = Array(Set(paths))
        var i = 0
        while i < unique.count {
            let part = Array(unique[i..<min(i + 150, unique.count)])
            i += 150
            let (_, text) = Shell.run("/usr/bin/du", ["-sk"] + part)
            let wanted = Set(part)
            for line in text.split(separator: "\n") {
                guard let tab = line.firstIndex(of: "\t"), let kb = Int64(line[..<tab]) else { continue }
                let p = String(line[line.index(after: tab)...])
                if wanted.contains(p) { out[p] = kb * 1024 }
            }
        }
        return out
    }

    static func size(_ path: String) -> Int64 { sizes([path])[path] ?? 0 }

    static func string(_ b: Int64) -> String { ByteCountFormatter.string(fromByteCount: b, countStyle: .file) }
}

// MARK: - Modeller

struct DiskVolume: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let name: String
    let total: Int64
    let available: Int64
    /// macOS'un gerektiğinde boşaltabileceği alan dahil (temizlenebilir).
    let availableImportant: Int64
    let isInternal: Bool
    let isRoot: Bool
    let isRemovable: Bool
    var used: Int64 { max(0, total - availableImportant) }
    var purgeable: Int64 { max(0, availableImportant - available) }
}

struct DiskCategory: Identifiable, Hashable {
    let id: String
    let icon: String
    let colorIndex: Int
    let path: String?
    var size: Int64
    var title: String { L("disk.cat.\(id)") }
}

struct DiskApp: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let name: String
    let bundleID: String?
    let version: String?
    let appStore: Bool
    var appSize: Int64 = 0
    var dataSize: Int64 = 0
    var lastUsed: Date?
    var total: Int64 { appSize + dataSize }
    /// Sıralama için: hiç açılmamışsa en eski sayılır.
    var lastUsedSort: Date { lastUsed ?? .distantPast }

    var unused: Bool {
        guard let d = lastUsed else { return true }
        return d < Date().addingTimeInterval(-90 * 86400)
    }
}

enum JunkGroup: String, CaseIterable, Identifiable {
    case trash, browser, caches, logs, developer, other
    var id: String { rawValue }
    var title: String { L("disk.junk.\(rawValue)") }
    var icon: String {
        switch self {
        case .trash: return "trash"
        case .browser: return "globe"
        case .caches: return "archivebox"
        case .logs: return "doc.text.magnifyingglass"
        case .developer: return "hammer"
        case .other: return "tray.full"
        }
    }
}

struct JunkItem: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let title: String
    let group: JunkGroup
    var size: Int64
    /// Varsayılan olarak seçili mi (güvenle silinebilir mi).
    let safe: Bool
    /// Klasörün kendisi kalır, yalnızca içi boşaltılır.
    let contentsOnly: Bool
    var note: String? = nil
}

struct BigFile: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let size: Int64
    let accessed: Date?
    let modified: Date?
    var name: String { (path as NSString).lastPathComponent }
    var kind: String {
        switch (path as NSString).pathExtension.lowercased() {
        case "mov", "mp4", "m4v", "mkv", "avi", "webm": return "video"
        case "dmg", "iso", "img", "sparseimage", "sparsebundle", "raw", "qcow2", "vmdk", "vdi": return "image"
        case "zip", "gz", "tgz", "xz", "bz2", "7z", "rar", "tar", "pkg", "xip": return "archive"
        case "mp3", "wav", "aiff", "flac", "m4a", "aac": return "audio"
        case "jpg", "jpeg", "png", "heic", "tiff", "psd", "dng", "cr2", "arw": return "photo"
        case "ipsw": return "ipsw"
        default: return "other"
        }
    }
}

struct Orphan: Identifiable, Hashable {
    let id: String
    let paths: [String]
    var size: Int64
}

// MARK: - Kalıntı bulucu (AppCleaner benzeri derin arama)

enum Leftovers {
    struct Location: Hashable {
        let dir: String
        let group: String
        let system: Bool
    }

    struct Entry: Hashable {
        let loc: Location
        let name: String
        var path: String { loc.dir + "/" + name }
    }

    static let home = NSHomeDirectory()

    static var locations: [Location] {
        let lib = home + "/Library"
        var l: [Location] = []
        func u(_ p: String, _ g: String) { l.append(Location(dir: lib + "/" + p, group: g, system: false)) }
        func s(_ p: String, _ g: String) { l.append(Location(dir: "/Library/" + p, group: g, system: true)) }
        u("Application Support", "support"); u("Application Scripts", "container")
        u("Caches", "cache"); u("Containers", "container"); u("Group Containers", "container")
        u("Preferences", "prefs"); u("Preferences/ByHost", "prefs")
        u("Saved Application State", "state")
        u("Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments", "state")
        u("HTTPStorages", "web"); u("WebKit", "web"); u("Cookies", "web")
        u("Logs", "logs"); u("Logs/DiagnosticReports", "logs"); u("Application Support/CrashReporter", "logs")
        u("LaunchAgents", "launch")
        for p in ["Internet Plug-Ins", "PreferencePanes", "Services", "QuickLook", "Spotlight", "Screen Savers",
                  "Audio/Plug-Ins/Components", "Address Book Plug-Ins", "Input Methods"] { u(p, "plugins") }
        s("Application Support", "support"); s("Caches", "cache"); s("Preferences", "prefs")
        s("LaunchAgents", "launch"); s("LaunchDaemons", "launch"); s("PrivilegedHelperTools", "launch")
        s("Logs", "logs"); s("Logs/DiagnosticReports", "logs")
        for p in ["Internet Plug-Ins", "PreferencePanes", "QuickLook", "Spotlight", "Screen Savers", "Services",
                  "Audio/Plug-Ins/HAL", "Audio/Plug-Ins/Components", "Input Methods"] { s(p, "plugins") }
        l.append(Location(dir: "/private/var/db/receipts", group: "receipts", system: true))
        // Kullanıcıya özel geçici önbellek klasörleri ($TMPDIR/../C, $TMPDIR).
        for name in [_CS_DARWIN_USER_CACHE_DIR, _CS_DARWIN_USER_TEMP_DIR] {
            var buf = [CChar](repeating: 0, count: 1024)
            if confstr(name, &buf, buf.count) > 0 {
                let p = String(cString: buf).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                l.append(Location(dir: "/" + p, group: "cache", system: false))
            }
        }
        return l
    }

    /// Tüm konumların ilk seviye içerikleri (bir kez okunur, tüm uygulamalar için kullanılır).
    static func buildIndex() -> [Entry] {
        let fm = FileManager.default
        var out: [Entry] = []
        for loc in locations {
            guard let names = try? fm.contentsOfDirectory(atPath: loc.dir) else { continue }
            for n in names where !n.hasPrefix(".") { out.append(Entry(loc: loc, name: n)) }
        }
        return out
    }

    private static let stripExt: Set<String> = [
        "plist", "savedstate", "binarycookies", "sfl2", "sfl3", "sfl", "appex", "app", "bundle", "plugin",
        "qlgenerator", "mdimporter", "prefpane", "saver", "component", "driver", "bom", "ips", "crash", "diag",
        "log", "lockfile", "inputmethod", "service", "spi", "db", "lock",
    ]

    static func base(_ name: String) -> String {
        var b = name.lowercased()
        for _ in 0..<2 {
            let ext = (b as NSString).pathExtension
            if !ext.isEmpty, stripExt.contains(ext) { b = (b as NSString).deletingPathExtension } else { break }
        }
        return b
    }

    private static let generic: Set<String> = [
        "google", "microsoft", "adobe", "apple", "electron", "default", "setup", "installer", "helper", "update",
        "updater", "app", "application", "data", "cache", "caches", "logs", "temp", "tmp", "chrome", "mozilla",
        "java", "python", "node", "user", "shared", "common", "support", "plugins", "settings", "config",
    ]

    /// Uygulamanın kendisi ve içindeki yardımcı/eklentilerin paket kimlikleri.
    static func identifiers(appPath: String) -> [String] {
        var ids = Set<String>()
        if let id = Bundle(path: appPath)?.bundleIdentifier { ids.insert(id.lowercased()) }
        let fm = FileManager.default
        for sub in ["Contents/Library/LoginItems", "Contents/PlugIns", "Contents/Library/SystemExtensions",
                    "Contents/Helpers", "Contents/Library/QuickLook", "Contents/Library/Spotlight"] {
            let dir = appPath + "/" + sub
            for n in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] {
                if let id = Bundle(path: dir + "/" + n)?.bundleIdentifier { ids.insert(id.lowercased()) }
            }
        }
        // Yönetici yardımcıları (SMJobBless): dosya adı = etiket = /Library/PrivilegedHelperTools içindeki ad.
        for n in (try? fm.contentsOfDirectory(atPath: appPath + "/Contents/Library/LaunchServices")) ?? [] {
            ids.insert(n.lowercased())
        }
        return ids.filter { $0.split(separator: ".").count >= 2 && !$0.hasPrefix("com.apple.") }.sorted()
    }

    /// Bir uygulamaya ait dosyalar. `others`: başka kurulu uygulamaların kimlikleri (yanlış eşleşmeyi önler).
    static func find(appPath: String, index: [Entry], others: Set<String>) -> [Uninstaller.Candidate] {
        let bundle = Bundle(path: appPath)
        let ids = identifiers(appPath: appPath)
        let fileName = ((appPath as NSString).lastPathComponent as NSString).deletingPathExtension
        var names = Set([fileName, bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String,
                         bundle?.object(forInfoDictionaryKey: "CFBundleExecutable") as? String]
            .compactMap { $0?.lowercased() }
            .filter { $0.count >= 4 && !generic.contains($0) })
        names.formUnion(names.map { $0.replacingOccurrences(of: " ", with: "") })
        let team = Signing.info(path: appPath)?.teamID?.lowercased()
        let words = fileName.lowercased().split(separator: " ", maxSplits: 1).map(String.init)
        let otherIDs = others.subtracting(ids)

        var out: [Uninstaller.Candidate] = []
        var seen = Set<String>()
        // Dosya sistemi büyük/küçük harf duyarsız: aynı klasör farklı yazımla iki kez sayılmasın.
        func add(_ p: String, _ g: String, weak: Bool) {
            guard !seen.contains(p.lowercased()) else { return }
            seen.insert(p.lowercased())
            out.append(Uninstaller.Candidate(path: p, size: 0, isApp: false, byName: weak, group: g))
        }

        for e in index {
            let b = base(e.name)
            if b.hasPrefix("com.apple.") { continue }
            // Daha uzun, başka bir uygulamaya ait kimlik (ör. com.google.chrome.canary ≠ com.google.chrome).
            let ownedByOther = otherIDs.contains { o in
                (b == o || b.hasPrefix(o + ".") || b.hasSuffix("." + o)) && !ids.contains { $0.count >= o.count && (b == $0 || b.hasPrefix($0 + ".")) }
            }
            if ownedByOther { continue }
            if ids.contains(where: { b == $0 || b.hasPrefix($0 + ".") || b.hasSuffix("." + $0) || b.contains("." + $0 + ".") || b.hasPrefix($0 + "_") }) {
                add(e.path, e.loc.group, weak: false); continue
            }
            if names.contains(b) { add(e.path, e.loc.group, weak: false); continue }
            // Çökme raporları süreç adıyla başlar: "Slack_2026-01-02-….ips", "Slack-2026-….ips".
            if e.loc.group == "logs", names.contains(where: { b.hasPrefix($0 + "_") || b.hasPrefix($0 + "-") || b.hasPrefix($0 + " ") }) {
                add(e.path, e.loc.group, weak: false); continue
            }
            // Ekip kimliğiyle paylaşılan grup klasörleri (aynı üreticinin başka uygulamalarıyla ortak olabilir).
            if let team, e.loc.group == "container", b.hasPrefix(team + ".") { add(e.path, e.loc.group, weak: true); continue }
            // Ad geçiyor ama birebir değil: zayıf eşleşme, varsayılan seçili gelmez.
            if e.loc.group != "receipts", names.contains(where: { $0.count >= 5 && b.contains($0) }) {
                add(e.path, e.loc.group, weak: true)
            }
        }

        // "Üretici Ürün" → Application Support/Üretici/Ürün (ör. Google/Chrome).
        if words.count == 2, words[0].count >= 3, words[1].count >= 3 {
            let fm = FileManager.default
            // Diskteki gerçek yazımı bul (ör. "Google/Chrome").
            func child(_ dir: String, _ lower: String) -> String? {
                ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).first { $0.lowercased() == lower }.map { dir + "/" + $0 }
            }
            for root in [home + "/Library/Application Support", home + "/Library/Caches", "/Library/Application Support"] {
                if let v = child(root, words[0]), let c = child(v, words[1]) {
                    add(c, root.contains("Caches") ? "cache" : "support", weak: false)
                }
            }
        }

        // Adı uymasa da programı bu uygulamanın içinden çalıştıran başlangıç öğeleri.
        for e in index where e.loc.group == "launch" && e.name.hasSuffix(".plist") && !seen.contains(e.path.lowercased()) {
            guard let d = NSDictionary(contentsOfFile: e.path) else { continue }
            let prog = (d["Program"] as? String) ?? ((d["ProgramArguments"] as? [String])?.first ?? "")
            if prog.hasPrefix(appPath + "/") { add(e.path, "launch", weak: false) }
        }
        return out
    }

    /// Bir yol sistem konumunda mı (silmek için yönetici izni gerekir)?
    static func isSystem(_ p: String) -> Bool { !p.hasPrefix(home + "/") && !p.hasSuffix(".app") }
}

// MARK: - Yönetici

@MainActor
final class DiskManager: ObservableObject {
    static let shared = DiskManager()

    @Published var volumes: [DiskVolume] = []
    @Published var categories: [DiskCategory] = []
    @Published var apps: [DiskApp] = []
    @Published var junk: [JunkItem] = []
    @Published var orphans: [Orphan] = []
    @Published var bigFiles: [BigFile] = []
    @Published var scanning = false
    @Published var phase = ""
    @Published var lastScan: Date?
    @Published var bigScanning = false
    @Published var bigScanned = 0

    private var index: [Leftovers.Entry] = []
    private var installedIDs = Set<String>()
    private var bigCancel = false

    var root: DiskVolume? { volumes.first(where: \.isRoot) ?? volumes.first }
    var trashSize: Int64 { junk.filter { $0.group == .trash }.reduce(0) { $0 + $1.size } }
    var cleanable: Int64 { junk.filter(\.safe).reduce(0) { $0 + $1.size } }
    var orphanSize: Int64 { orphans.reduce(0) { $0 + $1.size } }
    var appsSize: Int64 { apps.reduce(0) { $0 + $1.appSize } }

    func scanIfNeeded() {
        if lastScan == nil && !scanning { scan() }
    }

    func scan() {
        guard !scanning else { return }
        scanning = true
        volumes = Self.readVolumes()
        phase = L("disk.phase.apps")
        Task.detached(priority: .userInitiated) {
            var apps = Self.listApps()
            let sizes = DiskSize.sizes(apps.map(\.path))
            for i in apps.indices { apps[i].appSize = sizes[apps[i].path] ?? 0 }
            let snapshot = apps
            await MainActor.run { self.apps = snapshot.sorted { $0.total > $1.total }; self.phase = L("disk.phase.leftovers") }

            // Kalıntılar: her uygulama için eşleşen yollar, sonra tek seferde boyut.
            let index = Leftovers.buildIndex()
            var ids = Set<String>()
            for a in apps { ids.formUnion(Leftovers.identifiers(appPath: a.path)) }
            var perApp: [String: [String]] = [:]
            for a in apps {
                perApp[a.path] = Leftovers.find(appPath: a.path, index: index, others: ids)
                    .filter { !$0.byName }.map(\.path)
            }
            let dataSizes = DiskSize.sizes(perApp.values.flatMap { $0 })
            for i in apps.indices {
                apps[i].dataSize = (perApp[apps[i].path] ?? []).reduce(0) { $0 + (dataSizes[$1] ?? 0) }
            }
            let withData = apps
            let allIDs = ids
            await MainActor.run {
                self.index = index
                self.installedIDs = allIDs
                self.apps = withData.sorted { $0.total > $1.total }
                self.phase = L("disk.phase.junk")
            }

            let junk = Self.findJunk()
            await MainActor.run { self.junk = junk; self.phase = L("disk.phase.orphans") }
            let orphans = Self.findOrphans(index: index, installed: ids)
            await MainActor.run { self.orphans = orphans; self.phase = L("disk.phase.categories") }
            let cats = Self.readCategories(appsSize: apps.reduce(0) { $0 + $1.appSize },
                                           cachesSize: junk.filter { $0.group != .trash && $0.group != .developer }.reduce(0) { $0 + $1.size },
                                           trashSize: junk.filter { $0.group == .trash }.reduce(0) { $0 + $1.size })
            await MainActor.run {
                self.categories = cats
                self.scanning = false
                self.phase = ""
                self.lastScan = Date()
            }
        }
    }

    // MARK: Birimler

    nonisolated static func readVolumes() -> [DiskVolume] {
        let keys: [URLResourceKey] = [.volumeNameKey, .volumeTotalCapacityKey, .volumeAvailableCapacityKey,
                                      .volumeAvailableCapacityForImportantUsageKey, .volumeIsInternalKey,
                                      .volumeIsRootFileSystemKey, .volumeIsRemovableKey, .volumeIsEjectableKey]
        let urls = FileManager.default.mountedVolumeURLs(includingResourceValuesForKeys: keys, options: [.skipHiddenVolumes]) ?? []
        return urls.compactMap { u in
            guard let v = try? u.resourceValues(forKeys: Set(keys)), let total = v.volumeTotalCapacity, total > 0 else { return nil }
            let avail = Int64(v.volumeAvailableCapacity ?? 0)
            return DiskVolume(path: u.path, name: v.volumeName ?? u.lastPathComponent, total: Int64(total),
                              available: avail, availableImportant: max(avail, v.volumeAvailableCapacityForImportantUsage ?? avail),
                              isInternal: v.volumeIsInternal ?? false, isRoot: v.volumeIsRootFileSystem ?? (u.path == "/"),
                              isRemovable: (v.volumeIsRemovable ?? false) || (v.volumeIsEjectable ?? false))
        }
        .sorted { ($0.isRoot ? 0 : 1, $0.name) < ($1.isRoot ? 0 : 1, $1.name) }
    }

    // MARK: Uygulamalar

    nonisolated static func appFolders() -> [String] {
        ["/Applications", Leftovers.home + "/Applications"]
    }

    nonisolated static func listApps() -> [DiskApp] {
        let fm = FileManager.default
        var paths: [String] = []
        func walk(_ dir: String, depth: Int) {
            for n in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] where !n.hasPrefix(".") {
                let p = dir + "/" + n
                if n.hasSuffix(".app") { paths.append(p) }
                else if depth < 2 {
                    var isDir: ObjCBool = false
                    if fm.fileExists(atPath: p, isDirectory: &isDir), isDir.boolValue { walk(p, depth: depth + 1) }
                }
            }
        }
        for f in appFolders() { walk(f, depth: 0) }
        return paths.compactMap { makeApp($0) }
    }

    nonisolated static func makeApp(_ p: String) -> DiskApp? {
        // /Applications altındaki sistem uygulaması bağlantıları (Safari vb.) gerçek yol olarak /System altındadır.
        let real = (p as NSString).resolvingSymlinksInPath
        if real.hasPrefix("/System/") { return nil }
        let b = Bundle(path: p)
        let name = (b?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? ((p as NSString).lastPathComponent as NSString).deletingPathExtension
        var last = NSMetadataItem(url: URL(fileURLWithPath: p))?.value(forAttribute: "kMDItemLastUsedDate") as? Date
        // Spotlight her uygulama için kayıt tutmuyor: uygulamanın en son yazdığı tercih/durum dosyasına bak.
        if last == nil, let id = b?.bundleIdentifier {
            let lib = Leftovers.home + "/Library/"
            last = ["Preferences/\(id).plist", "Saved Application State/\(id).savedState",
                    "Containers/\(id)", "HTTPStorages/\(id)", "Caches/\(id)"]
                .compactMap { (try? FileManager.default.attributesOfItem(atPath: lib + $0))?[.modificationDate] as? Date }
                .max()
        }
        return DiskApp(path: p, name: name, bundleID: b?.bundleIdentifier,
                       version: b?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
                       appStore: FileManager.default.fileExists(atPath: p + "/Contents/_MASReceipt/receipt"),
                       lastUsed: last)
    }

    /// Sürükle-bırak ile gelen uygulamayı listeye ekler (listede yoksa).
    func adopt(_ path: String) -> DiskApp? {
        if let a = apps.first(where: { $0.path == path }) { return a }
        guard var a = Self.makeApp(path) else { return nil }
        a.appSize = DiskSize.size(path)
        apps.insert(a, at: 0)
        return a
    }

    /// Seçilen uygulamanın tüm dosyaları, boyutlarıyla (arka planda).
    func leftovers(for app: DiskApp, extraLaunch: [String]) async -> [Uninstaller.Candidate] {
        let index = self.index.isEmpty ? nil : self.index
        let ids = installedIDs
        return await Task.detached(priority: .userInitiated) {
            let idx = index ?? Leftovers.buildIndex()
            var list = [Uninstaller.Candidate(path: app.path, size: 0, isApp: true, group: "app")]
            list += Leftovers.find(appPath: app.path, index: idx, others: ids)
            for p in extraLaunch where !list.contains(where: { $0.path == p }) && FileManager.default.fileExists(atPath: p) {
                list.append(Uninstaller.Candidate(path: p, size: 0, isApp: false, group: "launch"))
            }
            let sizes = DiskSize.sizes(list.map(\.path))
            return list.map { var c = $0; c.size = sizes[$0.path] ?? 0; return c }
        }.value
    }

    func forget(_ app: DiskApp, keptApp: Bool) {
        if keptApp {
            if let i = apps.firstIndex(where: { $0.path == app.path }) { apps[i].dataSize = 0 }
        } else {
            apps.removeAll { $0.path == app.path }
        }
        volumes = Self.readVolumes()
    }

    /// /Library ve /private/var/db altındaki öğeler: tek yönetici şifresiyle durdurur ve siler.
    /// Dönen: silinemeyen yollar.
    nonisolated static func removeSystemItems(_ paths: [String]) -> [String] {
        guard !paths.isEmpty else { return [] }
        func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        var cmds: [String] = []
        let uid = getuid()
        for p in paths {
            if p.hasPrefix("/Library/LaunchDaemons/") { cmds.append("launchctl bootout system \(q(p)) 2>/dev/null") }
            if p.hasPrefix("/Library/LaunchAgents/") { cmds.append("launchctl bootout gui/\(uid) \(q(p)) 2>/dev/null") }
            if p.hasPrefix("/private/var/db/receipts/") {
                let id = Leftovers.base((p as NSString).lastPathComponent)
                cmds.append("pkgutil --forget \(q(id)) >/dev/null 2>&1")
            }
            cmds.append("rm -rf \(q(p))")
        }
        let shell = cmds.joined(separator: "; ") + "; true"
        let escaped = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        var err: NSDictionary?
        NSAppleScript(source: "do shell script \"\(escaped)\" with administrator privileges")?.executeAndReturnError(&err)
        return paths.filter { FileManager.default.fileExists(atPath: $0) }
    }

    // MARK: Önbellek ve gereksiz dosyalar

    nonisolated static let browserCaches: Set<String> = [
        "com.apple.safari", "google", "firefox", "mozilla", "com.microsoft.edgemac", "bravesoftware",
        "company.thebrowser.browser", "com.operasoftware.opera", "yandex", "com.vivaldi.vivaldi", "chromium",
    ]

    nonisolated static func findJunk() -> [JunkItem] {
        let fm = FileManager.default
        let h = Leftovers.home
        var items: [JunkItem] = []
        func exists(_ p: String) -> Bool { fm.fileExists(atPath: p) }

        if exists(h + "/.Trash") {
            items.append(JunkItem(path: h + "/.Trash", title: L("disk.junk.trashItem"), group: .trash, size: 0, safe: true, contentsOnly: true))
        }
        for n in (try? fm.contentsOfDirectory(atPath: h + "/Library/Caches")) ?? [] where !n.hasPrefix(".") {
            let p = h + "/Library/Caches/" + n
            let l = n.lowercased()
            let browser = browserCaches.contains(l)
            // Apple'ın kendi önbellekleri çoğunlukla korunur ya da hemen yeniden oluşur: listelenir ama seçili gelmez.
            let apple = l.hasPrefix("com.apple.") && !browser
            items.append(JunkItem(path: p, title: n, group: browser ? .browser : .caches, size: 0,
                                  safe: !apple, contentsOnly: true, note: apple ? L("disk.note.apple") : nil))
        }
        for n in (try? fm.contentsOfDirectory(atPath: h + "/Library/Logs")) ?? [] where !n.hasPrefix(".") {
            items.append(JunkItem(path: h + "/Library/Logs/" + n, title: n, group: .logs, size: 0, safe: true, contentsOnly: true))
        }
        let dev: [(String, String, Bool, String?)] = [
            ("Library/Developer/Xcode/DerivedData", "Xcode DerivedData", true, nil),
            ("Library/Developer/Xcode/Archives", "Xcode Archives", false, L("disk.note.archives")),
            ("Library/Developer/Xcode/iOS DeviceSupport", "iOS DeviceSupport", true, nil),
            ("Library/Developer/Xcode/watchOS DeviceSupport", "watchOS DeviceSupport", true, nil),
            ("Library/Developer/Xcode/macOS DeviceSupport", "macOS DeviceSupport", true, nil),
            ("Library/Developer/Xcode/UserData/Previews", "SwiftUI Previews", true, nil),
            ("Library/Developer/CoreSimulator/Caches", "Simulator Caches", true, nil),
            ("Library/Developer/CoreSimulator/Devices", "Simulator Devices", false, L("disk.note.simulators")),
            (".npm/_cacache", "npm cache", true, nil),
            (".pnpm-store", "pnpm store", true, nil),
            (".yarn/berry/cache", "Yarn cache", true, nil),
            (".gradle/caches", "Gradle caches", true, nil),
            (".m2/repository", "Maven repository", false, nil),
            (".cargo/registry/cache", "Cargo cache", true, nil),
            ("go/pkg/mod/cache", "Go module cache", true, nil),
            (".cache", "~/.cache", false, nil),
            (".cocoapods/repos", "CocoaPods repos", false, nil),
            ("Library/Containers/com.docker.docker/Data/vms", "Docker", false, L("disk.note.docker")),
        ]
        for (p, t, safe, note) in dev where exists(h + "/" + p) {
            items.append(JunkItem(path: h + "/" + p, title: t, group: .developer, size: 0, safe: safe, contentsOnly: true, note: note))
        }
        let other: [(String, String, Bool, String?)] = [
            ("Library/Containers/com.apple.mail/Data/Library/Mail Downloads", L("disk.junk.mailDownloads"), true, nil),
            ("Library/Application Support/MobileSync/Backup", L("disk.junk.iosBackups"), false, L("disk.note.backups")),
            ("Library/iTunes/iPhone Software Updates", "iPhone Software Updates", true, nil),
            ("Library/iTunes/iPad Software Updates", "iPad Software Updates", true, nil),
            ("Library/Application Support/CrashReporter", L("disk.junk.crashReports"), true, nil),
        ]
        for (p, t, safe, note) in other where exists(h + "/" + p) {
            items.append(JunkItem(path: h + "/" + p, title: t, group: .other, size: 0, safe: safe, contentsOnly: true, note: note))
        }
        let sizes = DiskSize.sizes(items.map(\.path))
        for i in items.indices { items[i].size = sizes[items[i].path] ?? 0 }
        // Boş klasörler (≤ 4 KB, yalnızca klasörün kendisi) gösterilmez.
        return items.filter { $0.size > 8 * 1024 }.sorted { ($0.group.rawValue, -$0.size) < ($1.group.rawValue, -$1.size) }
    }

    /// Seçilen önbellekleri kalıcı olarak siler. Dönen: (boşaltılan bayt, silinemeyen öğe sayısı).
    func clean(_ items: [JunkItem], completion: @escaping (Int64, Int) -> Void) {
        Task.detached(priority: .userInitiated) {
            let fm = FileManager.default
            var failed = 0
            for it in items {
                if it.contentsOnly {
                    for n in (try? fm.contentsOfDirectory(atPath: it.path)) ?? [] {
                        do { try fm.removeItem(atPath: it.path + "/" + n) } catch { failed += 1 }
                    }
                } else {
                    do { try fm.removeItem(atPath: it.path) } catch { failed += 1 }
                }
            }
            // Çöp Sepeti'nde izin vermeyen öğe kaldıysa Finder'a boşalttır (gerekirse şifre ister).
            let trash = Leftovers.home + "/.Trash"
            if items.contains(where: { $0.path == trash }), !((try? fm.contentsOfDirectory(atPath: trash)) ?? []).filter({ $0 != ".DS_Store" }).isEmpty {
                await MainActor.run {
                    var err: NSDictionary?
                    NSAppleScript(source: "tell application \"Finder\" to empty trash")?.executeAndReturnError(&err)
                }
            }
            let after = DiskSize.sizes(items.map(\.path))
            let freed = items.reduce(Int64(0)) { $0 + max(0, $1.size - (after[$1.path] ?? 0)) }
            let failedCount = failed
            await MainActor.run {
                for i in self.junk.indices { if let s = after[self.junk[i].path] { self.junk[i].size = s } }
                self.junk.removeAll { $0.size <= 8 * 1024 }
                self.volumes = Self.readVolumes()
                completion(freed, failedCount)
            }
        }
    }

    // MARK: Sahipsiz kalıntılar

    nonisolated static func findOrphans(index: [Leftovers.Entry], installed: Set<String>) -> [Orphan] {
        let rdns = try! NSRegularExpression(pattern: "^[a-z0-9-]+(\\.[a-z0-9_-]+){2,}$")
        let team = try! NSRegularExpression(pattern: "^[a-z0-9]{10}\\.")
        let uuid = try! NSRegularExpression(pattern: "\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        let running = Set(NSWorkspace.shared.runningApplications.compactMap { $0.bundleIdentifier?.lowercased() })
        let userGroups: Set<String> = ["support", "cache", "container", "prefs", "state", "web", "launch"]
        var groups: [String: [String]] = [:]
        for e in index where !e.loc.system && userGroups.contains(e.loc.group) {
            var b = Leftovers.base(e.name)
            if b.hasPrefix("group.") { b = String(b.dropFirst(6)) }
            if let m = team.firstMatch(in: b, range: NSRange(b.startIndex..., in: b)), m.range.location == 0 {
                b = String(b.dropFirst(11))
            }
            if let m = uuid.firstMatch(in: b, range: NSRange(b.startIndex..., in: b)), let r = Range(m.range, in: b) {
                b.removeSubrange(r)
            }
            guard rdns.firstMatch(in: b, range: NSRange(b.startIndex..., in: b)) != nil else { continue }
            if b.hasPrefix("com.apple.") || b.hasPrefix("apple.") || b.hasPrefix("systemgroup.") || b.contains("com.apple.")
                || b.hasPrefix("com.yusuf.permwatch") { continue }
            groups[b, default: []].append(e.path)
        }
        var out: [Orphan] = []
        for (id, paths) in groups {
            if running.contains(id) { continue }
            if installed.contains(where: { id == $0 || id.hasPrefix($0 + ".") || $0.hasPrefix(id + ".") }) { continue }
            if running.contains(where: { id.hasPrefix($0 + ".") }) { continue }
            if NSWorkspace.shared.urlForApplication(withBundleIdentifier: id) != nil { continue }
            out.append(Orphan(id: id, paths: paths.sorted(), size: 0))
        }
        let sizes = DiskSize.sizes(out.flatMap(\.paths))
        for i in out.indices { out[i].size = out[i].paths.reduce(0) { $0 + (sizes[$1] ?? 0) } }
        return out.filter { $0.size > 0 }.sorted { $0.size > $1.size }
    }

    func trashOrphans(_ list: [Orphan], completion: @escaping (Int) -> Void) {
        let urls = list.flatMap(\.paths).map { URL(fileURLWithPath: $0) }
        NSWorkspace.shared.recycle(urls) { _, _ in
            DispatchQueue.main.async {
                let fm = FileManager.default
                let left = list.flatMap(\.paths).filter { fm.fileExists(atPath: $0) }
                if !left.isEmpty { Uninstaller.trashWithFinder(left) }
                let still = left.filter { fm.fileExists(atPath: $0) }
                self.orphans.removeAll { o in list.contains(o) && !o.paths.contains(where: still.contains) }
                self.volumes = Self.readVolumes()
                completion(still.count)
            }
        }
    }

    // MARK: Kategoriler (depolama dağılımı)

    nonisolated static func readCategories(appsSize: Int64, cachesSize: Int64, trashSize: Int64) -> [DiskCategory] {
        let h = Leftovers.home
        let folders: [(String, String, String)] = [
            ("documents", "doc", h + "/Documents"), ("desktop", "menubar.dock.rectangle", h + "/Desktop"),
            ("downloads", "arrow.down.circle", h + "/Downloads"), ("pictures", "photo", h + "/Pictures"),
            ("movies", "film", h + "/Movies"), ("music", "music.note", h + "/Music"),
            ("icloud", "icloud", h + "/Library/Mobile Documents"), ("developer", "hammer", h + "/Library/Developer"),
            ("mail", "envelope", h + "/Library/Mail"),
        ]
        let sizes = DiskSize.sizes(folders.map(\.2))
        var out = [DiskCategory(id: "apps", icon: "square.grid.2x2", colorIndex: 0, path: "/Applications", size: appsSize)]
        for (i, f) in folders.enumerated() {
            out.append(DiskCategory(id: f.0, icon: f.1, colorIndex: i + 1, path: f.2, size: sizes[f.2] ?? 0))
        }
        out.append(DiskCategory(id: "caches", icon: "archivebox", colorIndex: 10, path: h + "/Library/Caches", size: cachesSize))
        out.append(DiskCategory(id: "trash", icon: "trash", colorIndex: 11, path: h + "/.Trash", size: trashSize))
        return out.filter { $0.size > 0 }
    }

    // MARK: Büyük dosyalar

    func scanBigFiles(minSize: Int64) {
        guard !bigScanning else { return }
        bigScanning = true
        bigCancel = false
        bigScanned = 0
        bigFiles = []
        Task.detached(priority: .userInitiated) {
            let home = URL(fileURLWithPath: Leftovers.home)
            let keys: [URLResourceKey] = [.isRegularFileKey, .totalFileAllocatedSizeKey, .contentAccessDateKey, .contentModificationDateKey]
            let skip = Set([Leftovers.home + "/.Trash", Leftovers.home + "/Library/Caches"])
            var found: [BigFile] = []
            var n = 0
            let e = FileManager.default.enumerator(at: home, includingPropertiesForKeys: keys, options: [], errorHandler: { _, _ in true })
            while let u = e?.nextObject() as? URL {
                n += 1
                if n % 5000 == 0 {
                    let c = n
                    let cancel = await MainActor.run { self.bigScanned = c; return self.bigCancel }
                    if cancel { break }
                }
                if skip.contains(u.path) { e?.skipDescendants(); continue }
                guard let v = try? u.resourceValues(forKeys: Set(keys)), v.isRegularFile == true,
                      let s = v.totalFileAllocatedSize, Int64(s) >= minSize else { continue }
                found.append(BigFile(path: u.path, size: Int64(s), accessed: v.contentAccessDate, modified: v.contentModificationDate))
            }
            let result = Array(found.sorted { $0.size > $1.size }.prefix(1000))
            await MainActor.run {
                self.bigFiles = result
                self.bigScanning = false
            }
        }
    }

    func cancelBigScan() { bigCancel = true }

    func trashFiles(_ paths: [String], completion: @escaping (Int) -> Void) {
        NSWorkspace.shared.recycle(paths.map { URL(fileURLWithPath: $0) }) { _, _ in
            DispatchQueue.main.async {
                let left = paths.filter { FileManager.default.fileExists(atPath: $0) }
                self.bigFiles.removeAll { paths.contains($0.path) && !left.contains($0.path) }
                self.volumes = Self.readVolumes()
                completion(left.count)
            }
        }
    }
}
