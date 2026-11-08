import AppKit
import Foundation
import ServiceManagement

/// "Çalıştırmadan önce engelle": permwatch-guard (Endpoint Security) servisini açar, durumunu ve
/// engellediği programları okur. Servis yalnızca Endpoint Security izniyle imzalanmış derlemelerde vardır.
@MainActor
final class GuardService: ObservableObject {
    static let shared = GuardService()
    nonisolated static let plistName = "com.yusuf.permwatch.guard.plist"
    nonisolated static let statusPath = "/Library/Application Support/permwatch/guard.json"
    nonisolated static let eventsPath = "/Library/Application Support/permwatch/guard-events.jsonl"
    nonisolated static let allowPath = NSHomeDirectory() + "/Library/Application Support/permwatch/guard-allow.txt"
    static var bundlePath: String { Bundle.main.bundlePath + "/Contents/Library/Guard/permwatch-guard.app" }

    enum State: Equatable { case unavailable, off, needsApproval, needsFullDisk, starting, active, failed(String) }

    @Published private(set) var state: State = .unavailable
    @Published private(set) var blocked = 0
    @Published private(set) var ruleCount = 0
    @Published private(set) var events: [GuardEvent] = []

    private var service: SMAppService { SMAppService.daemon(plistName: Self.plistName) }
    private var timer: Timer?
    private var readOffset: UInt64 = 0
    private let seenKey = "guardEventsSeen"

    var available: Bool { FileManager.default.fileExists(atPath: Bundle.main.bundlePath + "/Contents/Library/LaunchDaemons/" + Self.plistName) }

    private init() {
        // Önceki oturumda okunan olayları yeniden uyarı olarak gösterme.
        readOffset = UInt64(UserDefaults.standard.integer(forKey: seenKey))
        guard available else { return }
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func enable() {
        do { try service.register() } catch { state = .failed(error.localizedDescription) }
        if service.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
        refresh()
    }

    func disable() {
        try? service.unregister()
        refresh()
    }

    /// Tam Disk Erişimi listesine eklemek için servisi Finder'da gösterir ve ayarları açar.
    func showForFullDisk() {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: Self.bundlePath)])
        FullDisk.openSettings()
    }

    /// "Bu programı tanıyorum": koruma servisi artık engellemez.
    func allow(_ path: String) {
        var list = (try? String(contentsOfFile: Self.allowPath, encoding: .utf8))?.components(separatedBy: .newlines).filter { !$0.isEmpty } ?? []
        if !list.contains(path) { list.append(path) }
        try? FileManager.default.createDirectory(atPath: (Self.allowPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try? (list.joined(separator: "\n") + "\n").write(toFile: Self.allowPath, atomically: true, encoding: .utf8)
        chmod(Self.allowPath, 0o600)
        events.removeAll { $0.path == path }
    }

    private func refresh() {
        guard available else { state = .unavailable; return }
        switch service.status {
        case .notRegistered, .notFound: state = .off; return
        case .requiresApproval: state = .needsApproval; return
        default: break
        }
        guard let d = FileManager.default.contents(atPath: Self.statusPath),
              let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { state = .starting; return }
        let fresh = Date().timeIntervalSince1970 - (j["ts"] as? Double ?? 0) < 40
        ruleCount = j["rules"] as? Int ?? 0
        blocked = j["blocked"] as? Int ?? 0
        if let e = j["error"] as? String, j["active"] as? Bool != true {
            state = e == "fda" ? .needsFullDisk : .failed(e)
        } else {
            state = fresh && j["active"] as? Bool == true ? .active : .starting
        }
        readEvents()
    }

    private func readEvents() {
        guard let h = FileHandle(forReadingAtPath: Self.eventsPath) else { return }
        defer { try? h.close() }
        let size = (try? h.seekToEnd()) ?? 0
        if size < readOffset { readOffset = 0 }   // dosya baştan başladı
        guard size > readOffset else { return }
        try? h.seek(toOffset: readOffset)
        let data = h.readDataToEndOfFile()
        readOffset = size
        UserDefaults.standard.set(Int(readOffset), forKey: seenKey)
        for line in data.split(separator: 0x0a) {
            guard let j = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                  let path = j["path"] as? String else { continue }
            let ev = GuardEvent(path: path, rule: j["rule"] as? String ?? "", name: j["name"] as? String ?? "",
                                parent: j["parent"] as? String ?? "", date: Date(timeIntervalSince1970: j["ts"] as? Double ?? 0))
            events.insert(ev, at: 0)
            ThreatCenter.shared.report(Threat(
                id: "guard.\(path).\(Int(ev.date.timeIntervalSince1970))", risk: .high,
                title: L("guard.blockedTitle", ev.name), detail: PathUtil.abbreviate(path),
                iconKey: PathUtil.appBundle(path) ?? path, section: .scan, focus: .download(path)))
            // Tarama ekranında karantina seçeneğiyle görünsün.
            MalwareScanner.shared.add([Detection(path: path, rule: ev.rule, name: ev.name, date: ev.date,
                                                 launchItems: Targets.launchItemPrograms().filter { $0.program == path }.map(\.plist))],
                                       notify: false)
        }
        if events.count > 50 { events.removeLast(events.count - 50) }
    }
}

struct GuardEvent: Identifiable, Equatable {
    var id: String { path + "\(date.timeIntervalSince1970)" }
    let path: String
    let rule: String
    let name: String
    let parent: String
    let date: Date
}
