import AppKit
import Foundation
import UserNotifications

@MainActor
final class Store: ObservableObject {
    enum Source: Equatable {
        case system     // bu Mac'in gerçek durumu (TCC.db + launchd)
        case demo
        case file(URL)
    }

    @Published private(set) var items: [Item] = []
    @Published private(set) var apps: [AppSummary] = []
    @Published private(set) var source: Source = .system
    @Published private(set) var badLines = 0
    @Published private(set) var trusted: Set<String>
    @Published private(set) var needsFullDiskAccess = false
    @Published private(set) var scanning = false
    @Published private(set) var lastScan: Date?

    private var raw: [RawEvent] = []
    private var tail: DispatchSourceFileSystemObject?
    private var tailHandle: FileHandle?
    private var tailBuffer = Data()
    private var timer: Timer?
    private var watchers: [DispatchSourceFileSystemObject] = []
    private var pendingScan: DispatchWorkItem?
    private var rescanRequested = false
    private(set) var scanCount = 0
    private var activeObserver: NSObjectProtocol?

    private static let trustedKey = "trustedApps"
    /// Asıl tetikleyici dosya izleyicileridir; zamanlayıcı yalnızca yedek.
    private static let fallbackInterval: TimeInterval = 60

    init() {
        trusted = Set(UserDefaults.standard.stringArray(forKey: Self.trustedKey) ?? [])
        // Tam Disk Erişimi sonradan verilirse, uygulamaya dönüldüğünde taramayı yenile.
        activeObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.source == .system else { return }
                self.scanSystem()
            }
        }
        if ProcessInfo.processInfo.environment["PERMWATCH_DEMO"] != nil {
            loadDemo()
        } else {
            useSystem()
        }
    }

    // MARK: Kaynaklar

    func useSystem() {
        stopTail()
        source = .system
        badLines = 0
        scanSystem()
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: Self.fallbackInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.scanSystem() }
        }
    }

    func loadDemo() {
        stopTail()
        stopTimer()
        guard let url = Bundle.main.url(forResource: "sample-events", withExtension: "jsonl"),
              let data = try? Data(contentsOf: url) else { return }
        let r = JSONL.decode(data)
        raw = r.events
        badLines = r.bad
        source = .demo
        needsFullDiskAccess = false
        reanalyze(notifyNew: false)
    }

    func open(_ url: URL) {
        stopTail()
        stopTimer()
        guard let h = try? FileHandle(forReadingFrom: url) else { return }
        let r = JSONL.decode(h.readDataToEndOfFile())
        raw = r.events
        badLines = r.bad
        source = .file(url)
        needsFullDiskAccess = false
        reanalyze(notifyNew: false)
        startTail(handle: h)
    }

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = L("open.message")
        if panel.runModal() == .OK, let url = panel.url { open(url) }
    }

    private func stopTimer() {
        timer?.invalidate()
        timer = nil
        watchers.forEach { $0.cancel() }
        watchers = []
        pendingScan?.cancel()
    }

    // MARK: Canlı izleme

    /// TCC veritabanlarını ve başlangıç klasörlerini dosya sistemi olaylarıyla dinler.
    /// Dosya yeniden oluşturulabileceği için her taramadan sonra yeniden kurulur.
    private func armWatchers() {
        watchers.forEach { $0.cancel() }
        watchers = []
        var paths = [SystemScanner.userTCC, SystemScanner.systemTCC] + SystemScanner.launchDirs
        if let extra = ProcessInfo.processInfo.environment["PERMWATCH_WATCH_TEST"] { paths.append(extra) }
        for p in paths {
            let fd = Darwin.open(p, O_EVTONLY)
            guard fd >= 0 else { continue }
            let src = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd, eventMask: [.write, .extend, .delete, .rename, .attrib], queue: .main)
            src.setEventHandler { [weak self] in
                MainActor.assumeIsolated { self?.scheduleScan() }
            }
            src.setCancelHandler { Darwin.close(fd) }
            src.resume()
            watchers.append(src)
        }
    }

    /// Arka arkaya gelen değişiklikleri 1 saniyelik pencerede tek taramada birleştirir.
    private func scheduleScan() {
        pendingScan?.cancel()
        let w = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated { self?.scanSystem() }
        }
        pendingScan = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: w)
    }

    // MARK: Sistem taraması

    private struct State: Codable {
        var snapshot: SystemScanner.Snapshot
        var removed: [RawEvent]
    }

    private static var stateURL: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("permwatch", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("state.json")
    }

    func scanSystem() {
        guard source == .system else { return }
        if scanning { rescanRequested = true; return }
        scanning = true
        let url = Self.stateURL
        Task.detached(priority: .utility) {
            let prev = (try? Data(contentsOf: url)).flatMap { try? JSONDecoder().decode(State.self, from: $0) }
            let r = SystemScanner.scan(previous: prev?.snapshot, removedLog: prev?.removed ?? [])
            let removed = r.events.filter { $0.update == "delete" || $0.event == "btm_launch_item_remove" }
            // TCC okunamadıysa izin anlık görüntüsünü ezme (yoksa her şey "kaldırıldı" görünür).
            var snap = r.snapshot
            if !r.tccReadable, let p = prev?.snapshot { snap.tcc = p.tcc }
            if let data = try? JSONEncoder().encode(State(snapshot: snap, removed: Array(removed.suffix(500)))) {
                try? data.write(to: url, options: .atomic)
            }
            await MainActor.run {
                guard self.source == .system else { self.scanning = false; return }
                let first = self.lastScan == nil
                self.raw = r.events
                self.needsFullDiskAccess = !r.tccReadable
                self.lastScan = Date()
                self.scanning = false
                self.scanCount += 1
                self.reanalyze(notifyNew: !first)
                self.armWatchers()
                if self.rescanRequested {
                    self.rescanRequested = false
                    self.scheduleScan()
                }
            }
        }
    }

    func openFullDiskAccessSettings() {
        if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(u)
        }
    }

    // MARK: Canlı dosya okuma

    private func startTail(handle: FileHandle) {
        tailHandle = handle
        let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: handle.fileDescriptor,
                                                            eventMask: [.extend, .write], queue: .main)
        src.setEventHandler { [weak self] in
            MainActor.assumeIsolated { self?.readAppended() }
        }
        src.resume()
        tail = src
    }

    private func stopTail() {
        tail?.cancel()
        tail = nil
        try? tailHandle?.close()
        tailHandle = nil
        tailBuffer = Data()
    }

    private func readAppended() {
        guard let h = tailHandle else { return }
        tailBuffer.append(h.readDataToEndOfFile())
        guard let lastNL = tailBuffer.lastIndex(of: UInt8(ascii: "\n")) else { return }
        let complete = tailBuffer[...lastNL]
        tailBuffer = Data(tailBuffer[tailBuffer.index(after: lastNL)...])
        let r = JSONL.decode(Data(complete))
        guard !r.events.isEmpty else { return }
        raw.append(contentsOf: r.events)
        badLines += r.bad
        reanalyze(notifyNew: true)
    }

    // MARK: Analiz

    private func reanalyze(notifyNew: Bool) {
        let before = Set(items.filter { $0.risk == .high }.map(\.id))
        let a = Analyzer.run(raw, trusted: trusted)
        items = a.items
        apps = a.apps
        if notifyNew {
            for it in items where it.risk == .high && !before.contains(it.id) { notify(it) }
        }
    }

    func item(_ id: Int?) -> Item? {
        guard let id else { return nil }
        return items.first { $0.id == id }
    }

    func chain(for key: String) -> [Item] {
        items.filter { $0.appKey == key }.sorted { $0.date < $1.date }
    }

    var lastEvent: Date? { items.map(\.date).max() }

    var openAlerts: Int { items.filter { $0.risk >= .caution }.count }

    /// Son 24 saatte olan izin değişiklikleri (demo/kayıt dosyasında kayıttaki son olaya göre).
    var recentPermissionChanges: Int {
        let ref = source == .system ? Date() : (lastEvent ?? Date())
        return items.filter { $0.kind == .tcc && ref.timeIntervalSince($0.date) <= 86_400 }.count
    }

    var loginItemCount: Int { apps.filter { $0.loginItem != nil }.count }

    // MARK: Eylemler

    func toggleTrust(_ key: String) {
        if trusted.contains(key) { trusted.remove(key) } else { trusted.insert(key) }
        UserDefaults.standard.set(Array(trusted), forKey: Self.trustedKey)
        reanalyze(notifyNew: false)
    }

    func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    func openSettings(service: String) {
        if let u = Text10n.settingsURL(service: service) { NSWorkspace.shared.open(u) }
    }

    /// LaunchAgent plist'ini Çöp Sepeti'ne taşır (geri alınabilir).
    func trash(_ path: String, completion: @escaping (Bool) -> Void) {
        NSWorkspace.shared.recycle([URL(fileURLWithPath: path)]) { _, err in
            DispatchQueue.main.async {
                completion(err == nil)
                if err == nil { self.scanSystem() }
            }
        }
    }

    // MARK: Kaldırma ve izinler

    func bundleID(forKey key: String) -> String? {
        if key.hasPrefix("bundle:") { return String(key.dropFirst(7)) }
        return Uninstaller.bundleID(key)
    }

    /// Uygulama paketinin içindeki bir programı çalıştıran başlangıç öğeleri.
    func launchPlists(forApp appPath: String) -> [String] {
        raw.filter { $0.event == "btm_launch_item_add" && ($0.executable_path ?? "").hasPrefix(appPath + "/") }
            .compactMap { PathUtil.fromURL($0.item?.url) }
    }

    /// TCC iznini sıfırlar (tccutil). service nil ise uygulamanın bütün izinleri.
    /// İzin VERMEK mümkün değildir; macOS buna hiçbir uygulamaya izin vermez.
    func resetPermission(service: String?, key: String) -> String {
        guard let id = bundleID(forKey: key) else { return L("reset.noBundle") }
        let svc = service.map { $0.replacingOccurrences(of: "kTCCService", with: "") } ?? "All"
        let (code, out) = Shell.run("/usr/bin/tccutil", ["reset", svc, id])
        scanSystem()
        return code == 0 ? L("reset.done") : L("reset.failed", out)
    }

    func uninstall(_ items: [Uninstaller.Candidate], key: String, resetPermissions: Bool,
                   completion: @escaping (String) -> Void) {
        Uninstaller.run(items, bundleID: bundleID(forKey: key), resetPermissions: resetPermissions) { failed in
            self.scanSystem()
            completion(failed.isEmpty ? L("uninstall.done")
                                      : L("uninstall.failed", failed.map(PathUtil.abbreviate).joined(separator: ", ")))
        }
    }

    // MARK: Bildirim

    func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private func notify(_ it: Item) {
        let c = UNMutableNotificationContent()
        c.title = "\(it.risk.label): \(it.alertHeader)"
        c.body = "\(it.title)\n" + it.rules.map(\.text).joined(separator: "\n")
        c.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "pw-\(it.id)", content: c, trigger: nil))
    }
}

extension FileManager {
    func exists(_ p: String?) -> Bool { p.map { fileExists(atPath: $0) } ?? false }
}
