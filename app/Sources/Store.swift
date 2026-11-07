import AppKit
import Foundation
import UserNotifications

@MainActor
final class Store: ObservableObject {
    enum Source: Equatable {
        case none
        case demo
        case file(URL)
    }

    @Published private(set) var items: [Item] = []
    @Published private(set) var apps: [AppSummary] = []
    @Published private(set) var source: Source = .none
    @Published private(set) var badLines = 0
    @Published private(set) var trusted: Set<String>

    private var raw: [RawEvent] = []
    private var tail: DispatchSourceFileSystemObject?
    private var tailHandle: FileHandle?
    private var tailBuffer = Data()

    private static let trustedKey = "trustedApps"

    init() {
        trusted = Set(UserDefaults.standard.stringArray(forKey: Self.trustedKey) ?? [])
        loadDemo()
    }

    // MARK: Kaynaklar

    func loadDemo() {
        stopTail()
        guard let url = Bundle.main.url(forResource: "sample-events", withExtension: "jsonl"),
              let data = try? Data(contentsOf: url) else { return }
        let r = JSONL.decode(data)
        raw = r.events
        badLines = r.bad
        source = .demo
        reanalyze()
    }

    func open(_ url: URL) {
        stopTail()
        guard let h = try? FileHandle(forReadingFrom: url) else { return }
        let data = h.readDataToEndOfFile()
        let r = JSONL.decode(data)
        raw = r.events
        badLines = r.bad
        source = .file(url)
        reanalyze()
        startTail(handle: h)
    }

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = L("open.message")
        if panel.runModal() == .OK, let url = panel.url { open(url) }
    }

    // MARK: Canlı okuma

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
        let before = Set(items.filter { $0.risk == .high }.map(\.id))
        raw.append(contentsOf: r.events)
        badLines += r.bad
        reanalyze()
        for it in items where it.risk == .high && !before.contains(it.id) { notify(it) }
    }

    // MARK: Analiz

    private func reanalyze() {
        let a = Analyzer.run(raw, trusted: trusted)
        items = a.items
        apps = a.apps
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

    /// Kayıttaki son olaydan geriye 24 saatte olan izin değişiklikleri.
    var recentPermissionChanges: Int {
        guard let last = lastEvent else { return 0 }
        return items.filter { $0.kind == .tcc && last.timeIntervalSince($0.date) <= 86_400 }.count
    }

    var loginItemCount: Int { apps.filter { $0.loginItem != nil }.count }

    // MARK: Eylemler

    func toggleTrust(_ key: String) {
        if trusted.contains(key) { trusted.remove(key) } else { trusted.insert(key) }
        UserDefaults.standard.set(Array(trusted), forKey: Self.trustedKey)
        reanalyze()
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
            DispatchQueue.main.async { completion(err == nil) }
        }
    }

    // MARK: Bildirim

    func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private func notify(_ it: Item) {
        let c = UNMutableNotificationContent()
        c.title = it.alertHeader
        c.body = "\(it.title)\n" + it.rules.map(\.text).joined(separator: "\n")
        c.sound = .default
        let req = UNNotificationRequest(identifier: "pw-\(it.id)", content: c, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }
}

extension FileManager {
    func exists(_ p: String?) -> Bool { p.map { fileExists(atPath: $0) } ?? false }
}
