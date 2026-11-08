import AppKit
import Foundation

/// Yönetici modu yardımcısının (permwatch-root) yazdığı veri.
struct RootData {
    var ts: Date
    var lsof: String
    var btm: String
    var cron: String
    var profiles: String
    var procs: [Int32: (args: [String], dyld: [String])]

    var fresh: Bool { Date().timeIntervalSince(ts) < 20 }
}

/// Yönetici modunu başlatır ve yardımcının çıktısını okur.
@MainActor
final class RootBridge: ObservableObject {
    static let shared = RootBridge()
    static let prefKey = "rootMode"
    nonisolated static let outPath = "/Library/Application Support/permwatch/root.json"

    @Published private(set) var data: RootData?
    @Published private(set) var lastError: String?
    @Published private(set) var starting = false

    private var timer: Timer?

    var active: Bool { data?.fresh == true }
    var enabledPreference: Bool { UserDefaults.standard.bool(forKey: Self.prefKey) }

    private init() {
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.read() }
        }
        read()
    }

    /// Açılışta: kullanıcı modu daha önce açtıysa ve yardımcı çalışmıyorsa yeniden ister.
    func resumeIfNeeded() {
        if enabledPreference && !active { enable() }
    }

    /// macOS'un yönetici şifresi penceresiyle yardımcıyı root olarak başlatır.
    func enable() {
        guard !starting else { return }
        guard let helper = Bundle.main.path(forAuxiliaryExecutable: "permwatch-root") else {
            lastError = "permwatch-root"
            return
        }
        starting = true
        lastError = nil
        let pid = ProcessInfo.processInfo.processIdentifier
        let quoted = "'" + helper.replacingOccurrences(of: "'", with: "'\\''") + "'"
        let cmd = "\(quoted) \(pid) > /dev/null 2>&1 &"
        let script = "do shell script \"\(cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges with prompt \"\(L("settings.rootPrompt"))\""
        DispatchQueue.global(qos: .userInitiated).async {
            var err: NSDictionary?
            NSAppleScript(source: script)?.executeAndReturnError(&err)
            let msg = err.map { ($0[NSAppleScript.errorMessage] as? String) ?? "\($0[NSAppleScript.errorNumber] ?? "?")" }
            DispatchQueue.main.async {
                self.starting = false
                if let msg {
                    self.lastError = msg
                } else {
                    UserDefaults.standard.set(true, forKey: Self.prefKey)
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.read() }
                }
            }
        }
    }

    /// Tercihi kapatır; çalışan yardımcı permwatch kapanınca durur, verisi artık kullanılmaz.
    func disable() {
        UserDefaults.standard.set(false, forKey: Self.prefKey)
        data = nil
    }

    private func read() {
        guard enabledPreference || data != nil else { return }
        Task.detached(priority: .utility) {
            let parsed = RootBridge.parse()
            await MainActor.run {
                if self.enabledPreference { self.data = parsed } else { self.data = nil }
            }
        }
    }

    nonisolated static func parse() -> RootData? {
        guard let d = FileManager.default.contents(atPath: outPath),
              let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let ts = j["ts"] as? Double else { return nil }
        var procs: [Int32: (args: [String], dyld: [String])] = [:]
        for (k, v) in (j["procs"] as? [String: [String: [String]]]) ?? [:] {
            if let pid = Int32(k) { procs[pid] = (v["args"] ?? [], v["dyld"] ?? []) }
        }
        return RootData(ts: Date(timeIntervalSince1970: ts), lsof: j["lsof"] as? String ?? "",
                        btm: j["btm"] as? String ?? "", cron: j["cron"] as? String ?? "",
                        profiles: j["profiles"] as? String ?? "", procs: procs)
    }
}
