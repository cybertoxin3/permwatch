import AppKit
import Foundation
import Security
import ServiceManagement

/// Yönetici modu yardımcısının (permwatch-root) yazdığı veri.
struct RootData {
    var ts: Date
    var lsof: String
    var btm: String
    var cron: String
    var profiles: String
    var procs: [Int32: (args: [String], dyld: [String])]
    var captureActive = false
    var captureDevice: String?
    var captureError: String?
    var captureSkipped = 0
    var capturePktapError: String?

    var fresh: Bool { Date().timeIntervalSince(ts) < 20 }
}

/// Yönetici modunu başlatır ve yardımcının çıktısını okur.
@MainActor
final class RootBridge: ObservableObject {
    static let shared = RootBridge()
    static let prefKey = "rootMode"
    nonisolated static let outPath = "/Library/Application Support/permwatch/root.json"
    nonisolated static let packetsPath = "/Library/Application Support/permwatch/packets.jsonl"
    nonisolated static let pcapPath = "/Library/Application Support/permwatch/capture.pcap"

    @Published private(set) var data: RootData?
    @Published private(set) var lastError: String?
    @Published private(set) var starting = false

    private var timer: Timer?
    private var heartbeat: Timer?
    private var approvalWatch: Timer?
    @Published private(set) var waitingApproval = false

    nonisolated static let daemonPlist = "com.yusuf.permwatch.root.plist"
    var service: SMAppService { SMAppService.daemon(plistName: Self.daemonPlist) }
    /// Kalıcı servis kullanılabilir mi (geçerli Developer ID imzası ve paket içinde servis tanımı).
    var serviceAvailable: Bool {
        Self.ownTeamID() != nil &&
            FileManager.default.fileExists(atPath: Bundle.main.bundlePath + "/Contents/Library/LaunchDaemons/" + Self.daemonPlist)
    }
    static let aliveURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/permwatch/alive")

    var active: Bool { data?.fresh == true }
    var enabledPreference: Bool { UserDefaults.standard.bool(forKey: Self.prefKey) }

    private init() {
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.read() }
        }
        read()
        if enabledPreference { startHeartbeat() }
    }

    /// Servis modunda yardımcı yalnızca bu dosya tazeyken (permwatch açıkken) çalışır.
    private func startHeartbeat() {
        guard heartbeat == nil else { return }
        let beat = {
            let url = RootBridge.aliveURL
            try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: url.path) {
                try? FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: url.path)
            } else {
                FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
        }
        beat()
        heartbeat = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in beat() }
    }

    private func stopHeartbeat() {
        heartbeat?.invalidate(); heartbeat = nil
        try? FileManager.default.removeItem(at: Self.aliveURL)
    }

    /// Kalıcı servisi kaydeder; ilk seferde macOS Sistem Ayarları'nda onay ister.
    private func enableService() {
        lastError = nil
        startHeartbeat()
        UserDefaults.standard.set(true, forKey: Self.prefKey)
        switch service.status {
        case .enabled:
            waitingApproval = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { self.read() }
            return
        case .requiresApproval:
            break
        default:
            do { try service.register() } catch {
                if service.status != .requiresApproval {
                    lastError = error.localizedDescription
                    return
                }
            }
        }
        if service.status == .requiresApproval {
            waitingApproval = true
            SMAppService.openSystemSettingsLoginItems()
            approvalWatch?.invalidate()
            approvalWatch = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] t in
                MainActor.assumeIsolated {
                    guard let self else { t.invalidate(); return }
                    if self.service.status == .enabled { self.waitingApproval = false; t.invalidate(); self.read() }
                }
            }
        }
    }

    /// Açılışta: kullanıcı modu daha önce açtıysa ve yardımcı çalışmıyorsa yeniden ister.
    func resumeIfNeeded() {
        // Geliştirme anlık görüntüsü sırasında şifre sorma.
        if Snapshot.target != nil || Snapshot.section != nil { return }
        guard enabledPreference else { return }
        if serviceAvailable {
            // Kayıtlı servis: şifre sorulmaz; yalnızca "buradayım" sinyali.
            if service.status == .enabled { startHeartbeat() } else { enableService() }
            return
        }
        if !active { enable() }
    }

    nonisolated static let installedHelper = "/Library/PrivilegedHelperTools/com.yusuf.permwatch.root"
    nonisolated static let helperIdentifier = "com.yusuf.permwatch.root"

    /// Çalışan permwatch'ın geçerli imzasındaki Team ID (geçici imzalı derlemelerde nil).
    nonisolated static func ownTeamID() -> String? {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me,
              SecCodeCheckValidity(me, [], nil) == errSecSuccess else { return nil }
        var st: SecStaticCode?
        guard SecCodeCopyStaticCode(me, [], &st) == errSecSuccess, let st else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(st, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any] else { return nil }
        let team = d[kSecCodeInfoTeamIdentifier as String] as? String
        return team.flatMap { $0.allSatisfy { $0.isLetter || $0.isNumber } ? $0 : nil }
    }

    /// Yardımcının taşıması gereken imza: aynı geliştirici (Team ID) ve yardımcının kimliği.
    nonisolated static func helperRequirement(team: String) -> String {
        "identifier \"\(helperIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
    }

    /// macOS'un yönetici şifresi penceresiyle yardımcıyı root olarak başlatır.
    ///
    /// Güvenlik: yardımcı uygulama paketinin içinden doğrudan çalıştırılmaz (paket kullanıcının
    /// yazabildiği bir yerdeyse başka bir program onu değiştirip root olabilirdi). Root olarak
    /// root'a ait /Library/PrivilegedHelperTools'a kopyalanır, kopyanın imzası root olarak
    /// doğrulanır ve yalnızca doğrulama geçerse o kopya çalıştırılır.
    func enable() {
        guard !starting else { return }
        if serviceAvailable { enableService(); return }
        guard let helper = Bundle.main.path(forAuxiliaryExecutable: "permwatch-root") else {
            lastError = "permwatch-root"
            return
        }
        guard let team = Self.ownTeamID() else {
            lastError = L("settings.rootUnsigned")
            return
        }
        // Şifre sormadan önce de denetle (bozuk/değiştirilmiş paket için anlaşılır hata).
        var st: SecStaticCode?
        var req: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: helper) as CFURL, [], &st) == errSecSuccess, let st,
              SecRequirementCreateWithString(Self.helperRequirement(team: team) as CFString, [], &req) == errSecSuccess,
              SecStaticCodeCheckValidity(st, SecCSFlags(rawValue: kSecCSStrictValidate), req) == errSecSuccess else {
            lastError = L("settings.rootBadSignature")
            return
        }
        starting = true
        lastError = nil
        let pid = ProcessInfo.processInfo.processIdentifier
        func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let dst = Self.installedHelper
        let cmd = [
            "set -e",
            "/bin/mkdir -p /Library/PrivilegedHelperTools",
            "/usr/sbin/chown root:wheel /Library/PrivilegedHelperTools",
            "/bin/chmod 755 /Library/PrivilegedHelperTools",
            "/bin/rm -f \(q(dst))",
            "/usr/bin/ditto \(q(helper)) \(q(dst))",
            "/usr/sbin/chown root:wheel \(q(dst))",
            "/bin/chmod 755 \(q(dst))",
            "/usr/bin/codesign --verify --strict -R=\(q(Self.helperRequirement(team: team))) \(q(dst)) || { /bin/rm -f \(q(dst)); exit 41; }",
            "\(q(dst)) \(pid) > /dev/null 2>&1 &",
        ].joined(separator: "; ")
        let script = "do shell script \"\(cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges with prompt \"\(L("settings.rootPrompt"))\""
        DispatchQueue.global(qos: .userInitiated).async {
            var err: NSDictionary?
            NSAppleScript(source: script)?.executeAndReturnError(&err)
            let code = (err?[NSAppleScript.errorNumber] as? Int) ?? 0
            let msg: String? = err == nil ? nil
                : code == -128 ? L("settings.rootCancelled")
                : code == 41 ? L("settings.rootBadSignature")
                : (err?[NSAppleScript.errorMessage] as? String) ?? "\(code)"
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
        stopHeartbeat()
        approvalWatch?.invalidate(); waitingApproval = false
        if serviceAvailable, service.status != .notRegistered { try? service.unregister() }
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
        var r = RootData(ts: Date(timeIntervalSince1970: ts), lsof: j["lsof"] as? String ?? "",
                         btm: j["btm"] as? String ?? "", cron: j["cron"] as? String ?? "",
                         profiles: j["profiles"] as? String ?? "", procs: procs)
        if let c = j["capture"] as? [String: Any] {
            r.captureActive = c["active"] as? Bool ?? false
            r.captureDevice = c["device"] as? String
            r.captureError = c["error"] as? String
            r.captureSkipped = c["skipped"] as? Int ?? 0
            r.capturePktapError = c["pktapError"] as? String
        }
        return r
    }
}
