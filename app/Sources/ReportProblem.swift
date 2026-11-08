import AppKit
import SwiftUI

/// "Bize bildir": kullanıcının kendi e-posta uygulamasında, sorunu hızlı anlamaya yetecek teknik
/// bilgilerle doldurulmuş bir e-posta açar. Hiçbir şey kendiliğinden gönderilmez; kullanıcı neyin
/// gideceğini önce ekranda görür. Kullanıcı adı, bilgisayar adı, seri numarası ve dosya yolları eklenmez.
enum ProblemReport {
    static let address = "yusuf.itmo@mail.ru"

    static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
        return String(cString: buf)
    }

    static func sysctlInt(_ name: String) -> Int64? {
        var v: Int64 = 0
        var size = MemoryLayout<Int64>.size
        return sysctlbyname(name, &v, &size, nil, 0) == 0 ? v : nil
    }

    /// Mac'in pazarlama adı ve çip (ör. "MacBook Air", "Apple M1"). Seri numarası alınmaz.
    static func hardware() -> (model: String?, chip: String?) {
        let out = Shell.run("/usr/sbin/system_profiler", ["SPHardwareDataType"]).1
        func field(_ k: String) -> String? {
            out.split(separator: "\n").first { $0.trimmingCharacters(in: .whitespaces).hasPrefix(k + ":") }
                .map { String($0.split(separator: ":", maxSplits: 1)[1]).trimmingCharacters(in: .whitespaces) }
        }
        return (field("Model Name"), field("Chip") ?? field("Processor Name"))
    }

    /// E-postaya eklenecek bilgiler (ekranda da aynen gösterilir).
    /// Yavaş kısımlar (system_profiler, güvenlik durumu) arka planda; gerisi ana iş parçacığında.
    @MainActor
    static func diagnostics(hw: (model: String?, chip: String?), posture: [PostureCheck]) -> String {
        let b = Bundle.main
        let ver = b.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = b.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let mem = sysctlInt("hw.memsize").map { "\($0 >> 30) GB" } ?? "?"
        let rosetta = sysctlInt("sysctl.proc_translated") == 1
        let free = (try? URL(fileURLWithPath: "/").resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]))?
            .volumeAvailableCapacityForImportantUsage.map { "\($0 >> 30) GB" } ?? "?"
        let sig = Signing.classify(path: b.bundlePath).signature
        let root = RootBridge.shared
        let rt = RealtimeGuard.shared
        let intel = ThreatIntel.shared
        let scanner = MalwareScanner.shared
        let gs = GuardService.shared
        let updates = Bundle.main.infoDictionary?["SUPublicEDKey"] != nil ? "Sparkle" : "GitHub"
        func onOff(_ v: Bool) -> String { v ? "on" : "off" }

        var lines: [String] = []
        lines.append("— permwatch —")
        lines.append("Version: \(ver) (\(build)) · signature: \(sig) · updates: \(updates)")
        lines.append("Language: \(Locale.preferredLanguages.first ?? "?") · region: \(Locale.current.region?.identifier ?? "?")")
        lines.append("Mode: \(UserDefaults.standard.bool(forKey: Sidebar.advancedKey) ? "advanced" : "simple")")
        lines.append("")
        lines.append("— Mac —")
        lines.append("Model: \(hw.model ?? "?") (\(sysctlString("hw.model") ?? "?"))")
        lines.append("Chip: \(hw.chip ?? "?") · arch: \(sysctlString("hw.machine") ?? "?")\(rosetta ? " · Rosetta" : "")")
        lines.append("Memory: \(mem) · free disk: \(free)")
        lines.append("macOS: \(os.majorVersion).\(os.minorVersion).\(os.patchVersion) (\(sysctlString("kern.osversion") ?? "?"))")
        lines.append("Uptime: \(Int(ProcessInfo.processInfo.systemUptime / 3600)) h")
        for c in posture {
            let s: String
            switch c.state { case .on: s = "on"; case .off: s = "off"; case .warn: s = "warning"; case .unknown: s = "unknown" }
            lines.append("\(c.id): \(s)")
        }
        lines.append("")
        lines.append("— Permissions —")
        lines.append("Full Disk Access: \(onOff(FullDisk.granted))")
        lines.append("Admin mode: preference \(onOff(root.enabledPreference)), helper \(root.active ? "running" : "not running")"
                     + (root.waitingApproval ? ", waiting for Login Items approval" : ""))
        if let e = root.lastError { lines.append("Admin mode error: \(e)") }
        lines.append("")
        lines.append("— Protection —")
        lines.append("Real-time: \(onOff(rt.enabled)), watching \(rt.watching.count) folders, \(rt.scannedCount) files scanned this session")
        lines.append("Ransomware protection: \(onOff(rt.ransomEnabled)), alerts: \(rt.ransomAlerts.count)")
        lines.append("Threat lists: \(onOff(intel.enabled)), \(intel.domainCount) domains, \(intel.ipCount) IPs, updated: "
                     + (intel.lastUpdate.map { ISO8601DateFormatter().string(from: $0) } ?? "never"))
        if let e = intel.error { lines.append("Threat list error: \(e)") }
        lines.append("Signatures: \(YaraEngine.shared.ruleCount) rules (Elastic \(YaraEngine.shared.extraCount)), XProtect \(scanner.signatureVersion ?? "?")")
        lines.append("Last scan: " + (scanner.lastScan.map { ISO8601DateFormatter().string(from: $0) } ?? "never")
                     + " · \(scanner.lastKind?.rawValue ?? "-") · \(scanner.lastScanned) files · detections: \(scanner.detections.count)")
        if let e = scanner.error { lines.append("Scan error: \(e)") }
        lines.append("Quarantine: \(QuarantineStore.shared.items.count) items")
        if gs.available { lines.append("Block before run: \(gs.state)") }
        lines.append("DNS watch: " + (root.data?.dnsActive == true ? "running" : "off") + (root.data?.dnsError.map { " (\($0))" } ?? ""))
        lines.append("Report created: \(ISO8601DateFormatter().string(from: Date()))")
        return lines.joined(separator: "\n")
    }

    static func subject(version: String) -> String { "permwatch \(version): " + L("report.subject") }

    /// Posta uygulamasında yeni ileti açar (Mail yoksa mailto: ile varsayılan uygulamada).
    static func compose(message: String, details: String) {
        let ver = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let body = (message.isEmpty ? L("report.placeholder") : message) + "\n\n\n" + details
        if let s = NSSharingService(named: .composeEmail), s.canPerform(withItems: [body]) {
            s.recipients = [address]
            s.subject = subject(version: ver)
            s.perform(withItems: [body])
            return
        }
        var c = URLComponents()
        c.scheme = "mailto"
        c.path = address
        c.queryItems = [URLQueryItem(name: "subject", value: subject(version: ver)), URLQueryItem(name: "body", value: body)]
        if let u = c.url { NSWorkspace.shared.open(u) }
    }
}

struct ReportProblemView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var message = ""
    @State private var details = ""
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(L("report.title")).font(.system(size: 18, weight: .bold))
            Text(L("report.lead", ProblemReport.address)).font(.system(size: 12.5)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextEditor(text: $message)
                .font(.system(size: 13))
                .frame(height: 110)
                .overlay(alignment: .topLeading) {
                    if message.isEmpty {
                        Text(L("report.placeholder")).foregroundStyle(.tertiary).padding(.horizontal, 5).padding(.vertical, 1).allowsHitTesting(false)
                    }
                }
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.secondary.opacity(0.3)))
            Text(L("report.detailsTitle")).font(.system(size: 12, weight: .semibold))
            ScrollView {
                Text(details.isEmpty ? L("report.collecting") : details)
                    .font(.system(size: 10.5, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: 170)
            .padding(8)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
            Text(L("report.privacy")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(copied ? L("report.copied") : L("report.copy")) {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(message + "\n\n" + details, forType: .string)
                    copied = true
                }
                Spacer()
                Button(L("confirm.cancel")) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(L("report.send")) { ProblemReport.compose(message: message, details: details); dismiss() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(details.isEmpty)
            }
        }
        .padding(22)
        .frame(width: 560)
        .task {
            // system_profiler birkaç saniye sürebilir: arayüzü bekletmeden topla.
            let (hw, posture) = await Task.detached { (ProblemReport.hardware(), SecurityPosture.evaluate()) }.value
            details = ProblemReport.diagnostics(hw: hw, posture: posture)
        }
    }
}

/// Yardım menüsündeki "Bize bildir…" (pencereyi açmak için openWindow gerekir).
struct ReportMenuButton: View {
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Button(L("report.menu")) { openWindow(id: "report"); NSApp.activate(ignoringOtherApps: true) }
    }
}
