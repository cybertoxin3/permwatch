import AppKit
import SwiftUI

/// Kullanılmayan uygulamada duran hassas izin.
struct UnusedPermission: Identifiable {
    var id: String { key }
    let key: String
    let name: String
    let services: [String]
    let days: Int?        // nil: uygulama artık diskte yok
}

/// Öneriler: bütün izleyicilerin bulgularını sade dille açıklar ve tek tıkla düzeltme sunar.
@MainActor
final class Advisor: ObservableObject {
    @Published private(set) var unused: [UnusedPermission] = []
    static let sensitive: Set<String> = ["kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServiceScreenCapture",
                                         "kTCCServiceAccessibility", "kTCCServiceSystemPolicyAllFiles",
                                         "kTCCServiceListenEvent", "kTCCServicePostEvent"]
    nonisolated static let unusedDays = 90

    /// Başarıyla kaldırılan öneriyi listeden çıkar (yeniden tarama bitene kadar geri gelmesin).
    func drop(_ key: String) { unused.removeAll { $0.key == key } }

    func refresh(apps: [AppSummary]) {
        let input = apps.compactMap { a -> (String, String, [String])? in
            let s = a.services.filter(Self.sensitive.contains)
            // Başlangıçta açılan uygulamalar "açılmasa" da her gün çalışır: önerme.
            return s.isEmpty || a.loginItem != nil ? nil : (a.key, a.name, s)
        }
        Task.detached(priority: .utility) {
            let running = Advisor.runningPaths()
            var out: [UnusedPermission] = []
            for (key, name, services) in input {
                let path: String?
                if key.hasPrefix("/") { path = key }
                else if key.hasPrefix("bundle:") { path = await MainActor.run { Signing.appPath(bundleID: String(key.dropFirst(7))) } }
                else { path = nil }
                guard let path else {
                    if key.hasPrefix("bundle:") { out.append(UnusedPermission(key: key, name: name, services: services, days: nil)) }
                    continue
                }
                guard FileManager.default.fileExists(atPath: path) else {
                    out.append(UnusedPermission(key: key, name: name, services: services, days: nil)); continue
                }
                // Sistem bileşenlerini önerme.
                if path.hasPrefix("/System/") || path.hasPrefix("/usr/") { continue }
                // Şu an çalışıyorsa (kendisi ya da paketindeki bir yardımcı) kullanılıyordur.
                if running.contains(where: { $0 == path || $0.hasPrefix(path + "/") }) { continue }
                // Arka planda çalışan araçlar (menü çubuğu, yardımcılar) Spotlight'ta "açıldı" sayılmaz.
                if Advisor.isBackgroundCapable(path) { continue }
                guard let item = MDItemCreate(kCFAllocatorDefault, path as CFString),
                      let used = MDItemCopyAttribute(item, kMDItemLastUsedDate) as? Date else { continue }
                let days = Int(Date().timeIntervalSince(used) / 86_400)
                if days >= Advisor.unusedDays { out.append(UnusedPermission(key: key, name: name, services: services, days: days)) }
            }
            let result = out.sorted { ($0.days ?? .max) > ($1.days ?? .max) }
            await MainActor.run { self.unused = result }
        }
    }
}

extension Advisor {
    /// Çalışan bütün süreçlerin dosya yolları.
    nonisolated static func runningPaths() -> [String] {
        let n = proc_listallpids(nil, 0)
        var pids = [Int32](repeating: 0, count: Int(max(n, 0)) + 64)
        let got = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size)))
        var buf = [CChar](repeating: 0, count: 4096)
        return pids.prefix(max(0, got)).compactMap { pid in
            guard pid > 0, proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return nil }
            return String(cString: buf)
        }
    }

    /// Kullanıcı açmadan arka planda çalışabilen uygulama mı (LSUIElement, LSBackgroundOnly,
    /// paket içi oturum açma öğesi ya da launchd servisi)?
    nonisolated static func isBackgroundCapable(_ app: String) -> Bool {
        let info = NSDictionary(contentsOfFile: app + "/Contents/Info.plist")
        if (info?["LSUIElement"] as? Bool) == true || (info?["LSUIElement"] as? String) == "1" { return true }
        if (info?["LSBackgroundOnly"] as? Bool) == true { return true }
        let fm = FileManager.default
        for sub in ["Contents/Library/LoginItems", "Contents/Library/LaunchAgents", "Contents/Library/LaunchDaemons",
                    "Contents/Library/LaunchServices", "Contents/Library/SystemExtensions"] {
            if let c = try? fm.contentsOfDirectory(atPath: app + "/" + sub), !c.isEmpty { return true }
        }
        return false
    }
}

struct AdviceItem: Identifiable {
    let id: String
    let verdict: Explanation.Verdict
    let icon: String
    let title: String
    let body: String
    var iconKey: String? = nil
    var primary: (title: String, run: () -> Void)? = nil
    var secondary: (title: String, run: () -> Void)? = nil
    var category: String? = nil
}

struct AdviceView: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var posture: SecurityPosture
    @EnvironmentObject var downloads: DownloadGuard
    @EnvironmentObject var network: NetworkMonitor
    @EnvironmentObject var monitor: ProcessMonitor
    @EnvironmentObject var packets: PacketMonitor
    @EnvironmentObject var advisor: Advisor
    @EnvironmentObject var center: ThreatCenter
    @EnvironmentObject var scanner: MalwareScanner
    @EnvironmentObject var checks: SecurityChecks
    @State private var done: Set<String> = []
    @State private var message: String?
    @State private var confirm: AdviceItem?

    var body: some View {
        let list = (items + checkItems).filter { !done.contains($0.id) }
        let order: [Explanation.Verdict] = [.danger, .caution, .info, .ok]
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header(list)
                if let m = message ?? checks.message {
                    Text(m).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                if list.isEmpty && checks.lastRun != nil {
                    ContentUnavailableView(L("ov.good"), systemImage: "checkmark.seal.fill", description: Text(L("ov.goodBody")))
                        .frame(maxWidth: .infinity)
                }
                ForEach(order, id: \.self) { v in
                    let group = list.filter { $0.verdict == v }
                    if !group.isEmpty {
                        Text(v.label.uppercased(with: .current)).font(.system(size: 11, weight: .bold)).foregroundStyle(v.color)
                            .padding(.top, 6)
                        ForEach(group) { card($0) }
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: 860, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(L("nav.overview"))
        .confirmationDialog(confirm?.title ?? "", isPresented: Binding(get: { confirm != nil }, set: { if !$0 { confirm = nil } })) {
            Button(L("adv.revoke"), role: .destructive) { confirm?.primary?.run(); confirm = nil }
            Button(L("confirm.cancel"), role: .cancel) { confirm = nil }
        } message: {
            Text(L("adv.revokeConfirm"))
        }
        .onChange(of: store.apps.count) { advisor.refresh(apps: store.apps) }
        .onAppear {
            advisor.refresh(apps: store.apps); posture.refresh()
            if checks.lastRun == nil { runChecks() }
            if Snapshot.section == "advice" {
                DispatchQueue.main.asyncAfter(deadline: .now() + 8) { advisor.refresh(apps: store.apps) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 16) {
                    for i in (items + checkItems) { FileHandle.standardError.write(Data("öneri: [\(i.verdict.label)] \(i.title) — \(i.body.prefix(110))\n".utf8)) }
                    NSApp.terminate(nil)
                }
            }
        }
    }

    private func runChecks() {
        checks.run(apps: store.apps, rootProfiles: RootBridge.shared.active ? RootBridge.shared.data?.profiles : nil)
    }

    private func header(_ list: [AdviceItem]) -> some View {
        let urgent = list.filter { $0.verdict == .danger }.count
        let review = list.filter { $0.verdict == .caution }.count
        let busy = checks.running || scanner.running
        let color: Color = urgent > 0 ? .red : (review > 0 ? .orange : .green)
        return HStack(spacing: 18) {
            ZStack {
                Circle().fill(color.opacity(0.15)).frame(width: 74, height: 74)
                Image(systemName: urgent > 0 ? "exclamationmark.shield.fill" : (review > 0 ? "shield.lefthalf.filled" : "checkmark.shield.fill"))
                    .font(.system(size: 34)).foregroundStyle(color)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(urgent + review == 0 ? L("ov.good") : L("ov.issues", urgent.formatted(), review.formatted()))
                    .font(.system(size: 21, weight: .bold))
                Text(checks.lastRun.map { L("ov.lastCheck", Fmt.relative($0)) } ?? L("ov.never"))
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer()
            if busy {
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text(L("ov.checking")).font(.system(size: 12)) }
            } else {
                Button { runChecks(); scanner.start(.quick) } label: { Label(L("ov.check"), systemImage: "checkmark.shield") }
                    .buttonStyle(.borderedProminent).controlSize(.large)
            }
        }
    }

    /// Kontrol bulgularını kartlara çevir.
    private var checkItems: [AdviceItem] {
        checks.findings.map { f in
            let icon: String = ["browser": "globe", "mitm": "lock.trianglebadge.exclamationmark", "remote": "display.2",
                                "spyware": "eye.trianglebadge.exclamationmark"][f.category.rawValue] ?? "exclamationmark.triangle"
            func act(_ i: Int) -> (String, () -> Void)? {
                guard i < f.fixes.count else { return nil }
                let fx = f.fixes[i]
                return (fx.title, { MainActor.assumeIsolated { checks.apply(fx.fix, store: store) { runChecks() } } })
            }
            return AdviceItem(id: "chk." + f.id, verdict: f.verdict, icon: icon, title: f.title,
                              body: f.body, iconKey: f.iconKey, primary: act(0), secondary: act(1), category: L("ov.cat." + f.category.rawValue))
        }
    }

    private func card(_ a: AdviceItem) -> some View {
        HStack(alignment: .top, spacing: 14) {
            if let k = a.iconKey {
                AppIcon(name: a.title, risk: .normal, key: k, size: 36)
            } else {
                Image(systemName: a.icon).font(.system(size: 24)).foregroundStyle(a.verdict.color).frame(width: 36)
            }
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(a.title).font(.system(size: 14, weight: .semibold))
                    Spacer()
                    if let c = a.category {
                        Text(c).font(.system(size: 10.5, weight: .medium)).foregroundStyle(.secondary)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 4))
                    }
                }
                Text(a.body).font(.system(size: 12.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    if let p = a.primary {
                        Button(p.title) { if a.id.hasPrefix("unused.") || a.id.hasPrefix("chk.spy.") { confirm = a } else { p.run() } }
                            .buttonStyle(.borderedProminent).tint(a.verdict.color)
                    }
                    if let s = a.secondary { Button(s.title) { s.run() } }
                    Button(L("adv.dismiss")) { done.insert(a.id) }.buttonStyle(.borderless).foregroundStyle(.secondary)
                }
                .controlSize(.small)
                .padding(.top, 2)
            }
        }
        .padding(16)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(a.verdict.color.opacity(0.35)))
    }

    private func go(_ s: SidebarItem) { center.navigate(section: s) }

    // MARK: Öneri listesi

    private var items: [AdviceItem] {
        var out: [AdviceItem] = []
        if store.needsFullDiskAccess || downloads.needsFullDisk {
            out.append(.init(id: "fda", verdict: .danger, icon: "lock.shield", title: L("fda.one.title"), body: L("fda.one.body"),
                             primary: (L("fda.open"), FullDisk.openSettings)))
        }
        for c in posture.checks where c.state == .off || c.state == .warn {
            out.append(.init(id: "posture.\(c.id)", verdict: c.id == "sip" || c.id == "gatekeeper" ? .danger : .caution,
                             icon: "shield.slash", title: L("adv.posture.title", c.title), body: L("adv.posture." + c.id),
                             primary: c.settingsURL.flatMap { URL(string: $0) }.map { u in (L("sec.fix"), { NSWorkspace.shared.open(u) }) }))
        }
        if !scanner.detections.isEmpty {
            out.append(.init(id: "malware", verdict: .danger, icon: "ladybug.fill",
                             title: L("scan.found", scanner.detections.count.formatted()),
                             body: scanner.detections.map { "\($0.name): \(PathUtil.abbreviate($0.path))" }.joined(separator: "\n"),
                             primary: (L("threat.review"), { go(.scan) })))
        } else if scanner.lastScan.map({ Date().timeIntervalSince($0) > 7 * 86_400 }) ?? true {
            out.append(.init(id: "malware.scan", verdict: .info, icon: "ladybug",
                             title: scanner.lastScan == nil ? L("scan.never") : L("scan.stale"), body: L("scan.adviceBody"),
                             primary: (L("scan.quick"), { go(.scan); scanner.start(.quick) })))
        }
        let high = store.items.filter { $0.risk == .high && !$0.trusted }.count
        if high > 0 {
            out.append(.init(id: "alerts", verdict: .danger, icon: "exclamationmark.triangle.fill",
                             title: L("adv.alerts.title", high.formatted()), body: L("adv.alerts.body"),
                             primary: (L("threat.review"), { go(.alerts) })))
        }
        if monitor.suspicious > 0 {
            out.append(.init(id: "procs", verdict: .caution, icon: "cpu", title: L("adv.procs.title", monitor.suspicious.formatted()),
                             body: L("adv.procs.body"), primary: (L("threat.review"), { go(.running) })))
        }
        if downloads.risky > 0 {
            out.append(.init(id: "downloads", verdict: .caution, icon: "arrow.down.circle",
                             title: L("adv.downloads.title", downloads.risky.formatted()), body: L("adv.downloads.body"),
                             primary: (L("threat.review"), { go(.downloads) })))
        }
        if network.risky > 0 {
            out.append(.init(id: "network", verdict: .caution, icon: "network", title: L("adv.network.title", network.risky.formatted()),
                             body: L("adv.network.body"), primary: (L("threat.review"), { go(.network) })))
        }
        // Paket yakalamadan: şifresiz parola ve izleyiciler
        let credApps = Set(packets.packets.filter { $0.flags?.contains("pkt.flag.cleartextCreds") == true }.map { $0.eproc ?? $0.proc ?? "?" })
        if !credApps.isEmpty {
            out.append(.init(id: "pkt.creds", verdict: .danger, icon: "key.fill",
                             title: L("pkt.threat.creds"), body: L("adv.creds.body", credApps.sorted().joined(separator: ", ")),
                             primary: (L("threat.review"), { go(.packets) })))
        }
        var trackerApps: [String: Set<String>] = [:]
        for p in packets.packets {
            if let t = Trackers.match(p.host ?? packets.names[p.dst]) { trackerApps[p.eproc ?? p.proc ?? "?", default: []].insert(t.company) }
        }
        if !trackerApps.isEmpty {
            let lines = trackerApps.sorted { $0.value.count > $1.value.count }.prefix(6)
                .map { "\($0.key): \($0.value.sorted().joined(separator: ", "))" }.joined(separator: "\n")
            out.append(.init(id: "pkt.trackers", verdict: .info, icon: "eye.trianglebadge.exclamationmark",
                             title: L("adv.trackers.title", trackerApps.count.formatted()), body: L("adv.trackers.body") + "\n\n" + lines,
                             primary: (L("threat.review"), { go(.packets) })))
        }
        // Kullanılmayan uygulamalarda duran izinler
        for u in advisor.unused.prefix(12) {
            let svc = u.services.map(Text10n.service).joined(separator: ", ")
            let body = u.days.map { L("adv.unused.body", $0.formatted(), svc) } ?? L("adv.gone.body", svc)
            out.append(.init(id: "unused.\(u.key)", verdict: u.days == nil ? .caution : .info, icon: "hand.raised.slash",
                             title: u.days == nil ? L("adv.gone.title", u.name) : L("adv.unused.title", u.name), body: body,
                             iconKey: u.key.hasPrefix("/") ? u.key : nil,
                             primary: (L("adv.revoke"), {
                                 let r = store.revoke(services: u.services, key: u.key)
                                 message = "\(u.name): " + r.message
                                 if r.ok { done.insert("unused.\(u.key)"); advisor.drop(u.key) }
                             })))
        }
        return out
    }
}
