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

    func refresh(apps: [AppSummary]) {
        let input = apps.compactMap { a -> (String, String, [String])? in
            let s = a.services.filter(Self.sensitive.contains)
            return s.isEmpty ? nil : (a.key, a.name, s)
        }
        Task.detached(priority: .utility) {
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

struct AdviceItem: Identifiable {
    let id: String
    let verdict: Explanation.Verdict
    let icon: String
    let title: String
    let body: String
    var iconKey: String? = nil
    var primary: (title: String, run: () -> Void)? = nil
    var secondary: (title: String, run: () -> Void)? = nil
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
    @State private var done: Set<String> = []
    @State private var message: String?

    var body: some View {
        let list = items.filter { !done.contains($0.id) }
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header(list)
                if let m = message {
                    Text(m).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                if list.isEmpty {
                    ContentUnavailableView(L("adv.allGood"), systemImage: "checkmark.seal.fill",
                                           description: Text(L("adv.allGoodBody")))
                        .frame(maxWidth: .infinity)
                }
                ForEach(list) { card($0) }
            }
            .padding(24)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(L("nav.advice"))
        .onAppear {
            advisor.refresh(apps: store.apps); posture.refresh()
            if Snapshot.section == "advice" {
                DispatchQueue.main.asyncAfter(deadline: .now() + 8) { advisor.refresh(apps: store.apps) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 14) {
                    FileHandle.standardError.write(Data("durum: apps=\(store.apps.count) checks=\(posture.checks.map { "\($0.id)=\($0.state)" }) unused=\(advisor.unused.count) items=\(store.items.count)\n".utf8))
                    for i in items { FileHandle.standardError.write(Data("öneri: [\(i.verdict.label)] \(i.title) — \(i.body.prefix(90))\n".utf8)) }
                    NSApp.terminate(nil)
                }
            }
        }
    }

    private func header(_ list: [AdviceItem]) -> some View {
        let urgent = list.filter { $0.verdict == .danger }.count
        return HStack(spacing: 16) {
            Image(systemName: list.isEmpty ? "checkmark.seal.fill" : "lightbulb.max.fill")
                .font(.system(size: 38)).foregroundStyle(list.isEmpty ? Color.green : (urgent > 0 ? Color.red : Color.orange))
            VStack(alignment: .leading, spacing: 4) {
                Text(L("nav.advice")).font(.system(size: 20, weight: .bold))
                Text(list.isEmpty ? L("adv.allGood") : L("adv.count", list.count.formatted(), urgent.formatted()))
                    .foregroundStyle(.secondary)
            }
            Spacer()
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
                    Text(a.verdict.label).font(.system(size: 11, weight: .semibold)).foregroundStyle(a.verdict.color)
                }
                Text(a.body).font(.system(size: 12.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    if let p = a.primary { Button(p.title) { p.run() }.buttonStyle(.borderedProminent).tint(a.verdict.color) }
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
                                 var msgs: [String] = []
                                 for s in u.services { msgs.append(store.resetPermission(service: s, key: u.key)) }
                                 message = "\(u.name): " + (msgs.first ?? "")
                                 done.insert("unused.\(u.key)")
                             })))
        }
        if !packets.running && packets.packets.isEmpty {
            out.append(.init(id: "pkt.try", verdict: .info, icon: "waveform.path.ecg", title: L("adv.capture.title"),
                             body: L("adv.capture.body"), primary: (L("pkt.start"), { go(.packets); packets.start() })))
        }
        return out
    }
}
