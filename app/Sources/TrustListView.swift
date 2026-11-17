import SwiftUI

/// Uygulamanın farklı yerlerinde "güvenilir", "tanıyorum", "izin ver" denen her şey tek listede; tek tek geri alınabilir.
struct TrustListView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var intel = ThreatIntel.shared
    @ObservedObject private var phish = PhishGuard.shared
    @ObservedObject private var share = ShareGuard.shared
    @ObservedObject private var guardSvc = GuardService.shared
    @State private var apps = UserDefaults.standard.stringArray(forKey: "trustedApps") ?? []
    @State private var fw = UserDefaults.standard.stringArray(forKey: NetworkMonitor.fwAllowKey) ?? []

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L("tl.title")).font(.system(size: 16, weight: .bold))
            Text(L("tl.body")).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            List {
                section(L("tl.apps"), apps.sorted(), label: { $0.hasPrefix("bundle:") ? String($0.dropFirst(7)) : PathUtil.abbreviate($0) }) { k in
                    apps.removeAll { $0 == k }
                    UserDefaults.standard.set(apps, forKey: "trustedApps")
                    NotificationCenter.default.post(name: .init("permwatch.trustChanged"), object: nil)
                }
                section(L("tl.firewall"), fw.sorted(), label: PathUtil.abbreviate) { p in
                    NetworkMonitor.disallowProgram(p); fw.removeAll { $0 == p }
                }
                section(L("tl.intel"), intel.allowed.sorted(), label: { $0 }) { intel.disallow($0) }
                section(L("tl.phish"), phish.allowed.sorted(), label: { $0 }) { phish.untrust($0) }
                section(L("tl.share"), share.trusted.keys.sorted(), label: { share.trusted[$0] ?? $0 }) { share.untrust($0) }
                if guardSvc.available {
                    section(L("tl.guard"), guardSvc.allowList, label: PathUtil.abbreviate) { guardSvc.disallow($0) }
                }
            }
            .listStyle(.inset)
            HStack { Spacer(); Button(L("common.ok")) { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(18)
        .frame(width: 620, height: 560)
    }

    @ViewBuilder
    private func section(_ title: String, _ items: [String], label: @escaping (String) -> String, remove: @escaping (String) -> Void) -> some View {
        Section {
            if items.isEmpty {
                Text(L("tl.empty")).font(.system(size: 11.5)).foregroundStyle(.tertiary)
            } else {
                ForEach(items, id: \.self) { k in
                    HStack {
                        Text(label(k)).font(.system(size: 12)).lineLimit(1).truncationMode(.middle).help(k)
                        Spacer()
                        Button(L("tl.remove")) { remove(k) }.controlSize(.small)
                    }
                }
            }
        } header: {
            Text("\(title) (\(items.count))")
        }
    }
}
