import SwiftUI

struct MenuBarPanel: View {
    @EnvironmentObject var store: Store
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("permwatch").font(.system(size: 14, weight: .bold))
                Spacer()
                Label(store.source == .demo ? L("status.demo") : L("menu.watching"), systemImage: "circle.fill")
                    .labelStyle(.titleAndIcon)
                    .font(.system(size: 11))
                    .foregroundStyle(store.source == .demo ? .orange : .green)
            }
            .padding([.horizontal, .top], 14)
            .padding(.bottom, 10)

            HStack(spacing: 8) {
                stat(store.openAlerts, L("menu.openAlerts"), red: store.openAlerts > 0)
                stat(store.recentPermissionChanges, L("menu.permChanges"))
                stat(store.loginItemCount, L("menu.loginItems"))
            }
            .padding(.horizontal, 14)
            .padding(.bottom, 12)

            Text(L("menu.recent").uppercased(with: .current))
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 14)
                .padding(.bottom, 4)

            ForEach(recent) { it in
                Divider()
                HStack(alignment: .top, spacing: 10) {
                    Circle().fill(it.risk.color).frame(width: 8, height: 8).padding(.top, 5)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(it.title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                        Text(it.subtitle).font(.system(size: 11.5)).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    Text(Fmt.time.string(from: it.date)).font(.system(size: 11.5).monospacedDigit()).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
            }

            Divider()
            HStack {
                Button(L("menu.openTimeline")) {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                .buttonStyle(.link)
                Spacer()
                Button(L("menu.quit")) { NSApp.terminate(nil) }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            }
            .font(.system(size: 13))
            .padding(14)
        }
        .frame(width: 380)
    }

    private var recent: [Item] {
        let alerts = store.items.filter { $0.risk >= .caution }.sorted { $0.date > $1.date }
        let rest = store.items.filter { $0.risk == .normal }.sorted { $0.date > $1.date }
        return Array((alerts.prefix(3) + rest.prefix(1)).sorted { $0.date > $1.date })
    }

    private func stat(_ n: Int, _ label: String, red: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(n)").font(.system(size: 20, weight: .bold)).foregroundStyle(red ? Color.red : Color.primary)
            Text(label).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2)
        }
        .padding(10)
        .frame(maxWidth: .infinity, minHeight: 70, alignment: .topLeading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 9))
    }
}
