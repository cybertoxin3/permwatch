import SwiftUI

struct AppsView: View {
    @EnvironmentObject var store: Store
    @State private var sort = 0

    var body: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 16), GridItem(.flexible(), spacing: 16)], spacing: 16) {
                ForEach(sorted) { AppCard(app: $0) }
            }
            .padding(20)
        }
        .navigationTitle(L("nav.apps"))
        .navigationSubtitle(L("apps.subtitle"))
        .toolbar {
            Picker("", selection: $sort) {
                Text(L("sort.risk")).tag(0)
                Text(L("sort.name")).tag(1)
                Text(L("sort.recent")).tag(2)
            }
            .pickerStyle(.segmented)
        }
    }

    private var sorted: [AppSummary] {
        switch sort {
        case 1: return store.apps.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case 2: return store.apps.sorted { $0.lastSeen > $1.lastSeen }
        default: return store.apps.sorted { ($0.risk, $0.lastSeen) > ($1.risk, $1.lastSeen) }
        }
    }
}

struct AppCard: View {
    @EnvironmentObject var store: Store
    let app: AppSummary

    var body: some View {
        let risky = app.risk == .high && !app.trusted
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                AppIcon(name: app.name, risk: app.trusted ? .normal : app.risk, size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(app.name).font(.system(size: 15, weight: .semibold))
                    Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                RiskTag(app.risk, trusted: app.trusted)
            }

            FlowLayout(spacing: 6) {
                ForEach(app.services, id: \.self) { s in
                    Pill(text: Text10n.service(s), systemImage: Icons.service(s), tint: risky ? .red : .blue)
                }
                if let li = app.loginItem {
                    Pill(text: li, systemImage: "power", tint: risky ? .red : .blue)
                } else if !app.services.isEmpty {
                    Pill(text: L("app.noLoginItem"), systemImage: "power", neutral: true)
                }
            }

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                row(L("field.signature"), app.signatureText ?? "—")
                if app.quarantineRemoved { row(L("field.quarantine"), L("quarantine.removed")) }
                if let g = app.grantedVia { row(L("field.grantedVia"), g) }
                row(L("field.lastActivity"), Fmt.relativeDay.string(from: app.lastSeen))
            }
            .font(.system(size: 12))

            if app.buckets.contains(where: { $0.level > 0.12 }) {
                HStack(alignment: .bottom, spacing: 3) {
                    ForEach(Array(app.buckets.enumerated()), id: \.offset) { _, b in
                        RoundedRectangle(cornerRadius: 2)
                            .fill(b.high && !app.trusted ? Color.red : Color.blue.opacity(0.18))
                            .frame(height: 26 * b.level)
                    }
                }
                .frame(height: 26, alignment: .bottom)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(risky ? Color.red.opacity(0.04) : Color(nsColor: .controlBackgroundColor))
        )
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(risky ? Color.red.opacity(0.3) : Color.secondary.opacity(0.2)))
        .contextMenu {
            Button(store.trusted.contains(app.key) ? L("action.untrust") : L("action.trust")) { store.toggleTrust(app.key) }
        }
    }

    private var subtitle: String {
        [app.signatureText, app.location, L("app.firstSeen", Fmt.relative(app.firstSeen))]
            .compactMap { $0 }.joined(separator: " · ")
    }

    @ViewBuilder
    private func row(_ k: String, _ v: String) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary)
            Text(v)
        }
    }
}
