import SwiftUI

struct DetailView: View {
    @EnvironmentObject var store: Store
    let item: Item
    var scrollable = true
    @State private var confirmTrash = false
    @State private var trashed = false
    @State private var showUninstall = false
    @State private var message: String?

    var body: some View {
        Group {
            if scrollable { ScrollView { content } } else { content }
        }
        .confirmationDialog(L("confirm.trash.title", (item.removablePlist as NSString?)?.lastPathComponent ?? ""),
                            isPresented: $confirmTrash) {
            Button(L("confirm.trash.ok"), role: .destructive) {
                if let p = item.removablePlist { store.trash(p) { trashed = $0 } }
            }
            Button(L("confirm.cancel"), role: .cancel) {}
        } message: {
            Text(L("confirm.trash.body"))
        }
        .sheet(isPresented: $showUninstall) {
            UninstallSheet(appPath: item.appKey, name: item.appName).environmentObject(store)
        }
        .alert(message ?? "", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button(L("common.ok")) { message = nil }
        }
    }

    private var content: some View {
            VStack(alignment: .leading, spacing: 16) {
                if !item.rules.isEmpty && !item.trusted {
                    alertBox
                }

                HStack(alignment: .top, spacing: 12) {
                    AppIcon(name: item.appName, risk: item.risk, key: item.appKey, size: 42)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(item.title).font(.system(size: 17, weight: .bold))
                        Text("\(Fmt.full.string(from: item.date)) · \(item.rawType)")
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }

                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 7) {
                    ForEach(item.fields) { f in
                        GridRow {
                            Text(f.label).foregroundStyle(.secondary).font(.system(size: 12))
                            Text(f.value)
                                .font(f.mono ? .system(size: 11.5, design: .monospaced) : .system(size: 12))
                                .foregroundStyle(f.warn ? Color.red : Color.primary)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }

                chainView
                actions
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var alertBox: some View {
        let c = item.risk.color
        return VStack(alignment: .leading, spacing: 6) {
            Label("\(item.risk.label): \(item.alertHeader)", systemImage: "exclamationmark.triangle")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(c)
            Text(L("detail.triggered")).font(.system(size: 12, weight: .medium))
            ForEach(item.rules, id: \.self) { r in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("•")
                    Text(r.text).fixedSize(horizontal: false, vertical: true)
                }
                .font(.system(size: 12))
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(c.opacity(0.09), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(c.opacity(0.3)))
    }

    @ViewBuilder
    private var chainView: some View {
        let chain = store.chain(for: item.appKey)
        if chain.count > 1 {
            VStack(alignment: .leading, spacing: 8) {
                Text(L("detail.chain").uppercased(with: .current))
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 9) {
                    ForEach(chain.suffix(8)) { c in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Circle().fill(c.risk == .normal ? Color.secondary.opacity(0.5) : c.risk.color)
                                .frame(width: 8, height: 8)
                            Text(Fmt.time.string(from: c.date))
                                .font(.system(size: 12).monospacedDigit()).foregroundStyle(.secondary)
                            Text(c.title).font(.system(size: 12, weight: c.id == item.id ? .semibold : .regular))
                                .lineLimit(1)
                        }
                    }
                }
                .padding(.leading, 4)
            }
        }
    }

    private var actions: some View {
        FlowLayout(spacing: 8) {
            if item.removablePlist != nil {
                Button(trashed ? L("action.removed") : L("action.removeItem")) { confirmTrash = true }
                    .buttonStyle(.borderedProminent).tint(.red)
                    .disabled(trashed || !FileManager.default.exists(item.removablePlist))
            }
            if let p = item.revealPath {
                Button(L("action.showInFinder")) { store.reveal(p) }
                    .disabled(!FileManager.default.exists(p))
                    .help(FileManager.default.exists(p) ? "" : L("action.missingFile"))
            }
            if let s = item.tccService {
                Button(L("action.openPermissions")) { store.openSettings(service: s) }
                if store.bundleID(forKey: item.appKey) != nil {
                    Button(L("action.resetPermission")) { message = store.resetPermission(service: s, key: item.appKey) }
                }
            }
            Button(store.trusted.contains(item.appKey) ? L("action.untrust") : L("action.trust")) {
                store.toggleTrust(item.appKey)
            }
            if Uninstaller.blockReason(item.appKey) == nil {
                Button(L("action.uninstall")) { showUninstall = true }
                    .foregroundStyle(.red)
            }
        }
        .controlSize(.large)
    }
}
