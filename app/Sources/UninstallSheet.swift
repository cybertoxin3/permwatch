import SwiftUI

struct UninstallSheet: View {
    @EnvironmentObject var store: Store
    @Environment(\.dismiss) private var dismiss
    let appPath: String
    let name: String

    @State private var candidates: [Uninstaller.Candidate] = []
    @State private var selected = Set<String>()
    @State private var resetPermissions = true
    @State private var working = false
    @State private var result: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                AppIcon(name: name, risk: .normal, key: appPath, size: 48)
                VStack(alignment: .leading, spacing: 4) {
                    Text(L("uninstall.title", name)).font(.system(size: 15, weight: .bold))
                    Text(L("uninstall.body")).font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            List(candidates) { c in
                Toggle(isOn: Binding(get: { selected.contains(c.id) },
                                     set: { if $0 { selected.insert(c.id) } else { selected.remove(c.id) } })) {
                    HStack {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(PathUtil.abbreviate(c.path)).font(.system(size: 12, design: .monospaced))
                                .lineLimit(1).truncationMode(.middle)
                            if c.byName {
                                Text(L("uninstall.byName")).font(.system(size: 10.5)).foregroundStyle(.orange)
                            }
                        }
                        Spacer()
                        Text(ByteCountFormatter.string(fromByteCount: c.size, countStyle: .file))
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
            }
            .frame(minHeight: 160)

            if store.bundleID(forKey: appPath) != nil {
                Toggle(L("uninstall.resetPerms"), isOn: $resetPermissions)
            }

            if let result {
                Text(result).font(.system(size: 12)).foregroundStyle(.secondary)
            }

            HStack {
                Text(ByteCountFormatter.string(fromByteCount: totalSize, countStyle: .file))
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                Button(result == nil ? L("confirm.cancel") : L("common.ok")) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if result == nil {
                    Button(L("uninstall.confirm"), role: .destructive) { run() }
                        .buttonStyle(.borderedProminent).tint(.red)
                        .disabled(selected.isEmpty || working)
                }
            }
        }
        .padding(20)
        .frame(width: 560, height: 440)
        .onAppear {
            candidates = Uninstaller.candidates(appPath: appPath, launchPlists: store.launchPlists(forApp: appPath))
            selected = Set(candidates.filter { !$0.byName }.map(\.id))
        }
    }

    private var totalSize: Int64 {
        candidates.filter { selected.contains($0.id) }.reduce(0) { $0 + $1.size }
    }

    private func run() {
        working = true
        let items = candidates.filter { selected.contains($0.id) }
        store.uninstall(items, key: appPath, resetPermissions: resetPermissions) { msg in
            working = false
            result = msg
        }
    }
}
