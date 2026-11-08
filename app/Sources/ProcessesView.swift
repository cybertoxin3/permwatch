import SwiftUI

enum ProcFilter: CaseIterable {
    case all, suspicious, apps, thirdParty
    var title: String {
        switch self {
        case .all: return L("filter.all")
        case .suspicious: return L("proc.filter.suspicious")
        case .apps: return L("nav.apps")
        case .thirdParty: return L("proc.filter.thirdParty")
        }
    }
}

func procSignatureText(_ sig: String?, team: String?) -> String {
    if sig == "script" { return L("sig.script") }
    return Text10n.signature(sig, team: team) ?? "—"
}

struct ProcessesView: View {
    @EnvironmentObject var monitor: ProcessMonitor
    @State private var filter: ProcFilter = .all
    @State private var search = ""
    @State private var selection: Int32?
    @State private var sortOrder = [KeyPathComparator(\ProcRow.riskSort, order: .reverse),
                                    KeyPathComparator(\ProcRow.cpuSort, order: .reverse)]

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                HStack(spacing: 6) {
                    ForEach(ProcFilter.allCases, id: \.self) { f in
                        Chip(title: f.title, selected: filter == f) { filter = f }
                    }
                    Spacer()
                    Text(L("proc.count", rows.count)).font(.system(size: 11)).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                Divider()
                Table(rows, selection: $selection, sortOrder: $sortOrder) {
                    TableColumn(L("col.name"), value: \.name) { r in
                        HStack(spacing: 8) {
                            AppIcon(name: r.name, risk: r.risk, key: r.appPath ?? r.path, size: 18)
                            Text(r.name).lineLimit(1)
                        }
                    }
                    .width(min: 160, ideal: 220)
                    TableColumn("PID", value: \.pid) { Text(verbatim: String($0.pid)).monospacedDigit() }
                        .width(56)
                    TableColumn(L("col.user"), value: \.user) { Text($0.user).lineLimit(1) }
                        .width(min: 60, ideal: 80)
                    TableColumn(L("col.cpu"), value: \.cpuSort) { r in
                        Text(r.cpu.map { String(format: "%.1f", $0) } ?? "—").monospacedDigit()
                    }
                    .width(54)
                    TableColumn(L("col.memory"), value: \.memSort) { r in
                        Text(r.memory.map { ByteCountFormatter.string(fromByteCount: Int64($0), countStyle: .memory) } ?? "—")
                            .monospacedDigit()
                    }
                    .width(76)
                    TableColumn(L("field.signature"), value: \.sigSort) { r in
                        Text(procSignatureText(r.signature, team: r.team)).lineLimit(1)
                            .foregroundStyle(r.signature == "unsigned" ? Color.red : Color.secondary)
                    }
                    .width(min: 80, ideal: 140)
                    TableColumn(L("col.risk"), value: \.riskSort) { r in
                        if r.risk >= .caution { RiskTag(r.risk) }
                    }
                    .width(86)
                }
            }
            .frame(minWidth: 560)
            Divider()
            Group {
                if let r = monitor.rows.first(where: { $0.pid == selection }) {
                    ProcDetail(row: r)
                } else {
                    ContentUnavailableView(L("proc.select"), systemImage: "cpu")
                }
            }
            .frame(width: 400)
        }
        .navigationTitle(L("nav.running"))
        .searchable(text: $search, placement: .toolbar, prompt: L("search.prompt"))
        .onAppear { monitor.visible = true; monitor.refresh() }
        .onDisappear { monitor.visible = false }
    }

    private var rows: [ProcRow] {
        var r = monitor.rows
        switch filter {
        case .all: break
        case .suspicious: r = r.filter { $0.risk >= .caution }
        case .apps: r = r.filter { $0.appPath != nil }
        case .thirdParty: r = r.filter { $0.signature != "apple" }
        }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            r = r.filter { [$0.name, $0.path ?? "", "\($0.pid)", $0.team ?? "", $0.user].contains { $0.lowercased().contains(q) } }
        }
        return r.sorted(using: sortOrder)
    }
}

struct ProcDetail: View {
    @EnvironmentObject var monitor: ProcessMonitor
    @EnvironmentObject var store: Store
    let row: ProcRow
    @State private var connections: [String]?
    @State private var confirmForce = false
    @State private var showUninstall = false
    @State private var message: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if !row.rules.isEmpty && !row.trusted {
                    let c = row.risk.color
                    VStack(alignment: .leading, spacing: 6) {
                        Label("\(row.risk.label): \(L("alert.process"))", systemImage: "exclamationmark.triangle")
                            .font(.system(size: 13, weight: .bold)).foregroundStyle(c)
                        Text(L("detail.triggered")).font(.system(size: 12, weight: .medium))
                        ForEach(row.rules, id: \.self) { r in
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

                HStack(alignment: .top, spacing: 12) {
                    AppIcon(name: row.name, risk: row.risk, key: row.appPath ?? row.path, size: 42)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(row.name).font(.system(size: 17, weight: .bold))
                        Text("PID \(row.pid) · \(row.user)").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }

                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 7) {
                    field(L("field.path"), row.path.map(PathUtil.abbreviate) ?? "—", mono: true)
                    field(L("field.signature"), procSignatureText(row.signature, team: row.team), mono: true,
                          warn: row.signature == "unsigned")
                    field(L("field.parentChain"), parentChain, mono: true)
                    if let s = row.started { field(L("field.started"), Fmt.full.string(from: s)) }
                    field(L("col.cpu"), row.cpu.map { String(format: "%.1f %%", $0) } ?? L("proc.noAccess"))
                    field(L("col.memory"), row.memory.map { ByteCountFormatter.string(fromByteCount: Int64($0), countStyle: .memory) }
                          ?? L("proc.noAccess"))
                    if let a = row.args, a.count > 1 {
                        field(L("field.arguments"), a.dropFirst().joined(separator: " "), mono: true)
                    }
                    if !row.dyld.isEmpty { field("DYLD", row.dyld.joined(separator: "\n"), mono: true, warn: true) }
                    field(L("field.connections"), connectionText, mono: true)
                }

                FlowLayout(spacing: 8) {
                    if let p = row.path, FileManager.default.fileExists(atPath: p) {
                        Button(L("action.showInFinder")) { store.reveal(p) }
                    }
                    if row.isOwn {
                        Button(L("action.quit")) { message = monitor.quit(row, force: false) }
                        Button(L("action.forceQuit")) { confirmForce = true }
                            .tint(.red)
                    }
                    Button(store.trusted.contains(row.key) ? L("action.untrust") : L("action.trust")) {
                        store.toggleTrust(row.key)
                    }
                    if let app = row.appPath, Uninstaller.blockReason(app) == nil {
                        Button(L("action.uninstall")) { showUninstall = true }.foregroundStyle(.red)
                    }
                }
                .controlSize(.large)
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .task(id: row.pid) {
            connections = nil
            let pid = row.pid
            let own = row.isOwn
            connections = own ? await Task.detached { ProcessMonitor.connections(pid: pid) }.value : nil
        }
        .confirmationDialog(L("confirm.forceQuit.title", row.name), isPresented: $confirmForce) {
            Button(L("action.forceQuit"), role: .destructive) { message = monitor.quit(row, force: true) }
            Button(L("confirm.cancel"), role: .cancel) {}
        } message: {
            Text(L("confirm.forceQuit.body"))
        }
        .sheet(isPresented: $showUninstall) {
            if let app = row.appPath {
                UninstallSheet(appPath: app, name: PathUtil.displayName(app)).environmentObject(store)
            }
        }
        .alert(message ?? "", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button(L("common.ok")) { message = nil }
        }
    }

    private var connectionText: String {
        guard row.isOwn else { return L("proc.noAccess") }
        guard let c = connections else { return "…" }
        return c.isEmpty ? L("proc.noConnections") : c.prefix(12).joined(separator: "\n")
    }

    /// "zsh (5120) ← Terminal (5119) ← launchd (1)"
    private var parentChain: String {
        let byPID = Dictionary(uniqueKeysWithValues: monitor.rows.map { ($0.pid, $0) })
        var out: [String] = []
        var cur = byPID[row.ppid]
        var guardCount = 0
        while let p = cur, guardCount < 8 {
            out.append("\(p.name) (\(p.pid))")
            if p.pid <= 1 { break }
            cur = byPID[p.ppid]
            guardCount += 1
        }
        return out.isEmpty ? "—" : out.joined(separator: " ← ")
    }

    @ViewBuilder
    private func field(_ k: String, _ v: String, mono: Bool = false, warn: Bool = false) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary).font(.system(size: 12))
            Text(v)
                .font(mono ? .system(size: 11.5, design: .monospaced) : .system(size: 12))
                .foregroundStyle(warn ? Color.red : Color.primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
