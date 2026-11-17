import SwiftUI
import UniformTypeIdentifiers

enum DiskTab: String, CaseIterable, Identifiable {
    case overview, apps, junk, large, orphans
    var id: String { rawValue }
    var title: String { L("disk.tab.\(rawValue)") }
}

enum DiskPalette {
    static let colors: [Color] = [.blue, .indigo, .purple, .pink, .orange, .teal, .mint, .cyan, .green, .brown, .yellow, .red, .gray]
    static func color(_ i: Int) -> Color { colors[i % colors.count] }
}

struct DiskView: View {
    @ObservedObject var disk = DiskManager.shared
    @EnvironmentObject var store: Store
    @State fileprivate var tab: DiskTab = ProcessInfo.processInfo.environment["PERMWATCH_DISKTAB"].flatMap(DiskTab.init(rawValue:)) ?? .overview
    @State private var appSelection: DiskApp.ID?
    /// Ziyaret edilen sekmeler: Geri / Esc / ⌘[ bir öncekine döner.
    @State fileprivate var history: [DiskTab] = []
    @State fileprivate var goingBack = false

    fileprivate var canGoBack: Bool { !history.isEmpty || tab != .overview }

    fileprivate func goBack() {
        var target = history.popLast() ?? .overview
        while target == tab, let prev = history.popLast() { target = prev }
        if target == tab { target = .overview }
        guard target != tab else { return }
        goingBack = true
        tab = target
    }

    private var content: some View {
        VStack(spacing: 0) {
            DiskHeader()
            Picker("", selection: $tab) {
                ForEach(DiskTab.allCases) { t in Text(t.title).tag(t) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 20)
            .padding(.bottom, 10)
            Divider()
            Group {
                switch tab {
                case .overview: DiskOverviewTab(tab: $tab, appSelection: $appSelection)
                case .apps: DiskAppsTab(selection: $appSelection)
                case .junk: DiskJunkTab()
                case .large: DiskLargeTab()
                case .orphans: DiskOrphansTab()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .clipped()
        }
    }

    var body: some View {
        withToolbar(navigation(content.environmentObject(disk)))
        .onAppear { disk.scanIfNeeded() }
        // AppCleaner gibi: bir uygulamayı pencereye sürükle → kaldırma ekranı açılır.
        .dropDestination(for: URL.self) { urls, _ in
            guard let u = urls.first(where: { $0.pathExtension == "app" }), let a = disk.adopt(u.path) else { return false }
            tab = .apps
            appSelection = a.id
            return true
        }
    }
}


extension DiskView {
    fileprivate func navigation<V: View>(_ v: V) -> some View {
        v.navigationTitle(L("nav.disk"))
            .navigationSubtitle(subtitle)
            .onChange(of: tab) { old, _ in
                if goingBack { goingBack = false } else { history.append(old) }
            }
            .onExitCommand { if canGoBack { goBack() } }
    }

    fileprivate var subtitle: String {
        if disk.scanning { return disk.phase }
        guard let d = disk.lastScan else { return "" }
        return L("disk.scannedAt", Fmt.relative(min(d, Date())))
    }

    fileprivate func withToolbar<V: View>(_ v: V) -> some View {
        v.toolbar {
            ToolbarItem(placement: .navigation) {
                Button { goBack() } label: { Label(L("nav.back"), systemImage: "chevron.left") }
                    .disabled(!canGoBack)
                    .keyboardShortcut(.escape, modifiers: [])
                    .help(L("nav.back") + " (Esc, ⌘[)")
            }
            ToolbarItem(placement: .navigation) {
                // ⌘[ için görünmez ikinci kısayol.
                Button("") { if canGoBack { goBack() } }
                    .keyboardShortcut("[", modifiers: .command)
                    .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)
            }
            ToolbarItem(placement: .primaryAction) {
                HStack {
                    if disk.scanning { ProgressView().controlSize(.small) }
                    Button { disk.scan() } label: { Label(L("disk.rescan"), systemImage: "arrow.clockwise") }
                        .disabled(disk.scanning)
                        .help(L("disk.rescan"))
                }
            }
        }
    }
}

// MARK: - Üst bilgi: disk doluluk çubuğu

struct DiskHeader: View {
    @EnvironmentObject var disk: DiskManager

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let v = disk.root {
                HStack(alignment: .firstTextBaseline) {
                    Image(systemName: "internaldrive.fill").foregroundStyle(.secondary)
                    Text(v.name).font(.system(size: 15, weight: .semibold))
                    Text(L("disk.capacity", DiskSize.string(v.total))).font(.system(size: 12)).foregroundStyle(.secondary)
                    Spacer()
                    Text(L("disk.free", DiskSize.string(v.availableImportant)))
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(freeColor(v))
                }
                UsageBar(volume: v, categories: disk.categories)
                    .frame(height: 16)
                HStack(spacing: 16) {
                    stat(L("disk.used"), DiskSize.string(v.used))
                    if v.purgeable > 0 { stat(L("disk.purgeable"), DiskSize.string(v.purgeable)) }
                    if disk.cleanable > 0 { stat(L("disk.cleanable"), DiskSize.string(disk.cleanable), tint: .green) }
                    Spacer()
                    Text(L("disk.percentUsed", Int((Double(v.used) / Double(max(v.total, 1)) * 100).rounded())))
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private func freeColor(_ v: DiskVolume) -> Color {
        let ratio = Double(v.availableImportant) / Double(max(v.total, 1))
        return ratio < 0.05 ? .red : ratio < 0.15 ? .orange : .green
    }

    private func stat(_ k: String, _ v: String, tint: Color = .primary) -> some View {
        HStack(spacing: 4) {
            Text(k).foregroundStyle(.secondary)
            Text(v).fontWeight(.semibold).foregroundStyle(tint)
        }
        .font(.system(size: 12))
    }
}

/// Kategorilere bölünmüş, dolu/boş alanı gösteren çubuk.
struct UsageBar: View {
    let volume: DiskVolume
    let categories: [DiskCategory]

    var body: some View {
        GeometryReader { g in
            let total = Double(max(volume.total, 1))
            let known = categories.reduce(Int64(0)) { $0 + $1.size }
            let other = max(0, volume.used - known)
            HStack(spacing: 1) {
                ForEach(categories.sorted { $0.size > $1.size }) { c in
                    Rectangle().fill(DiskPalette.color(c.colorIndex))
                        .frame(width: max(1, g.size.width * Double(c.size) / total))
                        .help("\(c.title): \(DiskSize.string(c.size))")
                }
                if categories.isEmpty {
                    Rectangle().fill(Color.accentColor).frame(width: g.size.width * Double(volume.used) / total)
                } else if other > 0 {
                    Rectangle().fill(Color.gray.opacity(0.55))
                        .frame(width: g.size.width * Double(other) / total)
                        .help("\(L("disk.cat.system")): \(DiskSize.string(other))")
                }
                if volume.purgeable > 0 {
                    Rectangle().fill(Color.gray.opacity(0.25))
                        .frame(width: g.size.width * Double(volume.purgeable) / total)
                        .help("\(L("disk.purgeable")): \(DiskSize.string(volume.purgeable))")
                }
                Spacer(minLength: 0)
            }
            .background(Color.secondary.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 5))
        }
    }
}

// MARK: - Genel bakış

struct DiskOverviewTab: View {
    @EnvironmentObject var disk: DiskManager
    @Binding var tab: DiskTab
    @Binding var appSelection: DiskApp.ID?
    @State private var confirmTrash = false
    @State private var message: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if disk.scanning && disk.categories.isEmpty {
                    HStack(spacing: 10) {
                        ProgressView().controlSize(.small)
                        Text(disk.phase).foregroundStyle(.secondary)
                    }
                    .padding(.top, 4)
                }
                quickActions
                HStack(alignment: .top, spacing: 16) {
                    breakdown
                    largestApps
                }
                HStack(alignment: .top, spacing: 16) {
                    unusedApps
                    volumesCard
                }
            }
            .padding(20)
        }
        .confirmationDialog(L("disk.trash.confirm"), isPresented: $confirmTrash) {
            Button(L("disk.trash.empty"), role: .destructive) {
                let t = disk.junk.filter { $0.group == .trash }
                disk.clean(t) { freed, _ in message = L("disk.freed", DiskSize.string(freed)) }
            }
        } message: { Text(L("disk.permanent")) }
        .alert(message ?? "", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button(L("common.ok")) { message = nil }
        }
    }

    private var quickActions: some View {
        HStack(spacing: 12) {
            ActionTile(icon: "sparkles", tint: .green, title: L("disk.tile.junk"), value: DiskSize.string(disk.cleanable),
                       button: L("disk.review")) { tab = .junk }
            ActionTile(icon: "trash", tint: .orange, title: L("disk.tile.trash"), value: DiskSize.string(disk.trashSize),
                       button: L("disk.trash.empty")) { confirmTrash = true }
                .disabled(disk.trashSize == 0)
            ActionTile(icon: "shippingbox", tint: .purple, title: L("disk.tile.orphans"),
                       value: "\(disk.orphans.count) · \(DiskSize.string(disk.orphanSize))", button: L("disk.review")) { tab = .orphans }
            ActionTile(icon: "doc.badge.ellipsis", tint: .blue, title: L("disk.tile.large"),
                       value: disk.bigFiles.isEmpty ? "—" : "\(disk.bigFiles.count)", button: L("disk.find")) { tab = .large }
        }
    }

    private var breakdown: some View {
        Card(title: L("disk.breakdown"), icon: "chart.pie") {
            if let v = disk.root {
                let known = disk.categories.reduce(Int64(0)) { $0 + $1.size }
                let rows = disk.categories.sorted { $0.size > $1.size }
                VStack(spacing: 7) {
                    ForEach(rows) { c in
                        SizeRow(icon: c.icon, color: DiskPalette.color(c.colorIndex), title: c.title, size: c.size,
                                fraction: Double(c.size) / Double(max(v.used, 1)))
                            .contextMenu {
                                if let p = c.path { Button(L("action.showInFinder")) { NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: p) } }
                            }
                    }
                    if !rows.isEmpty {
                        SizeRow(icon: "gearshape.2", color: .gray, title: L("disk.cat.system"), size: max(0, v.used - known),
                                fraction: Double(max(0, v.used - known)) / Double(max(v.used, 1)))
                    }
                }
            }
        }
    }

    private var largestApps: some View {
        Card(title: L("disk.largestApps"), icon: "square.grid.2x2") {
            let top = Array(disk.apps.sorted { $0.total > $1.total }.prefix(10))
            let maxSize = Double(top.first?.total ?? 1)
            VStack(spacing: 7) {
                ForEach(top) { a in
                    Button {
                        appSelection = a.id
                        tab = .apps
                    } label: {
                        HStack(spacing: 8) {
                            AppIcon(name: a.name, risk: .normal, key: a.path, size: 20)
                            Text(a.name).lineLimit(1)
                            Spacer()
                            Bar(fraction: Double(a.total) / maxSize, color: .accentColor).frame(width: 80)
                            Text(DiskSize.string(a.total)).monospacedDigit().foregroundStyle(.secondary).frame(width: 70, alignment: .trailing)
                        }
                        .font(.system(size: 12))
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var unusedApps: some View {
        Card(title: L("disk.unusedApps"), icon: "moon.zzz") {
            let list = disk.apps.filter(\.unused).sorted { $0.total > $1.total }
            if list.isEmpty {
                Text(disk.scanning ? "…" : L("disk.unused.none")).font(.system(size: 12)).foregroundStyle(.secondary)
            } else {
                Text(L("disk.unused.summary", list.count, DiskSize.string(list.reduce(0) { $0 + $1.total })))
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                VStack(spacing: 6) {
                    ForEach(list.prefix(6)) { a in
                        Button { appSelection = a.id; tab = .apps } label: {
                            HStack(spacing: 8) {
                                AppIcon(name: a.name, risk: .normal, key: a.path, size: 18)
                                Text(a.name).lineLimit(1)
                                Spacer()
                                Text(a.lastUsed.map { Fmt.relative($0) } ?? L("disk.never")).foregroundStyle(.secondary)
                                Text(DiskSize.string(a.total)).monospacedDigit().frame(width: 64, alignment: .trailing)
                            }
                            .font(.system(size: 12))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }

    private var volumesCard: some View {
        Card(title: L("disk.volumes"), icon: "externaldrive") {
            VStack(spacing: 10) {
                ForEach(disk.volumes) { v in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: v.isRoot ? "internaldrive" : v.isRemovable ? "externaldrive" : "opticaldiscdrive")
                            Text(v.name).fontWeight(.medium)
                            Spacer()
                            Text(L("disk.freeOf", DiskSize.string(v.availableImportant), DiskSize.string(v.total)))
                                .foregroundStyle(.secondary)
                        }
                        Bar(fraction: Double(v.used) / Double(max(v.total, 1)), color: v.isRoot ? .accentColor : .teal)
                            .frame(height: 6)
                    }
                    .font(.system(size: 12))
                    .contextMenu { Button(L("action.showInFinder")) { NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: v.path) } }
                }
            }
        }
    }
}

// MARK: - Uygulamalar ve tam kaldırma

enum AppFilter: String, CaseIterable, Identifiable {
    case all, large, unused, appStore, data
    var id: String { rawValue }
    var title: String { L("disk.filter.\(rawValue)") }
}

struct DiskAppsTab: View {
    @EnvironmentObject var disk: DiskManager
    @Binding var selection: DiskApp.ID?
    @State private var search = ""
    @State private var filter: AppFilter = .all
    @State private var sortOrder = [KeyPathComparator(\DiskApp.total, order: .reverse)]

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                HStack(spacing: 6) {
                    ForEach(AppFilter.allCases) { f in Chip(title: f.title, selected: filter == f) { filter = f } }
                    Spacer()
                    TextField(L("disk.searchApps"), text: $search)
                        .textFieldStyle(.roundedBorder).frame(width: 170)
                }
                .padding(.horizontal, 12).padding(.vertical, 8)
                Table(rows, selection: $selection, sortOrder: $sortOrder) {
                    TableColumn(L("disk.col.name"), value: \.name) { a in
                        HStack(spacing: 8) {
                            AppIcon(name: a.name, risk: .normal, key: a.path, size: 20)
                            VStack(alignment: .leading, spacing: 0) {
                                Text(a.name).lineLimit(1)
                                if let v = a.version { Text(v).font(.system(size: 10)).foregroundStyle(.secondary) }
                            }
                            if a.appStore { Image(systemName: "bag").font(.system(size: 10)).foregroundStyle(.secondary).help("App Store") }
                        }
                    }
                    .width(min: 160, ideal: 220)
                    TableColumn(L("disk.col.app"), value: \.appSize) { Text(DiskSize.string($0.appSize)).monospacedDigit() }
                        .width(min: 60, ideal: 75)
                    TableColumn(L("disk.col.data"), value: \.dataSize) { a in
                        Text(a.dataSize > 0 ? DiskSize.string(a.dataSize) : "—").monospacedDigit()
                            .foregroundStyle(a.dataSize > 500_000_000 ? .orange : .secondary)
                    }
                    .width(min: 60, ideal: 75)
                    TableColumn(L("disk.col.total"), value: \.total) { Text(DiskSize.string($0.total)).monospacedDigit().fontWeight(.semibold) }
                        .width(min: 60, ideal: 80)
                    TableColumn(L("disk.col.lastUsed"), value: \.lastUsedSort) { a in
                        Text(a.lastUsed.map { Fmt.relative($0) } ?? L("disk.never"))
                            .foregroundStyle(a.unused ? .orange : .secondary)
                    }
                    .width(min: 80, ideal: 110)
                }
                .overlay {
                    if disk.apps.isEmpty && disk.scanning { ProgressView(disk.phase) }
                }
                HStack {
                    Image(systemName: "arrow.down.app").foregroundStyle(.secondary)
                    Text(L("disk.dropHint")).font(.system(size: 11)).foregroundStyle(.secondary)
                    Spacer()
                    Text(L("disk.appsSummary", rows.count, DiskSize.string(rows.reduce(0) { $0 + $1.total })))
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 12).padding(.vertical, 6)
            }
            .frame(minWidth: 520)
            Divider()
            Group {
                if let id = selection, let app = disk.apps.first(where: { $0.id == id }) {
                    AppRemovalPane(app: app).id(app.id)
                } else {
                    ContentUnavailableView(L("disk.pickApp"), systemImage: "app.badge.checkmark",
                                           description: Text(L("disk.pickApp.body")))
                }
            }
            .frame(width: 400)
            .background(Color(nsColor: .underPageBackgroundColor).opacity(0.25))
        }
    }

    private var rows: [DiskApp] {
        var list = disk.apps
        switch filter {
        case .all: break
        case .large: list = list.filter { $0.total >= 1_000_000_000 }
        case .unused: list = list.filter(\.unused)
        case .appStore: list = list.filter(\.appStore)
        case .data: list = list.filter { $0.dataSize >= 100_000_000 }
        }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty { list = list.filter { $0.name.lowercased().contains(q) || ($0.bundleID ?? "").lowercased().contains(q) } }
        return list.sorted(using: sortOrder)
    }
}

struct AppRemovalPane: View {
    @EnvironmentObject var disk: DiskManager
    @EnvironmentObject var store: Store
    let app: DiskApp

    @State private var items: [Uninstaller.Candidate] = []
    @State private var selected = Set<String>()
    @State private var loading = true
    @State private var resetPermissions = true
    @State private var working = false
    @State private var confirming = false
    /// Onay penceresi kapanırken sıfırlanmaz: düğme hangi işlem için açıldıysa onu çalıştırır.
    @State private var mode: Mode = .remove
    @State private var result: String?
    @State private var blocked: Uninstaller.Blocked?

    enum Mode { case remove, reset, cache }

    static let groupOrder = ["app", "support", "container", "cache", "prefs", "state", "web", "launch", "plugins", "logs", "receipts", "other"]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                AppIcon(name: app.name, risk: .normal, key: app.path, size: 52)
                VStack(alignment: .leading, spacing: 2) {
                    Text(app.name).font(.system(size: 16, weight: .bold))
                    Text([app.version, app.bundleID].compactMap { $0 }.joined(separator: " · "))
                        .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    Text(PathUtil.abbreviate(app.path)).font(.system(size: 11)).foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            HStack(spacing: 14) {
                metric(L("disk.col.app"), DiskSize.string(app.appSize))
                metric(L("disk.col.data"), DiskSize.string(dataTotal))
                metric(L("disk.col.lastUsed"), app.lastUsed.map { Fmt.relativeDay.string(from: $0) } ?? L("disk.never"))
            }

            HStack {
                Text(L("disk.foundItems", items.count)).font(.system(size: 12, weight: .semibold))
                Spacer()
                Button(L("disk.selectAll")) { selected = Set(items.map(\.id)) }.buttonStyle(.link).font(.system(size: 11))
                Button(L("disk.selectNone")) { selected = [] }.buttonStyle(.link).font(.system(size: 11))
            }

            if loading {
                ProgressView(L("disk.searching")).frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(groups, id: \.0) { g, list in
                        Section {
                            ForEach(list) { c in row(c) }
                        } header: {
                            HStack {
                                Text(L("disk.group.\(g)"))
                                Spacer()
                                Text(DiskSize.string(list.reduce(0) { $0 + $1.size }))
                            }
                        }
                    }
                }
                .listStyle(.inset)
            }

            if store.bundleID(forKey: app.path) != nil {
                Toggle(L("uninstall.resetPerms"), isOn: $resetPermissions).font(.system(size: 12))
            }
            if let b = blocked, b != .missing {
                Label(L("uninstall.blocked"), systemImage: "lock").font(.system(size: 12)).foregroundStyle(.orange)
            }
            if let result {
                Text(result).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Text(L("disk.selectedTotal", DiskSize.string(selectedSize))).font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                Button { NSWorkspace.shared.selectFile(app.path, inFileViewerRootedAtPath: "") } label: { Image(systemName: "magnifyingglass") }
                    .help(L("action.showInFinder"))
                Button(L("disk.clearCache")) { mode = .cache; confirming = true }
                    .disabled(working || loading || cacheItems.isEmpty)
                    .help(L("disk.clearCache.help"))
                Button(L("disk.resetApp")) { mode = .reset; confirming = true }
                    .disabled(working || loading || blocked != nil || selectedData.isEmpty)
                    .help(L("disk.resetApp.help"))
                Button(L("disk.removeFully"), role: .destructive) { mode = .remove; confirming = true }
                    .buttonStyle(.borderedProminent).tint(.red)
                    .disabled(working || loading || blocked != nil || !selected.contains(app.path))
            }
        }
        .padding(16)
        .task {
            blocked = Uninstaller.blockReason(app.path)
            items = await disk.leftovers(for: app, extraLaunch: store.launchPlists(forApp: app.path))
            selected = Set(items.filter { !$0.byName }.map(\.id))
            loading = false
        }
        .confirmationDialog(dialogTitle, isPresented: $confirming) {
            switch mode {
            case .reset: Button(L("disk.resetApp"), role: .destructive) { run(keepApp: true) }
            case .cache: Button(L("disk.clearCache"), role: .destructive) { run(keepApp: true, only: cacheItems) }
            case .remove: Button(L("disk.removeFully"), role: .destructive) { run(keepApp: false) }
            }
        } message: {
            switch mode {
            case .reset: Text(L("disk.remove.body", selectedData.count, DiskSize.string(selectedDataSize)))
            case .cache: Text(L("disk.remove.body", cacheItems.count, DiskSize.string(cacheItems.reduce(0) { $0 + $1.size })))
            case .remove: Text(L("disk.remove.body", selected.count, DiskSize.string(selectedSize)))
            }
        }
    }

    private func row(_ c: Uninstaller.Candidate) -> some View {
        Toggle(isOn: Binding(get: { selected.contains(c.id) },
                             set: { if $0 { selected.insert(c.id) } else { selected.remove(c.id) } })) {
            HStack(spacing: 6) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: c.path)).resizable().frame(width: 16, height: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text((c.path as NSString).lastPathComponent).font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
                    Text(PathUtil.abbreviate((c.path as NSString).deletingLastPathComponent))
                        .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.head)
                    if c.byName { Text(L("uninstall.byName")).font(.system(size: 10)).foregroundStyle(.orange) }
                    if Leftovers.isSystem(c.path) { Text(L("disk.needsAdmin")).font(.system(size: 10)).foregroundStyle(.blue) }
                }
                Spacer()
                Text(DiskSize.string(c.size)).font(.system(size: 11)).monospacedDigit().foregroundStyle(.secondary)
            }
        }
        .contextMenu { Button(L("action.showInFinder")) { NSWorkspace.shared.selectFile(c.path, inFileViewerRootedAtPath: "") } }
    }

    private var groups: [(String, [Uninstaller.Candidate])] {
        let d = Dictionary(grouping: items) { $0.group }
        return Self.groupOrder.compactMap { g in d[g].map { (g, $0.sorted { $0.size > $1.size }) } }
            + d.keys.filter { !Self.groupOrder.contains($0) }.sorted().map { ($0, d[$0]!) }
    }

    private var dataTotal: Int64 { items.filter { !$0.isApp && !$0.byName }.reduce(0) { $0 + $1.size } }
    private var selectedSize: Int64 { items.filter { selected.contains($0.id) }.reduce(0) { $0 + $1.size } }
    private var selectedData: [Uninstaller.Candidate] { items.filter { selected.contains($0.id) && !$0.isApp } }
    private var selectedDataSize: Int64 { selectedData.reduce(0) { $0 + $1.size } }
    /// Uygulamaya kesin ait önbellekler (ada göre zayıf eşleşenler hariç).
    private var cacheItems: [Uninstaller.Candidate] { items.filter { $0.group == "cache" && !$0.byName && !$0.isApp } }
    private var dialogTitle: String {
        switch mode {
        case .reset: return L("disk.resetApp.confirm", app.name)
        case .cache: return L("disk.clearCache.confirm", app.name)
        case .remove: return L("uninstall.title", app.name)
        }
    }

    private func metric(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(k).font(.system(size: 10)).foregroundStyle(.secondary)
            Text(v).font(.system(size: 13, weight: .semibold)).monospacedDigit()
        }
    }

    private func run(keepApp: Bool, only: [Uninstaller.Candidate]? = nil) {
        working = true
        let chosen = only ?? (keepApp ? selectedData : items.filter { selected.contains($0.id) })
        let system = chosen.filter { !$0.isApp && Leftovers.isSystem($0.path) }.map(\.path)
        let user = chosen.filter { $0.isApp || !Leftovers.isSystem($0.path) }
        // Önce uygulama ve yardımcıları kapansın ki dosyaları yeniden yazmasınlar.
        if let id = app.bundleID {
            for r in NSRunningApplication.runningApplications(withBundleIdentifier: id) { r.terminate() }
        }
        let sysFailed = DiskManager.removeSystemItems(system)
        // Yalnızca önbellek temizlenirken izinlere dokunma.
        store.uninstall(user, key: app.path, resetPermissions: only == nil && resetPermissions) { msg in
            working = false
            let fm = FileManager.default
            let left = chosen.filter { fm.fileExists(atPath: $0.path) }
            result = sysFailed.isEmpty ? msg : msg + "\n" + L("uninstall.failed", sysFailed.map(PathUtil.abbreviate).joined(separator: ", "))
            items.removeAll { c in chosen.contains(c) && !left.contains(c) }
            selected = selected.intersection(items.map(\.id))
            if only != nil { return }   // önbellek: uygulama listede kalır
            if left.isEmpty || keepApp { disk.forget(app, keptApp: keepApp || fm.fileExists(atPath: app.path)) }
        }
    }
}

// MARK: - Önbellek ve gereksiz dosyalar

struct DiskJunkTab: View {
    @EnvironmentObject var disk: DiskManager
    @State private var selected: Set<String>?
    @State private var confirm = false
    @State private var working = false
    @State private var message: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "info.circle").foregroundStyle(.secondary)
                Text(L("disk.junk.info")).font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            if disk.junk.isEmpty {
                if disk.scanning { ProgressView(disk.phase).frame(maxHeight: .infinity) }
                else { ContentUnavailableView(L("disk.junk.empty"), systemImage: "sparkles") }
            } else {
                List {
                    ForEach(JunkGroup.allCases) { g in
                        let list = disk.junk.filter { $0.group == g }.sorted { $0.size > $1.size }
                        if !list.isEmpty {
                            Section {
                                ForEach(list) { row($0) }
                            } header: {
                                HStack {
                                    Label(g.title, systemImage: g.icon)
                                    Spacer()
                                    Text(DiskSize.string(list.reduce(0) { $0 + $1.size }))
                                    Button(allOn(list) ? L("disk.selectNone") : L("disk.selectAll")) { toggleAll(list) }
                                        .buttonStyle(.link).font(.system(size: 11))
                                }
                            }
                        }
                    }
                }
                .listStyle(.inset)
            }
            Divider()
            HStack {
                Text(L("disk.selectedTotal", DiskSize.string(selectedSize))).font(.system(size: 12, weight: .semibold))
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button(L("disk.clean")) { confirm = true }
                    .buttonStyle(.borderedProminent)
                    .disabled(working || current.isEmpty)
            }
            .padding(12)
        }
        .confirmationDialog(L("disk.clean.confirm", DiskSize.string(selectedSize)), isPresented: $confirm) {
            Button(L("disk.clean"), role: .destructive) {
                working = true
                let list = disk.junk.filter { current.contains($0.id) }
                disk.clean(list) { freed, failed in
                    working = false
                    message = failed > 0 ? L("disk.freedPartial", DiskSize.string(freed), failed) : L("disk.freed", DiskSize.string(freed))
                }
            }
        } message: { Text(L("disk.permanent")) }
        .alert(message ?? "", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button(L("common.ok")) { message = nil }
        }
    }

    private var current: Set<String> {
        let ids = Set(disk.junk.map(\.id))
        return (selected ?? Set(disk.junk.filter(\.safe).map(\.id))).intersection(ids)
    }

    private var selectedSize: Int64 { disk.junk.filter { current.contains($0.id) }.reduce(0) { $0 + $1.size } }
    private func allOn(_ l: [JunkItem]) -> Bool { l.allSatisfy { current.contains($0.id) } }
    private func toggleAll(_ l: [JunkItem]) {
        var s = current
        if allOn(l) { s.subtract(l.map(\.id)) } else { s.formUnion(l.map(\.id)) }
        selected = s
    }

    private func row(_ it: JunkItem) -> some View {
        Toggle(isOn: Binding(get: { current.contains(it.id) },
                             set: { on in var s = current; if on { s.insert(it.id) } else { s.remove(it.id) }; selected = s })) {
            HStack(spacing: 8) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: it.path)).resizable().frame(width: 18, height: 18)
                VStack(alignment: .leading, spacing: 1) {
                    Text(it.title).font(.system(size: 12.5)).lineLimit(1)
                    Text(PathUtil.abbreviate(it.path)).font(.system(size: 10.5)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    if let n = it.note { Text(n).font(.system(size: 10.5)).foregroundStyle(.orange) }
                }
                Spacer()
                Text(DiskSize.string(it.size)).font(.system(size: 12)).monospacedDigit()
                    .foregroundStyle(it.size > 1_000_000_000 ? .orange : .secondary)
            }
        }
        .contextMenu { Button(L("action.showInFinder")) { NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: it.path) } }
    }
}

// MARK: - Büyük dosyalar

struct DiskLargeTab: View {
    @EnvironmentObject var disk: DiskManager
    @State private var threshold: Int64 = 100_000_000
    @State private var kind = "all"
    @State private var selected = Set<String>()
    @State private var confirm = false
    @State private var message: String?

    static let kinds = ["all", "video", "image", "archive", "audio", "photo", "ipsw", "other"]

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Picker(L("disk.large.min"), selection: $threshold) {
                    Text("50 MB").tag(Int64(50_000_000))
                    Text("100 MB").tag(Int64(100_000_000))
                    Text("500 MB").tag(Int64(500_000_000))
                    Text("1 GB").tag(Int64(1_000_000_000))
                    Text("5 GB").tag(Int64(5_000_000_000))
                }
                .frame(width: 190)
                Picker(L("disk.large.kind"), selection: $kind) {
                    ForEach(Self.kinds, id: \.self) { Text(L("disk.kind.\($0)")).tag($0) }
                }
                .frame(width: 200)
                Spacer()
                if disk.bigScanning {
                    ProgressView().controlSize(.small)
                    Text(L("disk.large.progress", disk.bigScanned)).font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                    Button(L("confirm.cancel")) { disk.cancelBigScan() }
                } else {
                    Button(disk.bigFiles.isEmpty ? L("disk.large.scan") : L("disk.rescan")) {
                        selected = []
                        disk.scanBigFiles(minSize: 50_000_000)
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            if rows.isEmpty {
                ContentUnavailableView(disk.bigScanning ? L("disk.searching") : L("disk.large.none"), systemImage: "doc.viewfinder",
                                       description: Text(L("disk.large.body")))
                    .frame(maxHeight: .infinity)
            } else {
                List(rows) { f in
                    Toggle(isOn: Binding(get: { selected.contains(f.id) },
                                         set: { if $0 { selected.insert(f.id) } else { selected.remove(f.id) } })) {
                        HStack(spacing: 8) {
                            Image(nsImage: NSWorkspace.shared.icon(forFile: f.path)).resizable().frame(width: 26, height: 26)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(f.name).font(.system(size: 12.5, weight: .medium)).lineLimit(1).truncationMode(.middle)
                                Text(PathUtil.abbreviate((f.path as NSString).deletingLastPathComponent))
                                    .font(.system(size: 10.5)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 1) {
                                Text(DiskSize.string(f.size)).font(.system(size: 12, weight: .semibold)).monospacedDigit()
                                if let d = f.accessed ?? f.modified {
                                    Text(L("disk.large.opened", Fmt.relative(d))).font(.system(size: 10)).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    .contextMenu {
                        Button(L("action.showInFinder")) { NSWorkspace.shared.selectFile(f.path, inFileViewerRootedAtPath: "") }
                        Button(L("disk.open")) { NSWorkspace.shared.open(URL(fileURLWithPath: f.path)) }
                    }
                }
                .listStyle(.inset)
            }
            Divider()
            HStack {
                Text(L("disk.large.summary", rows.count, DiskSize.string(rows.reduce(0) { $0 + $1.size })))
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                Text(L("disk.selectedTotal", DiskSize.string(selectedSize))).font(.system(size: 12, weight: .semibold))
                Button(L("uninstall.confirm"), role: .destructive) { confirm = true }
                    .disabled(selected.isEmpty)
            }
            .padding(12)
        }
        .confirmationDialog(L("disk.large.confirm", selected.count), isPresented: $confirm) {
            Button(L("uninstall.confirm"), role: .destructive) {
                disk.trashFiles(Array(selected)) { left in
                    selected = []
                    message = left == 0 ? L("uninstall.done") : L("disk.notMoved", left)
                }
            }
        } message: { Text(L("uninstall.body")) }
        .alert(message ?? "", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button(L("common.ok")) { message = nil }
        }
    }

    private var rows: [BigFile] {
        disk.bigFiles.filter { $0.size >= threshold && (kind == "all" || $0.kind == kind) }
    }
    private var selectedSize: Int64 { disk.bigFiles.filter { selected.contains($0.id) }.reduce(0) { $0 + $1.size } }
}

// MARK: - Sahipsiz kalıntılar

struct DiskOrphansTab: View {
    @EnvironmentObject var disk: DiskManager
    @State private var selected = Set<String>()
    @State private var expanded = Set<String>()
    @State private var confirm = false
    @State private var message: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top) {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                // Spacer ile yan yana "dikeyde sabit" metin çok dar bir genişlik alıp yüzlerce satıra
                // uzuyor ve sekmenin üstünü/altını (Tümünü seç, Sil) pencerenin dışına itiyordu.
                Text(L("disk.orphans.info")).font(.system(size: 12)).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            if disk.orphans.isEmpty {
                if disk.scanning { ProgressView(disk.phase).frame(maxHeight: .infinity) }
                else { ContentUnavailableView(L("disk.orphans.none"), systemImage: "checkmark.seal") }
            } else {
                HStack(spacing: 10) {
                    Button(allSelected ? L("disk.selectNone") : L("disk.selectAll")) {
                        selected = allSelected ? [] : Set(disk.orphans.map(\.id))
                    }
                    Text(L("disk.selectedTotal", DiskSize.string(selectedSize))).font(.system(size: 12)).foregroundStyle(.secondary)
                    Spacer()
                    Button(L("disk.trashSelected"), role: .destructive) { confirm = true }
                        .disabled(selected.isEmpty)
                    Button(L("disk.trashAll"), role: .destructive) {
                        selected = Set(disk.orphans.map(\.id))
                        confirm = true
                    }
                    .buttonStyle(.borderedProminent).tint(.red)
                }
                .padding(.horizontal, 16).padding(.bottom, 8)
                Divider()
                // Not: satırı Toggle + DisclosureGroup ile kurmak listeyi içeriği kadar uzatıp (kaydırmasız)
                // başlığı ve düğmeleri pencerenin dışına itiyordu; açılır kısım elle yönetiliyor.
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(disk.orphans) { o in
                        HStack(spacing: 8) {
                            Toggle("", isOn: Binding(get: { selected.contains(o.id) },
                                                     set: { if $0 { selected.insert(o.id) } else { selected.remove(o.id) } }))
                                .labelsHidden()
                            Button {
                                if expanded.contains(o.id) { expanded.remove(o.id) } else { expanded.insert(o.id) }
                            } label: {
                                Image(systemName: expanded.contains(o.id) ? "chevron.down" : "chevron.right")
                                    .font(.system(size: 10, weight: .semibold)).frame(width: 14)
                            }
                            .buttonStyle(.plain).foregroundStyle(.secondary)
                            Image(systemName: "shippingbox").foregroundStyle(.purple)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(o.id).font(.system(size: 12.5, weight: .medium)).lineLimit(1)
                                Text(L("disk.orphans.places", o.paths.count)).font(.system(size: 10.5)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(DiskSize.string(o.size)).font(.system(size: 12)).monospacedDigit().foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 6)
                        if expanded.contains(o.id) {
                            ForEach(o.paths, id: \.self) { p in
                                Text(PathUtil.abbreviate(p)).font(.system(size: 10.5, design: .monospaced))
                                    .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                    .padding(.leading, 76).padding(.trailing, 16).padding(.vertical, 2)
                                    .contextMenu { Button(L("action.showInFinder")) { NSWorkspace.shared.selectFile(p, inFileViewerRootedAtPath: "") } }
                            }
                        }
                        Divider().padding(.leading, 16)
                    }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            Divider()
            HStack {
                Text(L("disk.orphans.summary", disk.orphans.count, DiskSize.string(disk.orphanSize)))
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                Button(L("disk.selectAll")) { selected = Set(disk.orphans.map(\.id)) }.disabled(disk.orphans.isEmpty)
                Text(L("disk.selectedTotal", DiskSize.string(selectedSize))).font(.system(size: 12, weight: .semibold))
                Button(L("uninstall.confirm"), role: .destructive) { confirm = true }
                    .buttonStyle(.borderedProminent).tint(.red)
                    .disabled(selected.isEmpty)
            }
            .padding(12)
        }
        .confirmationDialog(L("disk.orphans.confirm", selected.count), isPresented: $confirm) {
            Button(L("uninstall.confirm"), role: .destructive) {
                disk.trashOrphans(disk.orphans.filter { selected.contains($0.id) }) { left in
                    selected = selected.intersection(disk.orphans.map(\.id))
                    message = left == 0 ? L("uninstall.done") : L("disk.notMoved", left)
                }
            }
        } message: { Text(L("uninstall.body")) }
        .alert(message ?? "", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button(L("common.ok")) { message = nil }
        }
    }

    private var selectedSize: Int64 { disk.orphans.filter { selected.contains($0.id) }.reduce(0) { $0 + $1.size } }
    private var allSelected: Bool { !disk.orphans.isEmpty && selected.count >= disk.orphans.count }
}

// MARK: - Küçük parçalar

struct Card<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: icon).font(.system(size: 13, weight: .semibold))
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.secondary.opacity(0.2)))
    }
}

struct ActionTile: View {
    let icon: String
    let tint: Color
    let title: String
    let value: String
    let button: String
    let action: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: icon).font(.system(size: 16)).foregroundStyle(tint)
                Spacer()
            }
            Text(title).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
            Text(value).font(.system(size: 17, weight: .bold)).monospacedDigit().lineLimit(1).minimumScaleFactor(0.7)
            Button(button, action: action).controlSize(.small)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12).fill(tint.opacity(0.07)))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(tint.opacity(0.25)))
    }
}

struct Bar: View {
    let fraction: Double
    let color: Color

    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.secondary.opacity(0.15))
                Capsule().fill(color).frame(width: max(2, g.size.width * min(1, max(0, fraction))))
            }
        }
        .frame(height: 6)
    }
}

struct SizeRow: View {
    let icon: String
    let color: Color
    let title: String
    let size: Int64
    let fraction: Double

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon).foregroundStyle(color).frame(width: 18)
            Text(title).lineLimit(1)
            Spacer()
            Bar(fraction: fraction, color: color).frame(width: 90)
            Text(DiskSize.string(size)).monospacedDigit().foregroundStyle(.secondary).frame(width: 70, alignment: .trailing)
        }
        .font(.system(size: 12))
    }
}
