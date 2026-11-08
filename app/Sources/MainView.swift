import SwiftUI

enum SidebarItem: Hashable {
    case timeline, alerts, advice, apps, running, security, downloads, network, packets
    case category(Category)
    case loginItems, processes
}

enum TimelineFilter: CaseIterable {
    case all, alerts, permissions, loginItems, processes
    var title: String {
        switch self {
        case .all: return L("filter.all")
        case .alerts: return L("filter.alerts")
        case .permissions: return L("filter.permissions")
        case .loginItems: return L("filter.loginItems")
        case .processes: return L("filter.processes")
        }
    }
}

struct MainView: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var monitor: ProcessMonitor
    @EnvironmentObject var center: ThreatCenter
    @Environment(\.openWindow) private var openWindow
    @State private var section: SidebarItem = .advice
    @State private var filter: TimelineFilter = .all
    @State private var selection: Int?
    @State private var search = ""

    var body: some View {
        NavigationSplitView {
            Sidebar(section: $section)
                .navigationSplitViewColumnWidth(min: 200, ideal: 230, max: 280)
        } detail: {
            if store.needsFullDiskAccess && store.source == .system {
                FullDiskAccessView()
            } else if section == .advice {
                AdviceView()
            } else if section == .apps {
                AppsView()
            } else if section == .running {
                ProcessesView()
            } else if section == .security {
                SecurityView()
            } else if section == .downloads {
                DownloadsView()
            } else if section == .network {
                NetworkView()
            } else if section == .packets {
                PacketsView()
            } else {
                HStack(spacing: 0) {
                    VStack(spacing: 0) {
                        if section == .category(.micCamera) { MediaLiveCard() }
                        TimelineList(items: visibleItems, filter: $filter, selection: $selection,
                                     showChips: section == .timeline)
                    }
                    .frame(minWidth: 460)
                    Divider()
                    Group {
                        if let it = store.item(selection) {
                            DetailView(item: it)
                        } else {
                            ContentUnavailableView(L("detail.empty"), systemImage: "sidebar.right")
                        }
                    }
                    .frame(width: 400)
                    .background(Color(nsColor: .underPageBackgroundColor).opacity(0.25))
                }
                .navigationTitle(sectionTitle)
                .searchable(text: $search, placement: .toolbar, prompt: L("search.prompt"))
            }
        }
        .onChange(of: center.navToken) {
            // Tehdit penceresinden "İncele": ilgili bölüme ve öğeye git.
            if let s = center.navSection { section = s }
            if case .item(let id) = center.navFocus {
                filter = .all
                search = ""
                selection = id
            }
        }
        .onChange(of: store.trusted) { _, t in
            monitor.trusted = t
            monitor.refresh()
        }
        .onAppear {
            center.openMainWindow = { [openWindow] in openWindow(id: "main") }
            RootBridge.shared.resumeIfNeeded()
            monitor.trusted = store.trusted
            DispatchQueue.main.async { selectFirstAlert() }
            if Snapshot.section == "apps" { section = .apps }
            if Snapshot.section == "running" { section = .running }
            if Snapshot.section == "packets" { section = .packets }
            if Snapshot.section == "advice" { section = .advice }
            Snapshot.scheduleIfRequested(store: store, selection: selection)
        }
        .onChange(of: store.items.count) {
            // Liste güncellenirken seçimi aynı döngüde değiştirmek NSTableView'ı uyarıyor.
            DispatchQueue.main.async { selectFirstAlert() }
        }
    }

    private func selectFirstAlert() {
        if store.item(selection) == nil {
            selection = store.items.filter { $0.risk == .high && $0.kind == .btmAdd }.first?.id
                ?? store.items.last?.id
        }
    }

    private var sectionTitle: String {
        switch section {
        case .timeline: return L("nav.timeline")
        case .alerts: return L("nav.alerts")
        case .advice: return L("nav.advice")
        case .apps: return L("nav.apps")
        case .running: return L("nav.running")
        case .security: return L("nav.security")
        case .downloads: return L("nav.downloads")
        case .network: return L("nav.network")
        case .packets: return L("nav.packets")
        case .category(.micCamera): return L("nav.micCamera")
        case .category(.screen): return L("nav.screen")
        case .category(.accessibility): return L("nav.accessibility")
        case .category(.fullDisk): return L("nav.fullDisk")
        case .loginItems: return L("nav.loginItems")
        case .processes: return L("nav.processes")
        }
    }

    private var visibleItems: [Item] {
        var its = store.items
        switch section {
        case .alerts: its = its.filter { $0.risk >= .caution }
        case .category(let c): its = its.filter { $0.tccService.map(c.services.contains) ?? false }
        case .loginItems: its = its.filter { $0.kind == .btmAdd || $0.kind == .btmRemove }
        case .processes: its = its.filter { $0.kind == .exec }
        default: break
        }
        if section == .timeline {
            switch filter {
            case .all: break
            case .alerts: its = its.filter { $0.risk >= .caution }
            case .permissions: its = its.filter { $0.kind == .tcc }
            case .loginItems: its = its.filter { $0.kind == .btmAdd || $0.kind == .btmRemove }
            case .processes: its = its.filter { $0.kind == .exec }
            }
        }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            its = its.filter { it in
                ([it.title, it.subtitle, it.appName] + it.fields.map(\.value)).contains { $0.lowercased().contains(q) }
            }
        }
        return its.sorted { $0.date > $1.date }
    }
}

// MARK: - Kenar çubuğu

struct Sidebar: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var monitor: ProcessMonitor
    @EnvironmentObject var posture: SecurityPosture
    @EnvironmentObject var downloads: DownloadGuard
    @EnvironmentObject var network: NetworkMonitor
    @Binding var section: SidebarItem

    var body: some View {
        List(selection: $section) {
            Label(L("nav.timeline"), systemImage: "list.bullet").badge(store.items.count).tag(SidebarItem.timeline)
            Label(L("nav.alerts"), systemImage: "exclamationmark.triangle").badge(store.openAlerts).tag(SidebarItem.alerts)
            Label(L("nav.advice"), systemImage: "lightbulb").tag(SidebarItem.advice)
            Label(L("nav.apps"), systemImage: "square.grid.2x2").tag(SidebarItem.apps)
            Label(L("nav.running"), systemImage: "cpu").badge(monitor.suspicious).tag(SidebarItem.running)

            Section(L("nav.protection")) {
                Label(L("nav.security"), systemImage: "checkmark.shield").badge(posture.issues).tag(SidebarItem.security)
                Label(L("nav.downloads"), systemImage: "arrow.down.circle").badge(downloads.risky).tag(SidebarItem.downloads)
                Label(L("nav.network"), systemImage: "network").badge(network.risky).tag(SidebarItem.network)
                Label(L("nav.packets"), systemImage: "waveform.path.ecg").tag(SidebarItem.packets)
            }
            Section(L("nav.permissions")) {
                Label(L("nav.micCamera"), systemImage: "mic").tag(SidebarItem.category(.micCamera))
                Label(L("nav.screen"), systemImage: "rectangle.dashed.badge.record").tag(SidebarItem.category(.screen))
                Label(L("nav.accessibility"), systemImage: "accessibility").tag(SidebarItem.category(.accessibility))
                Label(L("nav.fullDisk"), systemImage: "internaldrive").tag(SidebarItem.category(.fullDisk))
            }
            Section(L("nav.persistence")) {
                Label(L("nav.loginItems"), systemImage: "power").badge(store.loginItemCount).tag(SidebarItem.loginItems)
                Label(L("nav.processes"), systemImage: "terminal").tag(SidebarItem.processes)
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) { status.padding(12) }
    }

    private var status: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 5) {
                Circle().fill(statusColor).frame(width: 7, height: 7)
                Text(sourceText).lineLimit(1).truncationMode(.middle)
            }
            if store.source != .system, let d = store.lastEvent {
                Text(L("status.lastEvent", Fmt.relative(d)))
            }
            if store.badLines > 0 {
                Text(L("status.badLines", store.badLines)).foregroundStyle(.orange)
            }
        }
        .font(.system(size: 11))
        .foregroundStyle(.secondary)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var statusColor: Color {
        switch store.source {
        case .system: return store.needsFullDiskAccess ? .red : .green
        case .demo: return .orange
        case .file: return .blue
        }
    }

    private var sourceText: String {
        switch store.source {
        case .system: return store.needsFullDiskAccess ? L("fda.title") : "\(L("status.system")) · \(L("status.live"))"
        case .demo: return L("status.demo")
        case .file(let u): return L("status.file", u.lastPathComponent)
        }
    }
}

// MARK: - Zaman çizelgesi

struct TimelineList: View {
    let items: [Item]
    @Binding var filter: TimelineFilter
    @Binding var selection: Int?
    let showChips: Bool

    var body: some View {
        VStack(spacing: 0) {
            if showChips {
                HStack(spacing: 6) {
                    ForEach(TimelineFilter.allCases, id: \.self) { f in
                        Chip(title: f.title, selected: filter == f) { filter = f }
                    }
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                Divider()
            }
            if items.isEmpty {
                ContentUnavailableView(L("empty.title"), systemImage: "tray", description: Text(L("empty.body")))
            } else {
                List(selection: $selection) {
                    ForEach(days, id: \.0) { day, its in
                        Section {
                            ForEach(its) { EventRow(item: $0).tag($0.id) }
                        } header: {
                            Text(Fmt.day.string(from: day).uppercased(with: .current))
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
    }

    private var days: [(Date, [Item])] {
        let cal = Calendar.current
        let groups = Dictionary(grouping: items) { cal.startOfDay(for: $0.date) }
        return groups.keys.sorted(by: >).map { ($0, groups[$0]!.sorted { $0.date > $1.date }) }
    }
}

struct EventRow: View {
    let item: Item

    var body: some View {
        HStack(spacing: 12) {
            Text(Fmt.time.string(from: item.date))
                .font(.system(size: 12).monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 44, alignment: .leading)
            AppIcon(name: item.appName, risk: item.risk, key: item.appKey)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text(item.subtitle).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 8)
            RiskTag(item.risk, trusted: item.trusted)
        }
        .padding(.vertical, 5)
    }
}

// MARK: - Tam Disk Erişimi

struct FullDiskAccessView: View {
    @EnvironmentObject var store: Store

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield")
                .font(.system(size: 52, weight: .light))
                .foregroundStyle(.secondary)
            Text(L("fda.title")).font(.system(size: 22, weight: .bold))
            Text(L("fda.body"))
                .font(.system(size: 14))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)
            HStack(spacing: 12) {
                Button(L("fda.open")) { store.openFullDiskAccessSettings() }
                    .buttonStyle(.borderedProminent)
                Button(L("menu.loadDemo")) { store.loadDemo() }
            }
            .controlSize(.large)
            Text(L("fda.hint")).font(.system(size: 12)).foregroundStyle(.tertiary)
                .multilineTextAlignment(.center).frame(maxWidth: 520)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
