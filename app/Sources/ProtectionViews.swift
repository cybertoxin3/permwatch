import SwiftUI

// MARK: - Güvenlik durumu

struct SecurityView: View {
    @EnvironmentObject var posture: SecurityPosture

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                let s = posture.score
                HStack(spacing: 18) {
                    ZStack {
                        Circle().stroke(Color.secondary.opacity(0.2), lineWidth: 10)
                        Circle()
                            .trim(from: 0, to: s.total == 0 ? 0 : CGFloat(s.on) / CGFloat(s.total))
                            .stroke(s.on == s.total ? Color.green : Color.orange,
                                    style: StrokeStyle(lineWidth: 10, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                        Text("\(s.on)/\(s.total)").font(.system(size: 20, weight: .bold)).monospacedDigit()
                    }
                    .frame(width: 84, height: 84)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(L("nav.security")).font(.system(size: 20, weight: .bold))
                        Text(L("sec.score", s.on, s.total)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button { posture.refresh() } label: { Image(systemName: "arrow.clockwise") }
                }
                VStack(spacing: 0) {
                    ForEach(posture.checks) { c in
                        HStack(spacing: 12) {
                            Image(systemName: icon(c.state)).font(.system(size: 20)).foregroundStyle(color(c.state))
                                .frame(width: 26)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(c.title).font(.system(size: 13, weight: .semibold))
                                Text(c.detail ?? stateText(c.state)).font(.system(size: 12)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if c.state != .on, let u = c.settingsURL, let url = URL(string: u) {
                                Button(L("sec.fix")) { NSWorkspace.shared.open(url) }
                            }
                        }
                        .padding(.vertical, 12)
                        .padding(.horizontal, 14)
                        Divider()
                    }
                }
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.secondary.opacity(0.2)))
            }
            .padding(24)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(L("nav.security"))
        .onAppear { posture.refresh() }
    }

    private func icon(_ s: PostureCheck.State) -> String {
        switch s {
        case .on: return "checkmark.shield.fill"
        case .off: return "xmark.shield.fill"
        case .warn: return "exclamationmark.shield.fill"
        case .unknown: return "questionmark.circle"
        }
    }
    private func color(_ s: PostureCheck.State) -> Color {
        switch s {
        case .on: return .green
        case .off: return .red
        case .warn: return .orange
        case .unknown: return .secondary
        }
    }
    private func stateText(_ s: PostureCheck.State) -> String {
        switch s {
        case .on: return L("sec.on")
        case .off: return L("sec.off")
        case .warn, .unknown: return L("sec.unknown")
        }
    }
}

// MARK: - İndirilenler

struct DownloadsView: View {
    @EnvironmentObject var guardian: DownloadGuard
    @EnvironmentObject var center: ThreatCenter
    @State private var selection: String?

    var body: some View {
        VStack(spacing: 0) {
            if guardian.needsFullDisk {
                ContentUnavailableView {
                    Label(L("fda.one.title"), systemImage: "lock.shield")
                } description: {
                    Text(L("fda.one.body"))
                } actions: {
                    Button(L("fda.open")) { FullDisk.openSettings() }.buttonStyle(.borderedProminent)
                }
            } else if guardian.items.isEmpty {
                ContentUnavailableView(L("nav.downloads"), systemImage: "arrow.down.circle",
                                       description: Text(L("dl.empty")))
            } else {
                List(guardian.items, selection: $selection) { i in
                    HStack(spacing: 12) {
                        AppIcon(name: i.name, risk: i.risk, key: i.path, size: 34)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 6) {
                                Text(i.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                                Text(PathUtil.abbreviate(PathUtil.parentDir(i.path)))
                                    .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                            }
                            HStack(spacing: 6) {
                                Label(i.accepted == false ? L("dl.rejected") : (i.accepted == true ? L("dl.accepted") : "—"),
                                      systemImage: i.accepted == false ? "xmark.octagon" : "checkmark.seal")
                                    .foregroundStyle(i.accepted == false ? Color.red : Color.green)
                                Text("·")
                                Text(i.source ?? L("dl.notNotarized"))
                                Text("·")
                                Text(i.quarantined ? L("dl.quarantined") : L("dl.notQuarantined"))
                                    .foregroundStyle(i.quarantined ? Color.secondary : Color.orange)
                            }
                            .font(.system(size: 11.5))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        }
                        Spacer()
                        Text(Fmt.relativeDay.string(from: i.date)).font(.system(size: 11)).foregroundStyle(.secondary)
                        if i.risk >= .caution { RiskTag(i.risk) }
                        Menu {
                            Button(L("action.showInFinder")) { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: i.path)]) }
                            Button(L("action.virustotal")) { Lookup.virusTotal(path: i.path) }
                            Divider()
                            Button(L("uninstall.confirm"), role: .destructive) {
                                NSWorkspace.shared.recycle([URL(fileURLWithPath: i.path)]) { _, _ in
                                    DispatchQueue.main.async { guardian.scan() }
                                }
                            }
                        } label: { Image(systemName: "ellipsis.circle") }
                            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                    }
                    .padding(.vertical, 4)
                    .tag(i.id)
                }
                .listStyle(.inset)
            }
        }
        .navigationTitle(L("nav.downloads"))
        .navigationSubtitle(L("dl.subtitle"))
        .onAppear { guardian.scan(); applyFocus() }
        .onChange(of: center.navToken) { applyFocus() }
    }

    private func applyFocus() {
        if case .download(let p) = center.navFocus { selection = p }
    }
}

// MARK: - Ağ

struct NetworkView: View {
    @EnvironmentObject var net: NetworkMonitor
    @EnvironmentObject var center: ThreatCenter
    @ObservedObject private var blocks = BlockList.shared
    @State private var selection: String?
    @State private var onlyRisky = false
    @State private var sortOrder = [KeyPathComparator(\ConnRow.riskSort, order: .reverse)]

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Chip(title: L("filter.all"), selected: !onlyRisky) { onlyRisky = false }
                Chip(title: L("proc.filter.suspicious"), selected: onlyRisky) { onlyRisky = true }
                Spacer()
                Text(RootBridge.shared.active ? L("net.allVisible") : L("net.onlyOwn"))
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            Divider()
            HStack(spacing: 0) {
                Table(rows, selection: $selection, sortOrder: $sortOrder) {
                    TableColumn(L("net.process"), value: \.name) { c in
                        HStack(spacing: 8) {
                            AppIcon(name: c.name, risk: c.risk, key: c.path.map { PathUtil.appBundle($0) ?? $0 }, size: 18)
                            Text(c.name).lineLimit(1)
                        }
                    }
                    .width(min: 140, ideal: 180)
                    TableColumn(L("net.proto"), value: \.proto).width(50)
                    TableColumn(L("net.local"), value: \.local) { Text($0.local).font(.system(size: 11.5, design: .monospaced)) }
                    TableColumn(L("net.remote"), value: \.remoteSort) { c in
                        Text(c.remote ?? "—").font(.system(size: 11.5, design: .monospaced))
                    }
                    TableColumn(L("net.state"), value: \.state) { c in
                        Text(c.state.contains("LISTEN") ? L("net.listening") : c.state).font(.system(size: 11.5))
                    }
                    .width(min: 70, ideal: 100)
                    TableColumn(L("col.risk"), value: \.riskSort) { c in if c.risk >= .caution { RiskTag(c.risk) } }
                        .width(86)
                }
                if let c = net.rows.first(where: { $0.id == selection }) {
                    Divider()
                    VStack(alignment: .leading, spacing: 10) {
                        if !c.rules.isEmpty {
                            Label("\(c.risk.label): \(L("alert.network"))", systemImage: "exclamationmark.triangle")
                                .font(.system(size: 13, weight: .bold)).foregroundStyle(c.risk.color)
                        }
                        ForEach(Array(zip(c.rules, c.ruleArgs)), id: \.0) { r, a in
                            Text("• " + (a.isEmpty ? L(r) : L(r, a))).font(.system(size: 12))
                        }
                        Text("\(c.name) (pid \(String(c.pid)))").font(.system(size: 12, design: .monospaced))
                        Text(procSignatureText(c.signature, team: nil)).font(.system(size: 12)).foregroundStyle(.secondary)
                        if let p = c.path {
                            Button(L("action.virustotal")) { Lookup.virusTotal(path: PathUtil.appBundle(p) ?? p) }
                        }
                        if let r = c.remote { BlockButton(ip: BlockList.host(of: r)) }
                        Spacer()
                    }
                    .padding(16)
                    .frame(width: 300, alignment: .leading)
                }
            }
        }
        .navigationTitle(L("nav.network"))
        .onAppear { net.visible = true; net.refresh(); applyFocus() }
        .onDisappear { net.visible = false }
        .onChange(of: center.navToken) { applyFocus() }
    }

    private var rows: [ConnRow] {
        (onlyRisky ? net.rows.filter { $0.risk >= .caution } : net.rows).sorted(using: sortOrder)
    }

    private func applyFocus() {
        if case .connection(let id) = center.navFocus { selection = id; onlyRisky = false }
    }
}

// MARK: - Mikrofon ve kamera (canlı)

struct MediaLiveCard: View {
    @EnvironmentObject var media: MediaMonitor

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: media.micUsers.isEmpty ? "mic.slash" : "mic.fill")
                    .foregroundStyle(media.micUsers.isEmpty ? Color.secondary : Color.orange)
                Text(media.micUsers.isEmpty ? L("media.micIdle")
                     : L("media.micInUse", media.micUsers.map(\.name).joined(separator: ", ")))
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
                Image(systemName: media.cameraOn ? "video.fill" : "video.slash")
                    .foregroundStyle(media.cameraOn ? Color.green : Color.secondary)
                Text(media.cameraOn ? L("media.cameraOn") : L("media.cameraOff")).font(.system(size: 12))
            }
            if !media.history.isEmpty {
                Text(L("media.history").uppercased(with: .current))
                    .font(.system(size: 10.5, weight: .semibold)).foregroundStyle(.secondary)
                ForEach(media.history.prefix(5)) { s in
                    HStack(spacing: 8) {
                        Image(systemName: s.mic ? "mic" : "video").frame(width: 16).foregroundStyle(.secondary)
                        Text(s.name).font(.system(size: 12, weight: .medium))
                        Spacer()
                        Text(Fmt.time.string(from: s.start) + " – " + (s.end.map { Fmt.time.string(from: $0) } ?? L("media.now")))
                            .font(.system(size: 11.5).monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.secondary.opacity(0.2)))
        .padding(.horizontal, 16)
        .padding(.top, 12)
    }
}


/// "Bu sunucuyu engelle" — yönetici modu gerekir (kuralları root yardımcı uygular).
struct BlockButton: View {
    let ip: String
    @ObservedObject private var blocks = BlockList.shared
    @ObservedObject private var root = RootBridge.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if BlockList.isIP(ip) {
                Button(blocks.contains(ip) ? L("block.remove") : L("block.add", ip)) { blocks.toggle(ip) }
                    .tint(blocks.contains(ip) ? nil : .red)
                    .disabled(!root.active && !blocks.contains(ip))
                if !root.active {
                    Text(L("block.needsRoot")).font(.system(size: 10.5)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else if blocks.contains(ip) {
                    Text(L("block.active")).font(.system(size: 10.5)).foregroundStyle(.red)
                }
            }
        }
    }
}
