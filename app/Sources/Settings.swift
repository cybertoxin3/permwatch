import ServiceManagement
import AppKit
import SwiftUI

/// Görünüm teması. "system" macOS ayarını izler.
enum Theme: String, CaseIterable, Identifiable {
    case system, light, dark
    var id: String { rawValue }

    static let storageKey = "theme"

    var title: String {
        switch self {
        case .system: return L("theme.system")
        case .light: return L("theme.light")
        case .dark: return L("theme.dark")
        }
    }

    var symbol: String {
        switch self {
        case .system: return "circle.lefthalf.filled"
        case .light: return "sun.max"
        case .dark: return "moon"
        }
    }

    var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    /// NSApp düzeyinde uygulanır: başlık çubuğu, menüler, açılır pencereler ve
    /// kenar çubuğunun yarı saydam arka planı da temayı izler.
    func apply() {
        switch self {
        case .system: NSApp.appearance = nil
        case .light: NSApp.appearance = NSAppearance(named: .aqua)
        case .dark: NSApp.appearance = NSAppearance(named: .darkAqua)
        }
    }

    static var current: Theme {
        Theme(rawValue: UserDefaults.standard.string(forKey: storageKey) ?? "") ?? .system
    }
}

struct SettingsView: View {
    /// true: ana pencerenin içinde (kenar çubuğundan); false: macOS'un Ayarlar penceresinde.
    var embedded = false
    @AppStorage(Theme.storageKey) private var theme: Theme = .system
    @EnvironmentObject var downloads: DownloadGuard
    @EnvironmentObject var root: RootBridge
    @EnvironmentObject var packets: PacketMonitor
    @EnvironmentObject var updates: UpdateChecker
    @EnvironmentObject var intel: ThreatIntel
    @EnvironmentObject var realtime: RealtimeGuard
    @ObservedObject private var guardSvc = GuardService.shared
    @ObservedObject private var scam = ScamShield.shared
    @State private var loginOn = LoginLaunch.isEnabled
    @ObservedObject private var blocks = BlockList.shared
    /// Paket yakalama ve engellenen sunucular yalnızca gelişmiş modda.
    @AppStorage(Sidebar.advancedKey) private var advanced = false

    var body: some View {
        Form {
            Section {
                Picker(L("settings.appearance"), selection: $theme) {
                    ForEach(Theme.allCases) { t in
                        Label(t.title, systemImage: t.symbol).tag(t)
                    }
                }
                .pickerStyle(.radioGroup)
            }

            Section {
                Toggle(L("login.setting"), isOn: Binding(get: { loginOn }, set: { if LoginLaunch.set($0) { loginOn = $0 } }))
                Text(L("login.settingDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle(L("nav.shield"), isOn: $scam.enabled)
                Text(L("scam.settingDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle(L("rt.setting"), isOn: $realtime.enabled)
                Text(L("rt.settingDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if guardSvc.available { GuardRow() }
                Toggle(L("ransom.setting"), isOn: $realtime.ransomEnabled)
                Text(L("ransom.settingDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle(L("intel.setting"), isOn: $intel.enabled)
                Text(L("intel.settingDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if intel.enabled {
                    HStack {
                        Text(intel.lastUpdate.map { L("intel.status", intel.domainCount.formatted(), intel.ipCount.formatted(), Fmt.relative($0)) }
                             ?? L("intel.never"))
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                        Spacer()
                        if intel.updating { ProgressView().controlSize(.small) } else { Button(L("intel.updateNow")) { intel.update(force: true) } }
                    }
                    if let e = intel.error { Text(e).font(.system(size: 11)).foregroundStyle(.red) }
                }
            } header: {
                Text(L("protect.settings"))
            }

            Section {
                HStack {
                    Circle().fill(root.active ? Color.green : Color.secondary).frame(width: 8, height: 8)
                    Text(root.active ? L("settings.rootActive") : L("settings.rootInactive"))
                    Spacer()
                    if root.starting {
                        ProgressView().controlSize(.small)
                    } else if root.active || root.enabledPreference {
                        Button(L("settings.rootDisable")) { root.disable() }
                    } else {
                        Button(L("settings.rootEnable")) { root.enable() }
                    }
                }
                if root.waitingApproval {
                    Text(L("settings.rootApprove")).font(.system(size: 11)).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let e = root.lastError {
                    Text(L("settings.rootFailed", e)).font(.system(size: 11)).foregroundStyle(.red)
                }
            } header: {
                Text(L("settings.root"))
            } footer: {
                Text(L("settings.rootDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section {
                ForEach(downloads.folders, id: \.path) { f in
                    HStack {
                        Image(systemName: "folder").foregroundStyle(.secondary)
                        Text(PathUtil.abbreviate(f.path)).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        if f.source.isEmpty {
                            Button { downloads.removeFolder(f.path) } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.borderless)
                        } else {
                            Text(f.source).font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                    }
                }
                Button(L("settings.addFolder")) {
                    let p = NSOpenPanel()
                    p.canChooseDirectories = true
                    p.canChooseFiles = false
                    if p.runModal() == .OK, let u = p.url { downloads.addFolder(u.path) }
                }
            } header: {
                Text(L("settings.downloads"))
            } footer: {
                Text(L("settings.downloadsDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
            }

            if advanced {
                Section {
                    HStack {
                        Image(systemName: "folder").foregroundStyle(.secondary)
                        Text(packets.saveFolder.map(PathUtil.abbreviate) ?? L("settings.captureOff"))
                            .lineLimit(1).truncationMode(.middle)
                            .foregroundStyle(packets.saveFolder == nil ? .secondary : .primary)
                        Spacer()
                        if packets.saveFolder != nil {
                            Button { packets.saveFolder = nil } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                        }
                        Button(L("pkt.chooseFolder")) { packets.chooseSaveFolder() }
                    }
                } header: {
                    Text(L("settings.captureFolder"))
                } footer: {
                    Text(L("settings.captureFolderDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            // Engellenen sunucular: basit modda da, en az bir engel varsa görünür (kaldırabilmek için).
            if advanced || !blocks.ips.isEmpty {
                Section {
                    if blocks.ips.isEmpty {
                        Text(L("block.none")).foregroundStyle(.secondary)
                    }
                    ForEach(blocks.ips, id: \.self) { ip in
                        HStack {
                            Image(systemName: "nosign").foregroundStyle(.red)
                            Text(ip).font(.system(size: 12, design: .monospaced))
                            Spacer()
                            Button { blocks.remove(ip) } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                        }
                    }
                    if let e = root.data?.blockError { Text(e).font(.system(size: 11)).foregroundStyle(.red) }
                } header: {
                    Text(L("block.settings"))
                } footer: {
                    Text(L("block.settingsDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

            }
            Section {
                Toggle(L("upd.setting"), isOn: $updates.enabled)
                UpdateStatusRow()
                Text(L("upd.settingDesc", UpdateChecker.current)).font(.system(size: 11)).foregroundStyle(.secondary)
            }

            Section {
                HStack {
                    Text(L("report.settingDesc")).font(.system(size: 11.5)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    ReportMenuButton()
                }
            } header: {
                Text(L("report.title"))
            }

            Section {
                HStack {
                    Text(L("donate.desc")).font(.system(size: 11.5)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Link(L("donate.button"), destination: URL(string: "https://github.com/cybertoxin3/permwatch#-buy-me-a-coffee")!)
                }
            } header: {
                Text(L("donate.title"))
            }

        }
        .formStyle(.grouped)
        .frame(width: embedded ? nil : 520)
        .frame(maxWidth: embedded ? 680 : nil)
        .onChange(of: theme) { _, new in new.apply() }
    }
}

/// Çalıştırmadan önce engelleme (Endpoint Security) satırı: Ayarlar ve Tarama ekranında.
struct GuardRow: View {
    @ObservedObject private var svc = GuardService.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Circle().fill(svc.state == .active ? Color.green : (svc.state == .off ? Color.secondary : Color.orange))
                    .frame(width: 8, height: 8)
                Text(L("guard.setting")).font(.system(size: 13))
                Spacer()
                if svc.state == .off { Button(L("guard.enable")) { svc.enable() } }
                else { Button(L("guard.disable")) { svc.disable() } }
            }
            Text(statusText).font(.system(size: 11)).foregroundStyle(svc.state == .active ? Color.secondary : Color.orange)
                .fixedSize(horizontal: false, vertical: true)
            if svc.state == .needsFullDisk { Button(L("guard.fdaButton")) { svc.showForFullDisk() }.controlSize(.small) }
            if svc.state == .needsApproval { Button(L("guard.approveButton")) { SMAppService.openSystemSettingsLoginItems() }.controlSize(.small) }
            Text(L("guard.settingDesc")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private var statusText: String {
        switch svc.state {
        case .unavailable, .off: return L("guard.off")
        case .needsApproval: return L("guard.needsApproval")
        case .needsFullDisk: return L("guard.needsFDA")
        case .starting: return L("guard.starting")
        case .active: return L("guard.active", svc.ruleCount.formatted(), svc.blocked.formatted())
        case .failed(let e): return L("guard.failed", e)
        }
    }
}
