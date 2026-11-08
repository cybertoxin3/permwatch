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
    @AppStorage(Theme.storageKey) private var theme: Theme = .system
    @EnvironmentObject var downloads: DownloadGuard
    @EnvironmentObject var root: RootBridge

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
                if let e = root.lastError {
                    Text(L("settings.rootFailed", e)).font(.system(size: 11)).foregroundStyle(.red)
                }
            } header: {
                Text(L("settings.root"))
            } footer: {
                Text(L("settings.rootDesc")).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .onChange(of: theme) { _, new in new.apply() }
    }
}
