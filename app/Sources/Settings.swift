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

    var body: some View {
        Form {
            Picker(L("settings.appearance"), selection: $theme) {
                ForEach(Theme.allCases) { t in
                    Label(t.title, systemImage: t.symbol).tag(t)
                }
            }
            .pickerStyle(.radioGroup)
        }
        .formStyle(.grouped)
        .frame(width: 420)
        .fixedSize()
        .onChange(of: theme) { _, new in new.apply() }
    }
}
