import SwiftUI

@main
struct PermwatchApp: App {
    @StateObject private var store = Store()
    @StateObject private var monitor = ProcessMonitor()
    @StateObject private var posture = SecurityPosture()
    @StateObject private var downloads = DownloadGuard()
    @StateObject private var media = MediaMonitor()
    @StateObject private var network = NetworkMonitor()
    @StateObject private var packets = PacketMonitor()
    @StateObject private var advisor = Advisor()
    @StateObject private var terminals = TerminalStore()
    @StateObject private var center = ThreatCenter.shared
    @AppStorage(Theme.storageKey) private var theme: Theme = .system

    init() {
        // Son oturumda pencere kapalıyken çıkıldıysa macOS açılışta pencere getirmiyor;
        // permwatch her açılışta ana pencereyle başlasın.
        UserDefaults.standard.register(defaults: ["ApplePersistenceIgnoreState": true])
    }

    var body: some Scene {
        WindowGroup(id: "main") {
            MainView()
                .environmentObject(store)
                .environmentObject(monitor)
                .environmentObject(posture)
                .environmentObject(downloads)
                .environmentObject(media)
                .environmentObject(network)
                .environmentObject(packets)
                .environmentObject(advisor)
                .environmentObject(terminals)
                .environmentObject(RootBridge.shared)
                .environmentObject(center)
                .frame(minWidth: 1100, minHeight: 640)
                .preferredColorScheme(theme.colorScheme)
                .onAppear {
                    theme.apply()
                    store.requestNotificationPermission()
                }
        }
        .defaultSize(width: 1360, height: 820)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button(L("menu.scan")) { store.useSystem() }
                    .keyboardShortcut("r")
                Button(L("menu.openFile")) { store.chooseFile() }
                    .keyboardShortcut("o")
                Button(L("menu.loadDemo")) { store.loadDemo() }
            }
        }

        MenuBarExtra {
            MenuBarPanel()
                .environmentObject(store)
                .environmentObject(media)
                .environmentObject(center)
                .preferredColorScheme(theme.colorScheme)
        } label: {
            Image(systemName: store.openAlerts > 0 ? "exclamationmark.shield.fill" : "checkmark.shield")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(downloads)
                .environmentObject(RootBridge.shared)
                .environmentObject(packets)
                .preferredColorScheme(theme.colorScheme)
        }
    }
}
