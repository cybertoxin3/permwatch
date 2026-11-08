import SwiftUI

@main
struct PermwatchApp: App {
    @StateObject private var store = Store()
    @StateObject private var monitor = ProcessMonitor()
    @AppStorage(Theme.storageKey) private var theme: Theme = .system

    var body: some Scene {
        WindowGroup(id: "main") {
            MainView()
                .environmentObject(store)
                .environmentObject(monitor)
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
                .preferredColorScheme(theme.colorScheme)
        } label: {
            Image(systemName: store.openAlerts > 0 ? "exclamationmark.shield.fill" : "checkmark.shield")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .preferredColorScheme(theme.colorScheme)
        }
    }
}
