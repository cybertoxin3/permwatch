import SwiftUI

@main
struct PermwatchApp: App {
    @StateObject private var store = Store()

    var body: some Scene {
        WindowGroup(id: "main") {
            MainView()
                .environmentObject(store)
                .frame(minWidth: 1100, minHeight: 640)
                .onAppear { store.requestNotificationPermission() }
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
        } label: {
            Image(systemName: store.openAlerts > 0 ? "exclamationmark.shield.fill" : "checkmark.shield")
        }
        .menuBarExtraStyle(.window)
    }
}
