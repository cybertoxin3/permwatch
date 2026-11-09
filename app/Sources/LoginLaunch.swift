import AppKit
import ServiceManagement

/// "Mac açılınca başlat": korumalar (Dolandırıcılık Kalkanı, gerçek zamanlı koruma) yalnızca permwatch
/// çalışırken çalışır. Oturum açılırken başlatıldığında pencere açılmaz; permwatch menü çubuğunda bekler.
enum LoginLaunch {
    static let askedKey = "loginLaunchAsked"

    /// Önbellekli durum: SMAppService'e sormak bir sistem çağrısıdır; arayüz her yenilendiğinde yapılmamalı.
    nonisolated(unsafe) private static var cached: (value: Bool, at: Date)?
    static var isEnabled: Bool {
        if let c = cached, Date().timeIntervalSince(c.at) < 60 { return c.value }
        let v = SMAppService.mainApp.status == .enabled
        cached = (v, Date())
        return v
    }

    @discardableResult
    static func set(_ on: Bool) -> Bool {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            cached = nil
            return true
        } catch {
            cached = nil
            return false
        }
    }

    /// Bu açılış, oturum açma öğesi olarak mı yapıldı? (applicationWillFinishLaunching sırasında belirlenir)
    nonisolated(unsafe) static var launchedAtLogin = false
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        // Oturum açma öğesi olarak açılış: "aç" olayında keyAELaunchedAsLogInItem bulunur.
        let ev = NSAppleEventManager.shared().currentAppleEvent
        LoginLaunch.launchedAtLogin = (ev?.eventID == AEEventID(kAEOpenApplication)
            && ev?.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue == OSType(keyAELaunchedAsLogInItem))
            || ProcessInfo.processInfo.environment["PERMWATCH_START_HIDDEN"] != nil   // ölçüm/deneme için
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard LoginLaunch.launchedAtLogin else { return }
        // Sessiz başla: ana pencereyi kapat, menü çubuğunda kal.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            for w in NSApp.windows where w.isVisible && w.canBecomeMain { w.close() }
        }
    }
}
