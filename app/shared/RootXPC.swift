// Uygulama ↔ yönetici yardımcısı (permwatch-root) arasındaki XPC sözleşmesi. Hem uygulamaya hem yardımcıya derlenir.
//
// Neden: yardımcı eskiden kullanıcının klasöründeki dosyalara (capture.on, blocklist, vpn/want.json…) bakarak
// çalışıyordu. O klasöre bu kullanıcıyla çalışan HER program yazabildiği için, herhangi bir program şifre
// sormadan root'a paket yakalatabiliyor ya da VPN'i kendi sunucusuna yönlendirebiliyordu. Artık istekler
// yalnızca launchd'nin kayıtlı Mach servisi üzerinden gelir ve yardımcı bağlanan sürecin kod imzasını
// (aynı geliştirici + permwatch kimliği) ve oturum sahibi olduğunu doğrular.
import Foundation

@objc(PWRootControl) protocol RootControl {
    /// İstenen durumun tamamı (JSON). Uygulama birkaç saniyede bir ve her değişiklikte gönderir; yardımcı
    /// bunu "uygulama açık" sinyali olarak da kullanır.
    func sync(_ state: Data, reply: @escaping (Bool) -> Void)
}

enum RootXPC {
    static let rootService = "com.yusuf.permwatch.root.xpc"
    static let guardService = "com.yusuf.permwatch.guard.xpc"
    static let appIdentifier = "com.yusuf.permwatch"

    /// Bağlanmasına izin verilen istemci: permwatch uygulamasının kendisi, aynı geliştiricinin imzasıyla.
    static func clientRequirement(team: String) -> String {
        "identifier \"\(appIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
    }
}
