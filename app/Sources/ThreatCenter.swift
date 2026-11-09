import AppKit
import SwiftUI
import UserNotifications

/// Bir tehdidin uygulamada nereye götüreceği.
enum Focus: Equatable {
    case item(Int)
    case process(Int32)
    case download(String)
    case connection(String)
    case packet(Int)
    case media
}

struct Threat: Identifiable, Equatable {
    let id: String
    let risk: Risk
    let title: String
    let detail: String
    let iconKey: String?
    let section: SidebarItem
    let focus: Focus

    static func == (a: Threat, b: Threat) -> Bool { a.id == b.id }
}

/// Bütün izleyicilerden gelen tehditleri toplar; ekranın üstünde küçük bir pencerede
/// anında gösterir, bildirim gönderir ve "İncele" ile ilgili ayrıntıya götürür.
@MainActor
final class ThreatCenter: ObservableObject {
    static let shared = ThreatCenter()

    @Published private(set) var queue: [Threat] = []
    /// MainView bu iki değeri izleyip ilgili bölüme ve öğeye gider.
    @Published private(set) var navSection: SidebarItem?
    @Published private(set) var navFocus: Focus?
    @Published private(set) var navToken = 0

    var openMainWindow: (() -> Void)?

    private var seen = Set<String>()
    private var panel: NSPanel?
    private var hideWork: DispatchWorkItem?
    /// Açılış bitmeden pencere gösterilirse SwiftUI ana pencereyi hiç açmıyor;
    /// o yüzden açılış tamamlanana kadar tehditler sırada bekler.
    private var ready = false

    private init() {
        NotificationCenter.default.addObserver(forName: NSApplication.didFinishLaunchingNotification,
                                               object: nil, queue: .main) { [weak self] _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.ready = true
                    if !self.queue.isEmpty { self.showPanel() }
                }
            }
        }
    }

    /// Aynı tehdit (aynı kimlik) yalnızca bir kez gösterilir.
    func report(_ t: Threat) {
        guard !seen.contains(t.id) else { return }
        seen.insert(t.id)
        queue.removeAll { $0.id == t.id }
        queue.insert(t, at: 0)
        if queue.count > 20 { queue.removeLast(queue.count - 20) }
        if ProcessInfo.processInfo.environment["PERMWATCH_DEBUG"] != nil {
            FileHandle.standardError.write(Data("tehdit: \(t.id) | \(t.title) | \(t.detail)\n".utf8))
        }
        if ready { showPanel() }
        notify(t)
    }

    /// Açılışta zaten var olan bulguları "görüldü" say (açılışta pencere yağdırma).
    func markSeen(_ ids: [String]) { seen.formUnion(ids) }

    func open(_ t: Threat) {
        navSection = t.section
        navFocus = t.focus
        navToken += 1
        NSApp.activate(ignoringOtherApps: true)
        if let w = NSApp.windows.first(where: { $0.identifier?.rawValue.hasPrefix("main") == true && $0.isVisible }) {
            w.makeKeyAndOrderFront(nil)
        } else if let open = openMainWindow {
            open()
        } else {
            NSWorkspace.shared.open(Bundle.main.bundleURL)
        }
        dismiss(t)
    }

    /// Uygulama içinden bir bölüme git (Öneriler ekranındaki "İncele").
    func navigate(section: SidebarItem, focus: Focus? = nil) {
        navSection = section
        navFocus = focus
        navToken += 1
    }

    func dismiss(_ t: Threat) {
        queue.removeAll { $0.id == t.id }
        if queue.isEmpty { hidePanel() }
    }

    func dismissAll() {
        queue.removeAll()
        hidePanel()
    }

    // MARK: Üstteki küçük pencere

    private func showPanel() {
        let size = NSSize(width: 400, height: 132)
        if panel == nil {
            let p = NSPanel(contentRect: NSRect(origin: .zero, size: size),
                            styleMask: [.nonactivatingPanel, .borderless],
                            backing: .buffered, defer: false)
            p.level = .statusBar
            p.isFloatingPanel = true
            p.hidesOnDeactivate = false
            p.backgroundColor = .clear
            p.isOpaque = false
            p.hasShadow = true
            p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
            p.contentView = NSHostingView(rootView: ThreatHUD().environmentObject(self))
            panel = p
        }
        if let screen = NSScreen.main ?? NSScreen.screens.first {
            let f = screen.visibleFrame
            panel?.setFrameOrigin(NSPoint(x: f.midX - size.width / 2, y: f.maxY - size.height - 10))
        }
        panel?.alphaValue = 0
        panel?.orderFrontRegardless()
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.25
            panel?.animator().alphaValue = 1
        }
        hideWork?.cancel()
        let w = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated { self?.hidePanel() }
        }
        hideWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 25, execute: w)
    }

    private func hidePanel() {
        guard let p = panel else { return }
        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration = 0.2
            p.animator().alphaValue = 0
        }, completionHandler: { p.orderOut(nil) })
    }

    /// Dolandırıcılık Kalkanı: uzaktan oturum başladı.
    func notifyScam(tools: String) {
        let c = UNMutableNotificationContent()
        c.title = L("scam.notifyTitle")
        c.body = L("scam.notifyBody", tools)
        c.sound = .defaultCritical
        c.interruptionLevel = .timeSensitive
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "scam.\(Date().timeIntervalSince1970)", content: c, trigger: nil))
    }

    /// Güncelleme indirildi: kullanıcı başka bir uygulamadaysa da haberi olsun.
    func notifyUpdateReady(version: String) {
        let c = UNMutableNotificationContent()
        c.title = L("upd.notifyTitle", version)
        c.body = L("upd.notifyBody")
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "update.\(version)", content: c, trigger: nil))
    }

    private func notify(_ t: Threat) {
        let c = UNMutableNotificationContent()
        c.title = t.title
        c.body = t.detail
        c.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: t.id, content: c, trigger: nil))
    }
}

struct ThreatHUD: View {
    @EnvironmentObject var center: ThreatCenter

    var body: some View {
        Group {
            if let t = center.queue.first {
                HStack(alignment: .top, spacing: 12) {
                    ZStack(alignment: .bottomTrailing) {
                        AppIcon(name: t.title, risk: .normal, key: t.iconKey ?? Bundle.main.bundlePath, size: 44)
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 15))
                            .foregroundStyle(.white, t.risk.color)
                            .offset(x: 5, y: 5)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text("PERMWATCH").font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                            Spacer()
                            if center.queue.count > 1 {
                                Text(L("threat.more", center.queue.count - 1))
                                    .font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                            }
                            Button { center.dismissAll() } label: {
                                Image(systemName: "xmark").font(.system(size: 10, weight: .bold))
                            }
                            .buttonStyle(.plain).foregroundStyle(.secondary)
                        }
                        Text(t.title).font(.system(size: 13, weight: .bold)).foregroundStyle(t.risk.color).lineLimit(1)
                        Text(t.detail).font(.system(size: 12)).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 8) {
                            Button(L("threat.review")) { center.open(t) }
                                .buttonStyle(.borderedProminent).tint(t.risk.color)
                            Button(L("threat.dismiss")) { center.dismiss(t) }
                        }
                        .controlSize(.small)
                        .padding(.top, 4)
                    }
                }
                .padding(14)
                .frame(width: 400, alignment: .leading)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
                .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(t.risk.color.opacity(0.5), lineWidth: 1))
            }
        }
        .frame(width: 400, height: 132, alignment: .top)
    }
}
