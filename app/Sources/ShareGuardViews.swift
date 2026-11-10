import AppKit
import SwiftUI

// MARK: - Ekranın üstündeki küçük gösterge: "Ekranın kaydediliyor: Zoom"

/// Ekranı kaydeden/paylaşan tanınmamış uygulama varken ekranın üst ortasında küçük bir gösterge.
/// İşi engellemez, tıklamaları yalnızca kendi üzerinde alır; bütün masaüstlerinde ve tam ekran uygulamalarda görünür.
@MainActor
final class CaptureHUD {
    static let shared = CaptureHUD()
    private var panel: NSPanel?
    private let model = HUDModel()

    func update(_ captures: [ScreenCapture]) {
        model.captures = captures
        if captures.isEmpty {
            panel?.orderOut(nil); panel = nil
            return
        }
        if panel == nil {
            let p = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 560, height: 72),
                            styleMask: [.nonactivatingPanel, .borderless], backing: .buffered, defer: false)
            p.isFloatingPanel = true
            p.level = .statusBar
            p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
            p.backgroundColor = .clear
            p.isOpaque = false
            p.hasShadow = true
            p.hidesOnDeactivate = false
            p.contentView = NSHostingView(rootView: CaptureHUDView().environmentObject(model).environmentObject(ShareGuard.shared))
            panel = p
        }
        guard let p = panel, let screen = NSScreen.main else { return }
        let size = p.contentView?.fittingSize ?? NSSize(width: 560, height: 72)
        let frame = screen.visibleFrame
        p.setFrame(NSRect(x: frame.midX - size.width / 2, y: frame.maxY - size.height - 8, width: size.width, height: size.height), display: true)
        p.orderFrontRegardless()
    }
}

@MainActor
final class HUDModel: ObservableObject {
    @Published var captures: [ScreenCapture] = []
}

struct CaptureHUDView: View {
    @EnvironmentObject var model: HUDModel
    @EnvironmentObject var guardian: ShareGuard

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(.red).frame(width: 10, height: 10)
                .overlay(Circle().stroke(.red.opacity(0.4), lineWidth: 4).scaleEffect(1.6))
            VStack(alignment: .leading, spacing: 1) {
                Text(L("sg.hud.title", model.captures.map(\.name).joined(separator: ", ")))
                    .font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text(L("sg.hud.hint")).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button(L("sg.known")) { guardian.acknowledge(model.captures.map(\.key), always: false) }
                .controlSize(.small)
            Button(L("sg.stop")) { guardian.stopSharing(model.captures.map(\.key)) }
                .controlSize(.small).tint(.red)
            Button {
                NSApp.activate(ignoringOtherApps: true)
                ThreatCenter.shared.navigate(section: .shield)
            } label: { Image(systemName: "ellipsis.circle") }
                .buttonStyle(.borderless).help(L("sg.openPage"))
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .frame(width: 560)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.red.opacity(0.35)))
    }
}

// MARK: - Bilgi girişi uyarısı (ekranı kaplar)

@MainActor
final class ShareAlertController {
    static let shared = ShareAlertController()
    private var windows: [NSWindow] = []
    let model = ShareAlertModel()

    func show(_ g: ShareGuard, demo: Bool = false) {
        model.demo = demo
        if !windows.isEmpty { return }
        model.stage = .alert
        model.wifiOff = false
        let screens = ShareGuard.testMode ? [NSScreen.main].compactMap { $0 } : NSScreen.screens
        for (i, screen) in screens.enumerated() {
            let w = NSWindow(contentRect: screen.frame, styleMask: [.borderless], backing: .buffered, defer: false, screen: screen)
            w.isReleasedWhenClosed = false
            w.backgroundColor = .clear
            w.isOpaque = false
            if !ShareGuard.testMode {
                w.level = .screenSaver
                w.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
            }
            w.contentView = NSHostingView(rootView: ShareAlertView(primary: i == 0).environmentObject(g).environmentObject(model))
            w.setFrame(screen.frame, display: true)
            w.makeKeyAndOrderFront(nil)
            windows.append(w)
        }
        NSApp.activate(ignoringOtherApps: true)
        if ShareGuard.testMode, !demo {
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) { g.stopSharing(); self.showReport() }
        }
    }

    func showReport() {
        guard !windows.isEmpty else { return }
        model.stage = .report
        for w in windows.dropFirst() { w.orderOut(nil) }
        windows = Array(windows.prefix(1))
    }

    func hide() {
        for w in windows { w.orderOut(nil) }
        windows = []
        model.stage = .alert
        model.demo = false
    }
}

@MainActor
final class ShareAlertModel: ObservableObject {
    enum Stage { case alert, report }
    @Published var stage: Stage = .alert
    @Published var demo = false
    @Published var wifiOff = false
}

struct ShareAlertView: View {
    let primary: Bool
    var scrollable = true
    @EnvironmentObject var g: ShareGuard
    @EnvironmentObject var model: ShareAlertModel

    var body: some View {
        ZStack {
            // Ekranı hafifçe karartır: yazmaya devam etmeden önce kartı görmek için yeterli.
            Color.black.opacity(0.4).ignoresSafeArea()
            if primary {
                if scrollable {
                    ScrollView { card.padding(40).frame(maxWidth: .infinity, minHeight: NSScreen.main?.frame.height ?? 800) }
                } else {
                    card.padding(40)
                }
            }
        }
    }

    private var card: some View {
        VStack(spacing: 18) {
            if model.demo {
                Text(L("sg.demoBanner")).font(.system(size: 11.5, weight: .semibold)).padding(.horizontal, 10).padding(.vertical, 4)
                    .background(Color.yellow.opacity(0.85), in: Capsule()).foregroundStyle(.black)
            }
            if model.stage == .alert { alert } else { report }
        }
        .padding(28)
        .frame(width: 520)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Color.primary.opacity(0.08)))
        .shadow(color: .black.opacity(0.35), radius: 30, y: 10)
    }

    private var apps: [ScreenCapture] {
        model.demo ? [ScreenCapture(key: "demo", name: "Zoom", path: nil, pids: [], start: Date().addingTimeInterval(-300), kind: .capture)]
                   : g.unacknowledged
    }

    private var what: [String] { model.demo ? [L("sg.trigger.password", "Safari")] : (g.current?.sites ?? []) }

    private var alert: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 40)).foregroundStyle(.orange)
            Text(L("sg.alert.title")).font(.system(size: 19, weight: .bold)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(apps) { c in
                    Label(L("sg.alert.sharing", c.name, Fmt.relative(min(c.start, Date().addingTimeInterval(-1)))), systemImage: "record.circle")
                        .font(.system(size: 13, weight: .semibold))
                }
                ForEach(what, id: \.self) { w in Label(w, systemImage: "key.fill").font(.system(size: 13)).foregroundStyle(.secondary) }
            }
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            Text(L("sg.alert.body")).font(.system(size: 13)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 8) {
                Button { if model.demo { model.stage = .report } else { g.stopSharing(); ShareAlertController.shared.showReport() } } label: {
                    Text(apps.count == 1 ? L("sg.stopApp", apps[0].name) : L("sg.stop")).frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent).controlSize(.large).tint(.red)
                .keyboardShortcut(.defaultAction)
                Button {
                    if model.demo { model.wifiOff = true } else { model.wifiOff = g.cutInternet() }
                } label: {
                    Label(model.wifiOff ? L("sg.wifiDone") : L("sg.cutInternet"), systemImage: "wifi.slash").frame(maxWidth: .infinity)
                }
                .controlSize(.large).disabled(model.wifiOff)
            }
            Divider()
            VStack(spacing: 8) {
                Text(L("sg.knownTitle")).font(.system(size: 12)).foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    Button(L("sg.known")) {
                        if model.demo { ShareAlertController.shared.hide() } else { g.acknowledge(apps.map(\.key), always: false) }
                    }
                    Button(L("sg.trustAlways")) {
                        if model.demo { ShareAlertController.shared.hide() } else { g.acknowledge(apps.map(\.key), always: true) }
                    }
                }
                if apps.contains(where: \.isRemoteControl) {
                    Text(L("sg.authHint")).font(.system(size: 11)).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private var report: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "checkmark.circle.fill").font(.system(size: 34)).foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 2) {
                    Text(L("sg.report.title")).font(.system(size: 19, weight: .bold))
                    Text(L("sg.report.subtitle")).font(.system(size: 13)).foregroundStyle(.secondary)
                }
            }
            let actions = model.demo ? [L("sg.act.closed", "Zoom")] : g.lastActions
            if !actions.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(L("sg.report.done")).font(.system(size: 13, weight: .semibold))
                    ForEach(actions, id: \.self) { a in Label(a, systemImage: "checkmark").font(.system(size: 12.5)) }
                }
            }
            ShareStepsView()
            HStack {
                Spacer()
                Button(L("sg.report.close")) {
                    ShareAlertController.shared.hide()
                    if !model.demo { NSApp.activate(ignoringOtherApps: true); ThreatCenter.shared.navigate(section: .shield) }
                }
                .buttonStyle(.borderedProminent).controlSize(.large)
            }
        }
    }
}

/// Paylaşım sırasında bilgi girildiyse yapılacaklar.
struct ShareStepsView: View {
    var large = false

    var body: some View {
        VStack(alignment: .leading, spacing: large ? 12 : 8) {
            Text(L("sg.steps.title")).font(.system(size: large ? 18 : 13, weight: .bold))
            ForEach(1...4, id: \.self) { i in
                HStack(alignment: .top, spacing: 10) {
                    Text("\(i)").font(.system(size: large ? 15 : 12, weight: .bold)).frame(width: large ? 26 : 20, height: large ? 26 : 20)
                        .background(Circle().fill(Color.accentColor.opacity(large ? 0.9 : 0.2)))
                    Text(L("sg.step\(i)")).font(.system(size: large ? 15 : 12.5)).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

// MARK: - Kenar çubuğundaki sayfa

struct ShareGuardView: View {
    @EnvironmentObject var g: ShareGuard
    @EnvironmentObject var root: RootBridge
    @State private var expanded: String?
    @State private var confirmDelete: ShareIncident?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                nowCard
                howItWorks
                settings
                if !g.trusted.isEmpty { trustedList }
                if !g.incidents.isEmpty { history }
            }
            .padding(24)
            .frame(maxWidth: 860, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(L("nav.shield"))
        .confirmationDialog(L("sg.deleteTitle"), isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })) {
            Button(L("q.delete"), role: .destructive) { if let i = confirmDelete { g.deleteIncident(i) }; confirmDelete = nil }
            Button(L("confirm.cancel"), role: .cancel) { confirmDelete = nil }
        }
    }

    private var header: some View {
        HStack(spacing: 18) {
            ZStack {
                Circle().fill((g.enabled ? Color.green : Color.secondary).opacity(0.15)).frame(width: 74, height: 74)
                Image(systemName: "rectangle.dashed.badge.record").font(.system(size: 30)).foregroundStyle(g.enabled ? .green : .secondary)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(L("nav.shield")).font(.system(size: 22, weight: .bold))
                Text(g.enabled ? L("sg.statusOn") : L("sg.statusOff")).font(.system(size: 13)).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("", isOn: $g.enabled).toggleStyle(.switch).labelsHidden()
        }
    }

    private var nowCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L("sg.nowTitle")).font(.system(size: 14, weight: .bold))
            if g.captures.isEmpty {
                Label(L("sg.noSharing"), systemImage: "checkmark.circle").font(.system(size: 13)).foregroundStyle(.secondary)
            }
            ForEach(g.captures) { c in
                HStack(spacing: 12) {
                    AppIcon(name: c.name, risk: .normal, key: c.path ?? c.name, size: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(c.name).font(.system(size: 13, weight: .semibold))
                        Text(L(c.isRemoteControl ? "sg.kind.remote" : "sg.kind.capture") + " · " + Fmt.relative(min(c.start, Date().addingTimeInterval(-1))))
                            .font(.system(size: 11.5)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if g.trusted[c.key] != nil || g.acknowledged.contains(c.key) {
                        Label(L("sg.acknowledged"), systemImage: "checkmark").font(.system(size: 12)).foregroundStyle(.green)
                    } else {
                        Button(L("sg.known")) { g.acknowledge([c.key], always: false) }.controlSize(.small)
                    }
                    Button(L("sg.stop")) { g.stopSharing([c.key]) }.controlSize(.small)
                }
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    private var howItWorks: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L("sg.howTitle")).font(.system(size: 14, weight: .bold))
            Text(L("sg.howBody")).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
            ForEach(["sg.what1", "sg.what2", "sg.what3"], id: \.self) { k in
                Label(L(k), systemImage: "checkmark.circle").font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button { ShareAlertController.shared.show(g, demo: true) } label: { Label(L("sg.tryAlert"), systemImage: "play.circle") }
                Text(L("sg.tryHint")).font(.system(size: 11.5)).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    private var settings: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "building.columns").foregroundStyle(.secondary).frame(width: 22)
                VStack(alignment: .leading, spacing: 4) {
                    Text(L("sg.sitesTitle")).font(.system(size: 13, weight: .semibold))
                    Text(root.data?.dnsActive == true ? L("sg.sitesDNSOn") : L("sg.sitesDNSOff"))
                        .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 10) {
                        Button(L("sg.browserPermission")) { BrowserTab.requestPermissions() }.controlSize(.small)
                        Text(L("sg.browserHint")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Toggle(L("sg.speak"), isOn: $g.speak).font(.system(size: 13)).padding(.leading, 34)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    private var trustedList: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("sg.trustedTitle")).font(.system(size: 14, weight: .bold))
            Text(L("sg.trustedHint")).font(.system(size: 11.5)).foregroundStyle(.secondary)
            ForEach(g.trusted.sorted { $0.value < $1.value }, id: \.key) { key, name in
                HStack {
                    Text(name).font(.system(size: 13))
                    Spacer()
                    Button(L("q.delete")) { g.untrust(key) }.controlSize(.small)
                }
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    private var history: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L("sg.historyTitle")).font(.system(size: 14, weight: .bold))
            ForEach(g.incidents) { i in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: i.outcome == .stopped ? "xmark.circle.fill" : (i.outcome == .acknowledged ? "person.fill.checkmark" : "exclamationmark.triangle.fill"))
                            .foregroundStyle(i.outcome == .stopped ? .green : (i.outcome == .acknowledged ? .secondary : .orange))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(i.apps.joined(separator: ", ")).font(.system(size: 13, weight: .semibold))
                            Text("\(i.date.formatted(date: .abbreviated, time: .shortened)) · \(L("sg.outcome.\(i.outcome.rawValue)"))")
                                .font(.system(size: 11.5)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(expanded == i.id ? L("sg.hideReport") : L("sg.openReport")) { expanded = expanded == i.id ? nil : i.id }.controlSize(.small)
                        Button { confirmDelete = i } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                    }
                    ForEach(i.sites, id: \.self) { Text("• " + $0).font(.system(size: 12)).foregroundStyle(.orange) }
                    if expanded == i.id { ShareReportView(incident: i) }
                }
                .padding(12)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }
}

/// Bir uyarının raporu: yapılanlar, o sırada Mac'te değişenler, yapılacaklar.
struct ShareReportView: View {
    let incident: ShareIncident
    @State private var changes: [String]?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !incident.actions.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(L("sg.report.done")).font(.system(size: 12.5, weight: .semibold))
                    ForEach(incident.actions, id: \.self) { Label($0, systemImage: "checkmark").font(.system(size: 12)) }
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(L("sg.changesTitle")).font(.system(size: 12.5, weight: .semibold))
                if let c = changes {
                    if c.isEmpty { Text(L("sg.noChanges")).font(.system(size: 12)).foregroundStyle(.secondary) }
                    ForEach(c, id: \.self) { Label($0, systemImage: "exclamationmark.circle").font(.system(size: 12)).foregroundStyle(.orange) }
                } else {
                    ProgressView().controlSize(.small)
                }
                Text(L("sg.changesHint")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            ShareStepsView()
        }
        .padding(.top, 4)
        .task {
            let since = incident.date.addingTimeInterval(-15 * 60)
            changes = await Task.detached { ShareGuard.changes(since: since) }.value
        }
    }
}
