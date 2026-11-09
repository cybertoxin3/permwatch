import AppKit
import SwiftUI

// MARK: - Ekranı kaplayan uyarı

/// Uyarı pencereleri: her ekranı kaplar, bütün masaüstlerinde ve tam ekran uygulamaların üstünde görünür.
@MainActor
final class ScamAlertController {
    static let shared = ScamAlertController()
    private var windows: [NSWindow] = []
    private let model = ScamAlertModel()

    var isVisible: Bool { !windows.isEmpty }

    func show(_ shield: ScamShield, demo: Bool = false) {
        model.demo = demo
        if model.stage == .report && !demo { return }   // rapor ekranı açıkken yeniden uyarı gösterme
        if !windows.isEmpty { return }
        model.stage = .alert
        let screens = ScamShield.testMode ? [NSScreen.main].compactMap { $0 } : NSScreen.screens
        for (i, screen) in screens.enumerated() {
            let w = NSWindow(contentRect: screen.frame, styleMask: [.borderless], backing: .buffered, defer: false, screen: screen)
            w.isReleasedWhenClosed = false
            w.backgroundColor = .clear
            w.isOpaque = false
            w.hasShadow = false
            if !ScamShield.testMode {
                w.level = .screenSaver
                w.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
            }
            // Ana ekranda düğmeli tam uyarı, diğer ekranlarda yalnızca kırmızı perde ve kısa uyarı.
            w.contentView = NSHostingView(rootView: ScamAlertView(primary: i == 0).environmentObject(shield).environmentObject(model))
            w.setFrame(screen.frame, display: true)
            w.makeKeyAndOrderFront(nil)
            windows.append(w)
        }
        NSApp.activate(ignoringOtherApps: true)
        if ScamShield.testMode, !demo {
            FileHandle.standardError.write(Data("kalkan: uyarı gösterildi (\(shield.sessions.map(\.name)))\n".utf8))
            // Deneme: birkaç saniye sonra "Bağlantıyı Kes" seçilmiş gibi
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) { shield.disconnect() }
        }
    }

    /// Bağlantı kesildi: aynı pencerelerde "şimdi ne yapmalısın" ekranı.
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
final class ScamAlertModel: ObservableObject {
    enum Stage { case alert, report }
    @Published var stage: Stage = .alert
    @Published var demo = false
    @Published var wifiOff = false
}

struct ScamAlertView: View {
    let primary: Bool
    /// false: resim olarak çizilirken (ImageRenderer kaydırma görünümünü çizemez).
    var scrollable = true
    @EnvironmentObject var shield: ScamShield
    @EnvironmentObject var model: ScamAlertModel

    var body: some View {
        ZStack {
            (model.stage == .report ? Color(red: 0.05, green: 0.25, blue: 0.12) : Color(red: 0.45, green: 0.02, blue: 0.02))
                .opacity(0.96).ignoresSafeArea()
            if primary && !scrollable {
                VStack(spacing: 22) {
                    if model.demo {
                        Text(L("scam.demoBanner")).font(.system(size: 14, weight: .bold)).padding(.horizontal, 14).padding(.vertical, 6)
                            .background(.yellow, in: Capsule()).foregroundStyle(.black)
                    }
                    if model.stage == .alert { alert } else { report }
                }
                .padding(48)
                .frame(maxWidth: 900)
            } else if primary {
                ScrollView {
                    VStack(spacing: 22) {
                        if model.demo {
                            Text(L("scam.demoBanner")).font(.system(size: 14, weight: .bold)).padding(.horizontal, 14).padding(.vertical, 6)
                                .background(.yellow, in: Capsule()).foregroundStyle(.black)
                        }
                        if model.stage == .alert { alert } else { report }
                    }
                    .padding(48)
                    .frame(maxWidth: 900)
                    .frame(maxWidth: .infinity)
                }
            } else {
                VStack(spacing: 14) {
                    Image(systemName: "exclamationmark.octagon.fill").font(.system(size: 80))
                    Text(L("scam.alert.title")).font(.system(size: 34, weight: .heavy)).multilineTextAlignment(.center)
                }
                .foregroundStyle(.white).padding(40)
            }
        }
        .environment(\.colorScheme, .dark)
    }

    private var sessionLine: String {
        let names = model.demo ? "AnyDesk" : shield.sessions.map(\.name).joined(separator: ", ")
        // Geleceği gösteren "0 saniye sonra" çıkmasın: en az 1 saniye önce say.
        let start = min(model.demo ? Date().addingTimeInterval(-40) : (shield.current?.start ?? Date()), Date().addingTimeInterval(-1))
        return L("scam.alert.session", names, Fmt.relative(start))
    }

    private var alert: some View {
        VStack(spacing: 22) {
            Image(systemName: "exclamationmark.octagon.fill").font(.system(size: 96)).foregroundStyle(.white)
                .symbolEffect(.pulse, options: .repeating)
            Text(L("scam.alert.title")).font(.system(size: 40, weight: .heavy)).multilineTextAlignment(.center)
            Text(sessionLine).font(.system(size: 17, weight: .medium)).opacity(0.85)
            Text(L("scam.alert.body")).font(.system(size: 22, weight: .semibold)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            let sites = model.demo ? [] : (shield.current?.sensitiveSites ?? [])
            if !sites.isEmpty {
                VStack(spacing: 6) {
                    Label(L("scam.alert.bankTitle"), systemImage: "creditcard.trianglebadge.exclamationmark").font(.system(size: 20, weight: .heavy))
                    Text(L("scam.alert.bankBody", sites.joined(separator: ", "))).font(.system(size: 16)).multilineTextAlignment(.center)
                }
                .padding(18).frame(maxWidth: .infinity)
                .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 14))
            }
            VStack(spacing: 12) {
                Button { if model.demo { model.stage = .report } else { shield.disconnect() } } label: {
                    Label(L("scam.disconnect"), systemImage: "xmark.circle.fill")
                        .font(.system(size: 24, weight: .bold)).frame(maxWidth: 520).padding(.vertical, 14)
                }
                .buttonStyle(.borderedProminent).tint(.white).foregroundStyle(Color(red: 0.6, green: 0, blue: 0))
                .keyboardShortcut(.defaultAction)
                Button {
                    if model.demo { model.wifiOff = true } else { model.wifiOff = shield.cutInternet() }
                } label: {
                    Label(model.wifiOff ? L("scam.wifiDone") : L("scam.cutInternet"), systemImage: "wifi.slash")
                        .font(.system(size: 17, weight: .semibold)).frame(maxWidth: 520).padding(.vertical, 8)
                }
                .buttonStyle(.bordered).disabled(model.wifiOff)
                Text(L("scam.disconnectHint")).font(.system(size: 13)).opacity(0.8).multilineTextAlignment(.center)
            }
            .padding(.top, 8)
            Divider().overlay(Color.white.opacity(0.3)).padding(.vertical, 6)
            VStack(spacing: 8) {
                Text(L("scam.knownTitle")).font(.system(size: 13, weight: .semibold)).opacity(0.85)
                HStack(spacing: 12) {
                    Button(L("scam.allowHour")) { if model.demo { ScamAlertController.shared.hide() } else { shield.allowCurrent(always: false) } }
                    Button(L("scam.allowAlways")) { if model.demo { ScamAlertController.shared.hide() } else { shield.allowCurrent(always: true) } }
                }
                .controlSize(.small)
                Text(L("scam.knownHint")).font(.system(size: 11.5)).opacity(0.7).multilineTextAlignment(.center)
            }
        }
        .foregroundStyle(.white)
    }

    private var report: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 14) {
                Image(systemName: "checkmark.shield.fill").font(.system(size: 56)).foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 4) {
                    Text(L("scam.report.title")).font(.system(size: 32, weight: .heavy))
                    Text(L("scam.report.subtitle")).font(.system(size: 15)).opacity(0.85)
                }
            }
            let actions = model.demo ? [L("scam.act.killed", "AnyDesk"), L("scam.act.revoked", "AnyDesk")] : shield.lastActions
            if !actions.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text(L("scam.report.done")).font(.system(size: 15, weight: .bold))
                    ForEach(actions, id: \.self) { a in Label(a, systemImage: "checkmark").font(.system(size: 14)) }
                }
            }
            ScamStepsView(large: true)
            HStack {
                Spacer()
                Button {
                    ScamAlertController.shared.hide()
                    if !model.demo { ThreatCenter.shared.navigate(section: .shield) }
                } label: { Text(L("scam.report.close")).font(.system(size: 17, weight: .semibold)).padding(.horizontal, 20).padding(.vertical, 6) }
                .buttonStyle(.borderedProminent).tint(.green)
            }
        }
        .foregroundStyle(.white)
    }
}

/// "Şimdi ne yapmalısın": dolandırıcılıktan sonra sırayla yapılacaklar.
struct ScamStepsView: View {
    var large = false

    var body: some View {
        VStack(alignment: .leading, spacing: large ? 12 : 8) {
            Text(L("scam.steps.title")).font(.system(size: large ? 18 : 13, weight: .bold))
            ForEach(1...6, id: \.self) { i in
                HStack(alignment: .top, spacing: 10) {
                    Text("\(i)").font(.system(size: large ? 15 : 12, weight: .bold)).frame(width: large ? 26 : 20, height: large ? 26 : 20)
                        .background(Circle().fill(Color.accentColor.opacity(large ? 0.9 : 0.2)))
                    Text(L("scam.step\(i)")).font(.system(size: large ? 15 : 12.5)).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

// MARK: - Kenar çubuğundaki sayfa

struct ScamShieldView: View {
    @EnvironmentObject var shield: ScamShield
    @EnvironmentObject var root: RootBridge
    @State private var expanded: String?
    @State private var confirmDelete: ScamIncident?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if !shield.sessions.isEmpty { activeCard }
                howItWorks
                status
                if !shield.incidents.isEmpty { history }
                allowedList
            }
            .padding(24)
            .frame(maxWidth: 860, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(L("nav.shield"))
        .onAppear { shield.refreshInstalled() }
        .confirmationDialog(L("scam.deleteTitle"), isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })) {
            Button(L("q.delete"), role: .destructive) { if let i = confirmDelete { shield.deleteIncident(i) }; confirmDelete = nil }
            Button(L("confirm.cancel"), role: .cancel) { confirmDelete = nil }
        }
    }

    private var header: some View {
        HStack(spacing: 18) {
            ZStack {
                Circle().fill((shield.enabled ? Color.green : Color.secondary).opacity(0.15)).frame(width: 74, height: 74)
                Image(systemName: "phone.badge.waveform.fill").font(.system(size: 32)).foregroundStyle(shield.enabled ? .green : .secondary)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(L("nav.shield")).font(.system(size: 22, weight: .bold))
                Text(shield.enabled ? L("scam.statusOn") : L("scam.statusOff")).font(.system(size: 13)).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("", isOn: $shield.enabled).toggleStyle(.switch).labelsHidden()
        }
    }

    private var activeCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(L("scam.activeTitle"), systemImage: "exclamationmark.octagon.fill").font(.system(size: 15, weight: .bold)).foregroundStyle(.red)
            Text(shield.sessions.map(\.name).joined(separator: ", ")).font(.system(size: 13))
            Button(L("scam.showAlert")) { ScamAlertController.shared.show(shield) }.buttonStyle(.borderedProminent).tint(.red)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }

    private var howItWorks: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L("scam.howTitle")).font(.system(size: 14, weight: .bold))
            Text(L("scam.howBody")).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
            Text(L("scam.whatTitle")).font(.system(size: 14, weight: .bold)).padding(.top, 4)
            ForEach(["scam.what1", "scam.what2", "scam.what3", "scam.what4"], id: \.self) { k in
                Label(L(k), systemImage: "checkmark.circle").font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button { ScamAlertController.shared.show(shield, demo: true) } label: { Label(L("scam.tryAlert"), systemImage: "play.circle") }
                Text(L("scam.tryHint")).font(.system(size: 11.5)).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    private var status: some View {
        VStack(alignment: .leading, spacing: 10) {
            row("app.badge", L("scam.watchTools"),
                shield.installedTools.isEmpty ? L("scam.noTools") : L("scam.toolsInstalled", shield.installedTools.joined(separator: ", ")),
                warn: !shield.installedTools.isEmpty)
            row("rectangle.on.rectangle", L("scam.watchSharing"), L("scam.watchSharingBody"), warn: false)
            VStack(alignment: .leading, spacing: 6) {
                row("building.columns", L("scam.bankTitle"),
                    root.data?.dnsActive == true ? L("scam.bankDNSOn") : L("scam.bankDNSOff"), warn: false)
                HStack(spacing: 10) {
                    Button(L("scam.browserPermission")) { BrowserTab.requestPermissions() }.controlSize(.small)
                    Text(L("scam.browserHint")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                .padding(.leading, 34)
            }
            Toggle(L("scam.speak"), isOn: $shield.speak).font(.system(size: 13)).padding(.leading, 34)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    private func row(_ icon: String, _ title: String, _ detail: String, warn: Bool) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).font(.system(size: 17)).foregroundStyle(warn ? .orange : .secondary).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(detail).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var history: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L("scam.historyTitle")).font(.system(size: 14, weight: .bold))
            ForEach(shield.incidents) { i in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: icon(i.outcome)).foregroundStyle(color(i.outcome))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(i.tools.joined(separator: ", ")).font(.system(size: 13, weight: .semibold))
                            Text("\(i.start.formatted(date: .abbreviated, time: .shortened)) · \(L("scam.outcome.\(i.outcome.rawValue)"))")
                                .font(.system(size: 11.5)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(expanded == i.id ? L("scam.hideReport") : L("scam.openReport")) { expanded = expanded == i.id ? nil : i.id }
                            .controlSize(.small)
                        Button { confirmDelete = i } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                    }
                    if !i.sensitiveSites.isEmpty {
                        Label(L("scam.alert.bankBody", i.sensitiveSites.joined(separator: ", ")), systemImage: "creditcard.trianglebadge.exclamationmark")
                            .font(.system(size: 12)).foregroundStyle(.red)
                    }
                    if expanded == i.id { IncidentReportView(incident: i) }
                }
                .padding(12)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }

    @ViewBuilder private var allowedList: some View {
        let list = shield.allowed.sorted { $0.key < $1.key }
        if !list.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Text(L("scam.allowedTitle")).font(.system(size: 14, weight: .bold))
                ForEach(list, id: \.key) { name, until in
                    HStack {
                        Text(name).font(.system(size: 13))
                        Text(until.map { L("scam.allowedUntil", $0.formatted(date: .omitted, time: .shortened)) } ?? L("scam.allowedAlways"))
                            .font(.system(size: 11.5)).foregroundStyle(.secondary)
                        Spacer()
                        Button(L("q.delete")) { shield.removeAllowed(name) }.controlSize(.small)
                    }
                }
            }
            .padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
        }
    }

    private func icon(_ o: ScamIncident.Outcome) -> String {
        switch o { case .open: return "exclamationmark.octagon.fill"; case .disconnected: return "xmark.circle.fill"
        case .allowed: return "person.fill.checkmark"; case .ended: return "clock" }
    }
    private func color(_ o: ScamIncident.Outcome) -> Color {
        switch o { case .open: return .red; case .disconnected: return .green; case .allowed: return .secondary; case .ended: return .orange }
    }
}

/// Bir olayın raporu: yapılanlar, olay sırasında Mac'te değişenler, yapılacaklar.
struct IncidentReportView: View {
    let incident: ScamIncident
    @State private var changes: [String]?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !incident.actions.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(L("scam.report.done")).font(.system(size: 12.5, weight: .semibold))
                    ForEach(incident.actions, id: \.self) { Label($0, systemImage: "checkmark").font(.system(size: 12)) }
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(L("scam.changesTitle")).font(.system(size: 12.5, weight: .semibold))
                if let c = changes {
                    if c.isEmpty { Text(L("scam.noChanges")).font(.system(size: 12)).foregroundStyle(.secondary) }
                    ForEach(c, id: \.self) { Label($0, systemImage: "exclamationmark.circle").font(.system(size: 12)).foregroundStyle(.orange) }
                } else {
                    ProgressView().controlSize(.small)
                }
                Text(L("scam.changesHint")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            ScamStepsView()
        }
        .padding(.top, 4)
        .task {
            let since = incident.start.addingTimeInterval(-15 * 60)
            changes = await Task.detached { ScamShield.changes(since: since) }.value
        }
    }
}
