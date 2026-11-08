import AppKit
import SwiftTerm
import SwiftUI

/// Bir terminal oturumu: kullanıcının kabuğu, gerçek bir PTY ve SwiftTerm (xterm uyumlu) görünümü.
/// Görünüm nesnesi oturumla yaşar; bölüm değiştirince kabuk kapanmaz.
@MainActor
final class TerminalSession: NSObject, ObservableObject, Identifiable, LocalProcessTerminalViewDelegate {
    let id = UUID()
    let view: LocalProcessTerminalView
    @Published var title: String
    @Published var running = false
    @Published var exitCode: Int32?
    let number: Int

    init(number: Int, fontSize: CGFloat) {
        self.number = number
        title = "zsh"
        view = LocalProcessTerminalView(frame: NSRect(x: 0, y: 0, width: 800, height: 500))
        super.init()
        view.processDelegate = self
        view.optionAsMetaKey = true
        setFontSize(fontSize)
        start()
    }

    static var shell: String {
        let s = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
        return FileManager.default.isExecutableFile(atPath: s) ? s : "/bin/zsh"
    }

    func start() {
        var env = ProcessInfo.processInfo.environment
        env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"
        env["TERM_PROGRAM"] = "permwatch"
        if env["LANG"] == nil { env["LANG"] = Locale.current.identifier.replacingOccurrences(of: "-", with: "_") + ".UTF-8" }
        let shell = Self.shell
        title = (shell as NSString).lastPathComponent
        exitCode = nil
        running = true
        // "-zsh": oturum açma kabuğu (PATH, /etc/zprofile, ~/.zprofile yüklenir), Terminal.app gibi.
        view.startProcess(executable: shell, args: [], environment: env.map { "\($0.key)=\($0.value)" },
                          execName: "-" + (shell as NSString).lastPathComponent, currentDirectory: NSHomeDirectory())
    }

    /// Kabuğu ve alt süreçlerini kapat. Etkileşimli zsh SIGTERM'i yok sayar; terminal kapanınca olduğu
    /// gibi SIGHUP gönder, kapanmazsa zorla.
    func terminate() {
        let pid = view.process?.shellPid ?? 0
        if pid > 0 {
            kill(pid, SIGHUP)
            DispatchQueue.global().asyncAfter(deadline: .now() + 1) { if kill(pid, 0) == 0 { kill(pid, SIGKILL) } }
        }
        view.terminate()
        running = false
    }

    func setFontSize(_ size: CGFloat) {
        view.font = NSFont.monospacedSystemFont(ofSize: size, weight: .regular)
    }

    func applyAppearance(dark: Bool) {
        view.nativeBackgroundColor = dark ? NSColor(calibratedWhite: 0.11, alpha: 1) : NSColor(calibratedWhite: 0.99, alpha: 1)
        view.nativeForegroundColor = dark ? NSColor(calibratedWhite: 0.90, alpha: 1) : NSColor(calibratedWhite: 0.12, alpha: 1)
        view.caretColor = .controlAccentColor
    }

    /// Komutu yazar ama çalıştırmaz (Enter kullanıcıda).
    func type(_ text: String) {
        view.send(data: ArraySlice(Array(text.utf8)))
        view.window?.makeFirstResponder(view)
    }

    // MARK: LocalProcessTerminalViewDelegate (SwiftTerm ana iş parçacığından çağırır)

    nonisolated func sizeChanged(source: LocalProcessTerminalView, newCols: Int, newRows: Int) {}

    nonisolated func setTerminalTitle(source: LocalProcessTerminalView, title: String) {
        MainActor.assumeIsolated { if !title.isEmpty { self.title = title } }
    }

    nonisolated func hostCurrentDirectoryUpdate(source: SwiftTerm.TerminalView, directory: String?) {}

    nonisolated func processTerminated(source: SwiftTerm.TerminalView, exitCode: Int32?) {
        MainActor.assumeIsolated {
            self.running = false
            self.exitCode = exitCode
        }
    }
}

/// Bütün oturumlar (uygulama boyunca yaşar).
@MainActor
final class TerminalStore: ObservableObject {
    @Published private(set) var sessions: [TerminalSession] = []
    @Published var selected: UUID?
    @Published var fontSize: CGFloat = CGFloat(UserDefaults.standard.object(forKey: "terminalFontSize") as? Double ?? 13) {
        didSet {
            UserDefaults.standard.set(Double(fontSize), forKey: "terminalFontSize")
            sessions.forEach { $0.setFontSize(fontSize) }
        }
    }
    private var counter = 0

    var current: TerminalSession? { sessions.first { $0.id == selected } ?? sessions.first }

    func ensureOne() { if sessions.isEmpty { newSession() } }

    func newSession() {
        counter += 1
        let s = TerminalSession(number: counter, fontSize: fontSize)
        sessions.append(s)
        selected = s.id
    }

    func close(_ s: TerminalSession) {
        s.terminate()
        sessions.removeAll { $0.id == s.id }
        if selected == s.id { selected = sessions.last?.id }
    }

    init() {
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.sessions.forEach { $0.terminate() } }
        }
    }
}

/// Hazır komutlar: terminale yazılır, çalıştırılmaz.
struct QuickCommand: Identifiable {
    let id: String
    let command: String
    var title: String { L("term.cmd." + id) }

    static let all: [QuickCommand] = [
        .init(id: "connections", command: "lsof -nP -i -sTCP:ESTABLISHED"),
        .init(id: "listening", command: "lsof -nP -iTCP -sTCP:LISTEN"),
        .init(id: "tccLive", command: "log stream --style compact --predicate 'subsystem == \"com.apple.TCC\"'"),
        .init(id: "loginItems", command: "sudo sfltool dumpbtm | less"),
        .init(id: "posture", command: "csrutil status; spctl --status; fdesetup status; /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"),
        .init(id: "signature", command: "codesign -dvv --verbose=4 "),
        .init(id: "gatekeeper", command: "spctl -a -vv "),
        .init(id: "quarantine", command: "xattr -l "),
        .init(id: "dns", command: "scutil --dns | head -40"),
        .init(id: "profiles", command: "profiles list"),
        .init(id: "updates", command: "softwareupdate -l"),
        .init(id: "pktap", command: "sudo tcpdump -i pktap,all -k NP -nn"),
    ]
}

struct TerminalSection: View {
    @EnvironmentObject var store: TerminalStore
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            ZStack {
                if let s = store.current {
                    TerminalHost(session: s, dark: scheme == .dark)
                        .id(s.id)
                    if !s.running { ended(s) }
                }
            }
            Divider()
            HStack(spacing: 6) {
                Image(systemName: "info.circle")
                Text(L("term.note"))
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(L("nav.terminal"))
        .onAppear { store.ensureOne() }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    ForEach(store.sessions) { s in
                        TabChip(session: s, selected: s.id == store.current?.id,
                                select: { store.selected = s.id }, close: { store.close(s) })
                    }
                    Button { store.newSession() } label: { Image(systemName: "plus") }
                        .buttonStyle(.borderless).help(L("term.newTab"))
                        .keyboardShortcut("t", modifiers: .command)
                }
            }
            Spacer()
            Menu {
                ForEach(QuickCommand.all) { c in
                    Button(c.title) { store.current?.type(c.command) }
                }
            } label: { Label(L("term.commands"), systemImage: "list.bullet.rectangle") }
                .fixedSize()
                .help(L("term.commandsHelp"))
            Button { store.fontSize = max(9, store.fontSize - 1) } label: { Image(systemName: "textformat.size.smaller") }
                .help(L("term.smaller")).keyboardShortcut("-", modifiers: .command)
            Button { store.fontSize = min(28, store.fontSize + 1) } label: { Image(systemName: "textformat.size.larger") }
                .help(L("term.larger")).keyboardShortcut("+", modifiers: .command)
        }
        .padding(.horizontal, 12).padding(.vertical, 7)
    }

    private func ended(_ s: TerminalSession) -> some View {
        VStack(spacing: 10) {
            Text(L("term.ended", s.exitCode.map { String($0) } ?? "—")).font(.system(size: 13, weight: .semibold))
            Button(L("term.restart")) { s.start() }.buttonStyle(.borderedProminent)
        }
        .padding(18)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct TabChip: View {
    @ObservedObject var session: TerminalSession
    let selected: Bool
    let select: () -> Void
    let close: () -> Void

    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(session.running ? SwiftUI.Color.green : SwiftUI.Color.secondary).frame(width: 6, height: 6)
            Text("\(session.number) · \(session.title)").font(.system(size: 11.5)).lineLimit(1).frame(maxWidth: 160)
            Button(action: close) { Image(systemName: "xmark").font(.system(size: 9, weight: .bold)) }
                .buttonStyle(.plain).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 9).padding(.vertical, 4)
        .background(selected ? SwiftUI.Color.accentColor.opacity(0.18) : SwiftUI.Color.secondary.opacity(0.08),
                    in: RoundedRectangle(cornerRadius: 6))
        .contentShape(Rectangle())
        .onTapGesture(perform: select)
    }
}

/// SwiftTerm görünümünü SwiftUI'ye taşır; aynı NSView her seferinde yeniden kullanılır.
private struct TerminalHost: NSViewRepresentable {
    let session: TerminalSession
    let dark: Bool

    func makeNSView(context: Context) -> NSView {
        let container = NSView()
        attach(to: container)
        return container
    }

    func updateNSView(_ container: NSView, context: Context) {
        if session.view.superview !== container { attach(to: container) }
        session.applyAppearance(dark: dark)
    }

    private func attach(to container: NSView) {
        let v = session.view
        v.removeFromSuperview()
        v.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(v)
        NSLayoutConstraint.activate([
            v.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 6),
            v.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            v.topAnchor.constraint(equalTo: container.topAnchor, constant: 4),
            v.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])
        session.applyAppearance(dark: dark)
        DispatchQueue.main.async { v.window?.makeFirstResponder(v) }
    }
}
