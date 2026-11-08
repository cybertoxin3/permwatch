import AppKit
import Foundation
import UniformTypeIdentifiers

/// Canlı paket yakalama. Yönetici modunda permwatch-root bütün arayüzleri PKTAP ile yakalar
/// (her paket gönderen süreçle birlikte); değilse uygulama, erişim izni varsa (ör. Wireshark'ın
/// ChmodBPF'i) seçilen arayüzü kendisi yakalar ve süreçleri port eşleşmesinden bulur.
@MainActor
final class PacketMonitor: ObservableObject {
    enum Mode { case root, local }

    @Published private(set) var packets: [Packet] = []
    @Published private(set) var running = false
    @Published private(set) var mode: Mode?
    @Published private(set) var device: String?
    @Published private(set) var error: String?
    @Published private(set) var needsRoot = false
    @Published private(set) var totalBytes = 0
    @Published private(set) var totalPackets = 0
    @Published private(set) var skipped = 0
    @Published var localDevice: String = PacketMonitor.defaultDevice()
    /// IP → ad (yakalanan DNS yanıtlarından ve TLS SNI'dan, Wireshark'ın "yakalanan DNS ile çöz" seçeneği gibi).
    @Published private(set) var names: [String: String] = [:]
    /// Her yakalama durdurulunca .pcap dosyasının tarih-saatli kopyasının konacağı klasör (boşsa kapalı).
    @Published var saveFolder: String? = UserDefaults.standard.string(forKey: PacketMonitor.saveFolderKey) {
        didSet { UserDefaults.standard.set(saveFolder, forKey: Self.saveFolderKey) }
    }
    @Published private(set) var lastSaved: URL?
    @Published private(set) var saveError: String?
    nonisolated static let saveFolderKey = "captureSaveFolder"

    let maxRows = 20000
    nonisolated static let userDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/permwatch")
    nonisolated static var flagURL: URL { userDir.appendingPathComponent("capture.on") }
    nonisolated static var localPcap: URL { userDir.appendingPathComponent("capture.pcap") }

    private var engine: CaptureEngine?
    private let inbox = Inbox()
    private var timer: Timer?
    private var tail = Tail(path: RootBridge.packetsPath)
    private var portMap: [String: (pid: Int32, name: String)] = [:]
    private var portMapAt = Date.distantPast
    private var paths: [Int32: String] = [:]
    private var startedAt = Date()
    private var nextSeq = 0
    private var flows: [String: (out: Int, inb: Int, warned: Bool)] = [:]

    init() {
        try? FileManager.default.removeItem(at: Self.flagURL)
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { [weak self] _ in
            try? FileManager.default.removeItem(at: PacketMonitor.flagURL)
            // Yakalama sürerken çıkılırsa son durumu da kaydet.
            MainActor.assumeIsolated {
                if let self, self.running, let dir = self.saveFolder { _ = self.copyCapture(toFolder: dir) }
            }
        }
    }

    var pcapURL: URL? {
        switch mode {
        case .root: return URL(fileURLWithPath: RootBridge.pcapPath)
        case .local: return Self.localPcap
        case nil:
            if FileManager.default.isReadableFile(atPath: RootBridge.pcapPath) { return URL(fileURLWithPath: RootBridge.pcapPath) }
            return FileManager.default.fileExists(atPath: Self.localPcap.path) ? Self.localPcap : nil
        }
    }

    static func devices() -> [String] { CaptureEngine.devices().map(\.name) }

    /// İnternete giden trafiğin geçtiği arayüz (VPN açıksa tünel arayüzü).
    nonisolated static func defaultDevice() -> String {
        let out = Shell.run("/sbin/route", ["-n", "get", "1.1.1.1"]).1
        for line in out.split(separator: "\n") where line.contains("interface:") {
            return line.split(separator: ":").last.map { $0.trimmingCharacters(in: .whitespaces) } ?? "en0"
        }
        return "en0"
    }

    // MARK: Başlat / durdur

    func start() {
        guard !running else { return }
        error = nil
        lastSaved = nil
        saveError = nil
        needsRoot = false
        startedAt = Date()
        if RootBridge.shared.active {
            try? FileManager.default.createDirectory(at: Self.userDir, withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: Self.flagURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
            tail = Tail(path: RootBridge.packetsPath, notBefore: startedAt)
            mode = .root
            device = "pktap"
        } else {
            let e = CaptureEngine(device: localDevice)
            do {
                try e.open()
            } catch {
                let msg = (error as? CaptureError)?.message ?? "\(error)"
                needsRoot = msg.localizedCaseInsensitiveContains("permission") || msg.contains("Operation not permitted")
                self.error = msg
                return
            }
            try? FileManager.default.createDirectory(at: Self.userDir, withIntermediateDirectories: true)
            e.dump(to: Self.localPcap.path)
            let box = inbox
            e.onPacket = { box.put($0) }
            e.start()
            engine = e
            mode = .local
            device = localDevice
        }
        running = true
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }

    func stop() {
        let wasRunning = running
        try? FileManager.default.removeItem(at: Self.flagURL)
        engine?.stop()
        engine = nil
        timer?.invalidate()
        timer = nil
        running = false
        // Yakalayıcı dosyayı kapatsın (yerelde ≤0,25 sn, yardımcıda ≤1 sn), sonra klasöre kopyala.
        if wasRunning, let dir = saveFolder {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { [weak self] in _ = self?.copyCapture(toFolder: dir) }
        }
    }

    // MARK: Kaydetme

    private var captureStart: Date { startedAt }

    var defaultFileName: String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        return "permwatch-\(f.string(from: captureStart)).pcap"
    }

    /// Yakalamanın kopyasını klasöre tarih-saatli adla koyar.
    @discardableResult
    func copyCapture(toFolder dir: String) -> URL? {
        copyCapture(to: URL(fileURLWithPath: dir).appendingPathComponent(defaultFileName))
    }

    @discardableResult
    func copyCapture(to dest: URL) -> URL? {
        saveError = nil
        guard let src = pcapURL, FileManager.default.fileExists(atPath: src.path) else {
            saveError = L("pkt.noFile"); return nil
        }
        do {
            try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: dest.path) { try FileManager.default.removeItem(at: dest) }
            // Kopya her zaman kullanıcıya ait, normal izinli bir dosya olsun.
            let data = try Data(contentsOf: src, options: .mappedIfSafe)
            try data.write(to: dest, options: .atomic)
            lastSaved = dest
            return dest
        } catch {
            saveError = L("pkt.saveFailed", error.localizedDescription)
            return nil
        }
    }

    func saveAs() {
        let p = NSSavePanel()
        p.nameFieldStringValue = defaultFileName
        p.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        p.canCreateDirectories = true
        if let dir = saveFolder { p.directoryURL = URL(fileURLWithPath: dir) }
        if p.runModal() == .OK, let u = p.url { copyCapture(to: u) }
    }

    func chooseSaveFolder() {
        let p = NSOpenPanel()
        p.canChooseDirectories = true
        p.canChooseFiles = false
        p.canCreateDirectories = true
        p.prompt = L("pkt.chooseFolder")
        if let dir = saveFolder { p.directoryURL = URL(fileURLWithPath: dir) }
        if p.runModal() == .OK, let u = p.url { saveFolder = u.path }
    }

    func clear() {
        packets.removeAll()
        flows.removeAll()
        totalBytes = 0
        totalPackets = 0
    }

    func openInWireshark() {
        guard let url = pcapURL else { return }
        if let ws = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "org.wireshark.Wireshark") {
            NSWorkspace.shared.open([url], withApplicationAt: ws, configuration: NSWorkspace.OpenConfiguration())
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
    }

    func path(for pid: Int32?) -> String? {
        guard let pid, pid > 0 else { return nil }
        if let p = paths[pid] { return p.isEmpty ? nil : p }
        var buf = [CChar](repeating: 0, count: 4096)
        let p = proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : ""
        paths[pid] = p
        return p.isEmpty ? nil : p
    }

    func displayName(_ ip: String) -> String { names[ip] ?? ip }

    // MARK: Akış

    private func tick() {
        var batch: [Packet]
        switch mode {
        case .root:
            if let d = RootBridge.shared.data {
                if let e = d.captureError { error = e; stop(); return }
                skipped = d.captureSkipped
            } else if Date().timeIntervalSince(startedAt) > 15 {
                error = L("pkt.rootGone"); stop(); return
            }
            batch = tail.read()
        case .local:
            batch = inbox.take()
            skipped = engine?.skipped ?? 0
            refreshPortMap()
            for i in batch.indices where batch[i].pid == nil {
                let p = batch[i]
                let proto = p.proto == "UDP" || ["DNS", "QUIC", "mDNS", "NTP", "SSDP", "DHCP", "LLMNR"].contains(p.proto) ? "UDP" : "TCP"
                for port in [p.sport, p.dport].compactMap({ $0 }) {
                    if let m = portMap["\(proto):\(port)"] { batch[i].pid = m.pid; batch[i].proc = m.name; break }
                }
            }
        case nil:
            return
        }
        guard !batch.isEmpty else { return }
        ingest(batch)
    }

    private func ingest(_ incoming: [Packet]) {
        // Yakalama yeniden başlayınca sıra numaraları da baştan başlar; listede benzersiz olsun.
        var batch = incoming
        for i in batch.indices { nextSeq += 1; batch[i].seq = nextSeq }
        var newNames = names
        for p in batch {
            totalBytes += p.len
            if let ans = p.dns, let q = p.host {
                for a in ans where !a.hasPrefix("CNAME") { newNames[a] = q }
            }
            if p.proto == "TLS", let h = p.host { newNames[p.dst] = h }
            if p.flags?.contains("pkt.flag.cleartextCreds") == true { report(p) }
            // Yükleme izleme: bir uygulama bir sunucuya çok veri gönderip az alıyorsa uyar.
            if p.sport != nil {
                let out = p.dir == "out" || (p.dir == nil && Conversation.isLocal(p.src))
                let remote = out ? p.dst : p.src
                let key = "\(p.eproc ?? p.proc ?? "?")|\(remote)"
                var f = flows[key, default: (0, 0, false)]
                if out { f.out += p.len } else { f.inb += p.len }
                if !f.warned, f.out > 50 << 20, f.out > f.inb * 5 {
                    f.warned = true
                    reportUpload(p, remote: remote, bytes: f.out)
                }
                flows[key] = f
            }
        }
        if newNames.count != names.count { names = newNames }
        totalPackets += batch.count
        packets.append(contentsOf: batch)
        if packets.count > maxRows { packets.removeFirst(packets.count - maxRows) }
    }

    private func report(_ p: Packet) {
        let who = p.eproc ?? p.proc ?? (p.src + (p.sport.map { ":\($0)" } ?? ""))
        let host = p.host ?? displayName(p.dst)
        ThreatCenter.shared.report(Threat(
            id: "pkt.creds.\(who).\(host)", risk: .high,
            title: L("pkt.threat.creds"), detail: L("pkt.threat.credsDetail", who, host),
            iconKey: path(for: p.pid).map { PathUtil.appBundle($0) ?? $0 },
            section: .packets, focus: .packet(p.seq)))
    }

    private func reportUpload(_ p: Packet, remote: String, bytes: Int) {
        let who = p.eproc ?? p.proc ?? remote
        let host = names[remote] ?? remote
        ThreatCenter.shared.report(Threat(
            id: "pkt.upload.\(who).\(remote)", risk: .caution,
            title: L("pkt.threat.upload"),
            detail: L("pkt.threat.uploadDetail", who, ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file), host),
            iconKey: path(for: p.epid ?? p.pid).map { PathUtil.appBundle($0) ?? $0 },
            section: .packets, focus: .packet(p.seq)))
    }

    /// Kullanıcı modunda yerel port → süreç eşlemesi (lsof, yalnızca kendi süreçlerin).
    private func refreshPortMap() {
        guard Date().timeIntervalSince(portMapAt) > 3 else { return }
        portMapAt = Date()
        Task.detached(priority: .utility) {
            let out = Shell.run("/usr/sbin/lsof", ["-nP", "-i", "-F", "pcPn"]).1
            var map: [String: (pid: Int32, name: String)] = [:]
            var pid: Int32 = 0, name = "", proto = ""
            for line in out.split(separator: "\n") {
                guard let f = line.first else { continue }
                let v = String(line.dropFirst())
                switch f {
                case "p": pid = Int32(v) ?? 0
                case "c": name = v
                case "P": proto = v
                case "n":
                    let local = v.components(separatedBy: "->").first ?? v
                    if let port = local.split(separator: ":").last { map["\(proto):\(port)"] = (pid, name) }
                default: break
                }
            }
            let result = map
            await MainActor.run { self.portMap = result }
        }
    }
}

/// Yakalama iş parçacığından ana iş parçacığına paket kuyruğu.
final class Inbox: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [Packet] = []
    func put(_ p: Packet) { lock.lock(); items.append(p); lock.unlock() }
    func take() -> [Packet] { lock.lock(); defer { items.removeAll(keepingCapacity: true); lock.unlock() }; return items }
}

/// Yardımcının yazdığı packets.jsonl dosyasını kuyruğundan okur (dosya yenilenince baştan başlar).
struct Tail {
    let path: String
    var notBefore: Date = .distantPast
    private var offset: UInt64 = 0
    private var inode: UInt64 = 0
    private var partial = Data()

    init(path: String, notBefore: Date = .distantPast) { self.path = path; self.notBefore = notBefore }

    mutating func read() -> [Packet] {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let ino = (attrs[.systemFileNumber] as? NSNumber)?.uint64Value,
              let size = (attrs[.size] as? NSNumber)?.uint64Value else { return [] }
        if ino != inode || size < offset { inode = ino; offset = 0; partial.removeAll() }
        guard size > offset, let h = FileHandle(forReadingAtPath: path) else { return [] }
        defer { try? h.close() }
        try? h.seek(toOffset: offset)
        let chunk = h.readData(ofLength: Int(min(size - offset, 16 << 20)))
        offset += UInt64(chunk.count)
        partial.append(chunk)
        guard let last = partial.lastIndex(of: 0x0a) else { return [] }
        let complete = partial[partial.startIndex...last]
        partial = Data(partial[partial.index(after: last)...])
        let dec = JSONDecoder()
        let cutoff = notBefore.timeIntervalSince1970 - 2
        return complete.split(separator: 0x0a).compactMap { try? dec.decode(Packet.self, from: Data($0)) }
            .filter { $0.ts >= cutoff }
    }
}
