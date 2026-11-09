import Foundation

/// macOS'un ekran yakalama servisinin (replayd, ScreenCaptureKit) sistem kaydından hangi süreçlerin şu an
/// ekranı paylaştığını ya da kaydettiğini çıkarır. Zoom, Teams, Meet (tarayıcı), Discord, AnyDesk… hepsi
/// bu servisten geçer; program listesine ihtiyaç yoktur.
///
/// Kayıttaki zincir (gerçek satırlar, macOS 26):
///   accepted client connection PID: 439                       → istemci süreci
///   -[RPClient initWithConnection:…]:125 0x97ec99040            → istemci nesnesi (PID'e bağlanır)
///   -[RPClient captureSessionDidChange:…] client=0x97ec99040 captureSession=0x97e784000   → paylaşım başladı
///   -[RPClient stop:…] stream=0x97e784000                       → o paylaşım bitti
///   -[RPClient invalidate]:167 0x97ec99040                      → istemci ayrıldı (bütün paylaşımları biter)
struct CaptureLogParser {
    private var pendingPID: Int32?
    private var clients: [String: Int32] = [:]       // istemci nesnesi → PID
    private var streams: [String: String] = [:]      // paylaşım oturumu → istemci nesnesi
    private(set) var startedAt: [Int32: Date] = [:]

    /// Şu an ekranı paylaşan/kaydeden süreçler.
    var activePIDs: Set<Int32> { Set(streams.values.compactMap { clients[$0] }) }

    static let predicate = #"process == "replayd" AND (eventMessage CONTAINS "accepted client connection PID" OR eventMessage CONTAINS "initWithConnection:clientProxy" OR eventMessage CONTAINS "captureSessionDidChange" OR eventMessage CONTAINS "stop:transactionID:streamData" OR eventMessage CONTAINS "RPClient invalidate")"#

    mutating func feed(_ message: String, at date: Date = Date()) {
        if let r = message.range(of: "accepted client connection PID: ") {
            pendingPID = Int32(message[r.upperBound...].prefix { $0.isNumber })
        } else if message.contains("initWithConnection:clientProxy"), let addr = Self.lastHex(message), let pid = pendingPID {
            clients[addr] = pid
            pendingPID = nil
        } else if message.contains("captureSessionDidChange"),
                  let c = Self.value(message, "client="), let s = Self.value(message, "captureSession=") {
            if streams[s] == nil, let pid = clients[c], startedAt[pid] == nil { startedAt[pid] = date }
            streams[s] = c
        } else if message.contains("stop:transactionID:streamData"), let s = Self.value(message, "stream=") {
            streams[s] = nil
            prune()
        } else if message.contains("RPClient invalidate"), let addr = Self.lastHex(message) {
            streams = streams.filter { $0.value != addr }
            clients[addr] = nil
            prune()
        }
    }

    /// Kapanan süreçleri unut (kayıtta "bitti" satırı kaçırılmış olabilir).
    mutating func forget(dead: (Int32) -> Bool) {
        for (addr, pid) in clients where dead(pid) {
            clients[addr] = nil
            streams = streams.filter { $0.value != addr }
        }
        prune()
    }

    private mutating func prune() {
        let live = activePIDs
        startedAt = startedAt.filter { live.contains($0.key) }
    }

    static func value(_ s: String, _ key: String) -> String? {
        guard let r = s.range(of: key) else { return nil }
        let v = s[r.upperBound...].prefix { $0.isHexDigit || $0 == "x" }
        return v.isEmpty ? nil : String(v)
    }

    static func lastHex(_ s: String) -> String? {
        guard let r = s.range(of: "0x", options: .backwards) else { return nil }
        let v = s[r.lowerBound...].prefix { $0.isHexDigit || $0 == "x" }
        return v.count > 2 ? String(v) : nil
    }
}

/// Sistem kaydını sürekli dinler (log stream). Ölçülen maliyet: dakikada ~0 sn işlemci.
/// Açılışta son 30 dakikayı okuyarak zaten sürmekte olan paylaşımları da bulur.
final class CaptureLogWatcher: @unchecked Sendable {
    private let lock = NSLock()
    private var parser = CaptureLogParser()
    private var process: Process?
    private var buffer = Data()
    private var stopped = false

    var activePIDs: Set<Int32> {
        lock.lock(); defer { lock.unlock() }
        parser.forget { kill($0, 0) != 0 && errno == ESRCH }
        return parser.activePIDs
    }

    func startedAt(_ pid: Int32) -> Date? { lock.lock(); defer { lock.unlock() }; return parser.startedAt[pid] }

    func start() {
        lock.lock(); stopped = false; lock.unlock()
        DispatchQueue.global(qos: .utility).async { [weak self] in
            // Önce geçmiş: permwatch açılmadan önce başlamış paylaşımlar.
            let hist = Shell.run("/usr/bin/log", ["show", "--last", "30m", "--style", "ndjson", "--predicate", CaptureLogParser.predicate]).1
            self?.consume(Data(hist.utf8), flush: true)
            self?.launch()
        }
    }

    func stop() {
        lock.lock(); stopped = true; let p = process; process = nil; lock.unlock()
        p?.terminate()
    }

    private func launch() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        p.arguments = ["stream", "--style", "ndjson", "--predicate", CaptureLogParser.predicate]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil; return }
            self?.consume(d, flush: false)
        }
        p.terminationHandler = { [weak self] _ in
            // Beklenmedik biterse birkaç saniye sonra yeniden başlat.
            guard let self else { return }
            self.lock.lock(); let again = !self.stopped; self.lock.unlock()
            if again { DispatchQueue.global().asyncAfter(deadline: .now() + 5) { self.launch() } }
        }
        do { try p.run() } catch { return }
        lock.lock(); process = p; lock.unlock()
    }

    private func consume(_ d: Data, flush: Bool) {
        lock.lock(); defer { lock.unlock() }
        buffer.append(d)
        while let nl = buffer.firstIndex(of: 0x0a) {
            let line = buffer[buffer.startIndex..<nl]
            buffer.removeSubrange(buffer.startIndex...nl)
            Self.parse(line, into: &parser)
        }
        if flush { Self.parse(buffer, into: &parser); buffer.removeAll() }
    }

    private static func parse(_ line: Data, into p: inout CaptureLogParser) {
        guard !line.isEmpty, let j = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              let msg = j["eventMessage"] as? String else { return }
        var date = Date()
        if let ts = j["timestamp"] as? String {
            let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"
            date = f.date(from: ts) ?? date
        }
        p.feed(msg, at: date)
    }
}
