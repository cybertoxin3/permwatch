// permwatch-root: VPN bağlantısı (AmneziaWG ve Xray VLESS-Reality).
//
// Güvenlik tasarımı (yardımcının geri kalanıyla aynı ilke: komut almaz):
//  - Tek girdi, oturum sahibinin klasöründeki vpn/want.json dosyasıdır (sahibi o kullanıcı, düz dosya, ≤ 256 KB).
//  - Yalnızca uygulama paketinin içindeki iki program çalıştırılır (Contents/Resources/vpn/amneziawg-go ve xray),
//    argümanlar sabittir. Kullanıcıdan gelen değerler doğrulanır: anahtarlar base64, adresler inet_pton,
//    AWG parametreleri yalnızca bilinen anahtarlar ve satır sonu içermeyen kısa değerler.
//  - Xray yapılandırmasını yardımcı kendisi kurar: kullanıcıdan yalnızca "outbound" (vless/vmess/trojan/
//    shadowsocks) alınır; günlük dosyası, API gibi dosya yazabilen bölümler hiç yazılmaz.
//  - DNS ayarları değiştirilmeden önce yedeklenir; bağlantı kesilince (ya da yardımcı yeniden başlayınca) geri yüklenir.
import Darwin
import Foundation

final class VPNRunner {
    private var process: Process?
    private var current: String?          // çalışan isteğin özeti
    private var iface: String?
    private var kind = ""
    private var server = ""
    private var since: Date?
    private var error: String?
    private var hostRoute: (ip: String, gw: String)?
    private let dnsBackupPath = outDir + "/vpn-dns-backup.json"
    private let workDir = outDir + "/vpn"

    var wantPath: String { home + "/Library/Application Support/permwatch/vpn/want.json" }

    init() {
        // Önceki çalışmadan kalanlar: eski motor süreçleri ve değiştirilmiş DNS.
        _ = run("/usr/bin/pkill", ["-f", vpnBin("amneziawg-go")])
        _ = run("/usr/bin/pkill", ["-f", vpnBin("xray")])
        restoreDNS()
    }

    func vpnBin(_ name: String) -> String {
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        return exe.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/vpn/" + name).path
    }

    /// Her saniye: istenen bağlantı değiştiyse durdur/başlat; durumu yaz.
    func tick() {
        let want = readWant()
        let sig = want.map { String($0.hashValue) }
        if sig != current {
            stop()
            if let w = want { start(w) }
            current = sig
        } else if let p = process, !p.isRunning, want != nil {
            // Motor kendiliğinden kapandı: 5 sn sonra yeniden dene.
            stop(); error = error ?? "engine exited"
            current = nil
            sleep(5)
        }
        writeState()
    }

    func shutdown() { stop(); writeState() }

    private func readWant() -> String? {
        var st = stat()
        guard lstat(wantPath, &st) == 0, st.st_uid == owner, (st.st_mode & S_IFMT) == S_IFREG, st.st_size < 256 * 1024,
              let d = FileManager.default.contents(atPath: wantPath) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    // MARK: Başlat / durdur

    private func start(_ text: String) {
        error = nil
        guard let j = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any], let k = j["kind"] as? String else {
            error = "invalid request"; return
        }
        kind = k
        try? FileManager.default.createDirectory(atPath: workDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let dns = ((j["dns"] as? [String]) ?? []).filter(isIP).prefix(2)
        do {
            switch k {
            case "awg": try startAWG(j)
            case "xray": try startXray(j)
            default: throw VPNError.msg("unknown kind")
            }
            setDNS(dns.isEmpty ? ["1.1.1.1", "1.0.0.1"] : Array(dns))
            since = Date()
        } catch {
            self.error = (error as? VPNError)?.text ?? "\(error)"
            stop()
        }
    }

    private func stop() {
        if let p = process, p.isRunning {
            p.terminate()
            for _ in 0..<20 where p.isRunning { usleep(100_000) }
            if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        }
        process = nil
        if let r = hostRoute { _ = run("/sbin/route", ["-q", "-n", "delete", "-inet", r.ip, r.gw]); hostRoute = nil }
        restoreDNS()
        iface = nil; since = nil; server = ""
        try? FileManager.default.removeItem(atPath: workDir + "/xray.json")
    }

    // MARK: AmneziaWG

    private static let awgKeys: Set = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
                                       "header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout",
                                       "reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers",
                                       "disable_cookies"]

    private func startAWG(_ j: [String: Any]) throws {
        guard let a = j["awg"] as? [String: Any],
              let priv = (a["privateKey"] as? String).flatMap(b64hex), let pub = (a["publicKey"] as? String).flatMap(b64hex),
              let endpoint = a["endpoint"] as? String, let addrs = a["address"] as? [String] else { throw VPNError.msg("incomplete AWG config") }
        let (host, port) = try splitEndpoint(endpoint)
        guard let ip = resolve(host) else { throw VPNError.msg("cannot resolve \(host)") }
        server = host
        let name = freeUtun()
        let bin = vpnBin("amneziawg-go")
        guard FileManager.default.isExecutableFile(atPath: bin) else { throw VPNError.msg("engine missing") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["-f", name]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()
        process = p
        let sock = "/var/run/amneziawg/\(name).sock"
        for _ in 0..<50 where !FileManager.default.fileExists(atPath: sock) { usleep(100_000) }
        guard FileManager.default.fileExists(atPath: sock) else { throw VPNError.msg("tunnel did not start") }
        iface = name

        var cmd = "set=1\nprivate_key=\(priv)\n"
        for (k, v) in (a["params"] as? [String: String]) ?? [:] {
            let key = k.lowercased()
            guard Self.awgKeys.contains(key), !v.contains("\n"), v.count < 8192 else { continue }
            cmd += "\(key)=\(key == "header_protection_key" ? (b64hex(v) ?? v) : v)\n"
        }
        cmd += "replace_peers=true\npublic_key=\(pub)\n"
        if let psk = (a["presharedKey"] as? String).flatMap(b64hex) { cmd += "preshared_key=\(psk)\n" }
        cmd += "endpoint=\(ip.contains(":") ? "[\(ip)]" : ip):\(port)\npersistent_keepalive_interval=\((a["keepalive"] as? Int) ?? 25)\n"
        cmd += "replace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n\n"
        let reply = uapi(sock, cmd)
        guard reply.contains("errno=0") else { throw VPNError.msg("tunnel rejected config: \(reply.prefix(120))") }

        // Adresler, MTU ve yönlendirmeler (wg-quick'in macOS'ta yaptığı gibi).
        let mtu = (a["mtu"] as? Int).map { min(max($0, 1200), 1500) } ?? 1376
        _ = run("/sbin/ifconfig", [name, "mtu", String(mtu)])
        var has6 = false
        for cidr in addrs {
            let parts = cidr.split(separator: "/"), addr = String(parts[0])
            guard isIP(addr) else { continue }
            if addr.contains(":") {
                has6 = true
                _ = run("/sbin/ifconfig", [name, "inet6", addr, "prefixlen", parts.count > 1 ? String(parts[1]) : "128", "alias"])
            } else {
                _ = run("/sbin/ifconfig", [name, "inet", addr + "/" + (parts.count > 1 ? String(parts[1]) : "32"), addr, "alias"])
            }
        }
        _ = run("/sbin/ifconfig", [name, "up"])
        if let gw = defaultGateway(), !ip.contains(":") {
            _ = run("/sbin/route", ["-q", "-n", "add", "-inet", ip, gw])
            hostRoute = (ip, gw)
        }
        for net in ["0.0.0.0/1", "128.0.0.0/1"] { _ = run("/sbin/route", ["-q", "-n", "add", "-inet", net, "-interface", name]) }
        // IPv6 her durumda tünele: adres yoksa sızmasın diye tünelde düşer.
        for net in ["::/1", "8000::/1"] { _ = run("/sbin/route", ["-q", "-n", "add", "-inet6", net, "-interface", name]) }
        _ = has6
    }

    private func uapi(_ path: String, _ cmd: String) -> String {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return "" }
        defer { close(fd) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutableBytes(of: &addr.sun_path) { buf in path.utf8CString.withUnsafeBytes { buf.copyMemory(from: UnsafeRawBufferPointer(rebasing: $0.prefix(buf.count - 1))) } }
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard ok == 0 else { return "" }
        _ = cmd.utf8CString.withUnsafeBytes { write(fd, $0.baseAddress, $0.count - 1) }
        var out = Data(), buf = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { break }
            out.append(buf, count: n)
            if let s = String(data: out, encoding: .utf8), s.hasSuffix("\n\n") { break }
        }
        return String(data: out, encoding: .utf8) ?? ""
    }

    /// Tünelin aldığı/gönderdiği bayt ve son el sıkışma (AWG).
    private func awgStats() -> [String: Any] {
        guard let n = iface, kind == "awg" else { return [:] }
        let r = uapi("/var/run/amneziawg/\(n).sock", "get=1\n\n")
        var rx = 0, tx = 0, hs = 0
        for line in r.split(separator: "\n") {
            let kv = line.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else { continue }
            switch kv[0] {
            case "rx_bytes": rx += Int(kv[1]) ?? 0
            case "tx_bytes": tx += Int(kv[1]) ?? 0
            case "last_handshake_time_sec": hs = max(hs, Int(kv[1]) ?? 0)
            default: break
            }
        }
        return ["rx": rx, "tx": tx, "handshake": hs]
    }

    // MARK: Xray (VLESS + Reality)

    private static let allowedOutbounds: Set = ["vless", "vmess", "trojan", "shadowsocks"]

    private func startXray(_ j: [String: Any]) throws {
        guard var out = j["outbound"] as? [String: Any], let proto = out["protocol"] as? String, Self.allowedOutbounds.contains(proto) else {
            throw VPNError.msg("unsupported Xray config")
        }
        out["tag"] = "proxy"
        out["sendThrough"] = nil
        // Sunucu adresi: yönlendirme döngüsü olmasın diye Xray kendi bağlantılarını fiziksel arayüze bağlar
        // (autoOutboundsInterface). Burada yalnızca gösterim için okunur.
        if let s = out["settings"] as? [String: Any] {
            let vnext = (s["vnext"] as? [[String: Any]])?.first ?? (s["servers"] as? [[String: Any]])?.first
            server = (vnext?["address"] as? String) ?? (s["address"] as? String) ?? ""
        }
        let name = freeUtun()
        let config: [String: Any] = [
            "log": ["loglevel": "warning"],
            "inbounds": [[
                "tag": "tun", "protocol": "tun",
                "settings": ["name": name, "mtu": 1500, "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"], "autoOutboundsInterface": "auto"],
            ]],
            "outbounds": [out, ["tag": "direct", "protocol": "freedom"]],
        ]
        let path = workDir + "/xray.json"
        let data = try JSONSerialization.data(withJSONObject: config)
        FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600])
        let bin = vpnBin("xray")
        guard FileManager.default.isExecutableFile(atPath: bin) else { throw VPNError.msg("engine missing") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["run", "-c", path]
        p.environment = ["XRAY_LOCATION_ASSET": workDir]
        let errPipe = Pipe()
        p.standardOutput = FileHandle.nullDevice; p.standardError = errPipe
        try p.run()
        process = p
        for _ in 0..<50 where !interfaceExists(name) && p.isRunning { usleep(100_000) }
        guard p.isRunning, interfaceExists(name) else {
            let e = String(data: errPipe.fileHandleForReading.availableData, encoding: .utf8) ?? ""
            throw VPNError.msg("Xray did not start: \(e.suffix(160))")
        }
        iface = name
    }

    // MARK: DNS

    private func services() -> [String] {
        run("/usr/sbin/networksetup", ["-listallnetworkservices"]).split(separator: "\n").dropFirst()
            .map(String.init).filter { !$0.hasPrefix("*") }
    }

    private func setDNS(_ servers: [String]) {
        var backup: [String: [String]] = [:]
        if FileManager.default.fileExists(atPath: dnsBackupPath) { return }   // zaten yedekli
        for s in services() {
            let cur = run("/usr/sbin/networksetup", ["-getdnsservers", s]).split(separator: "\n").map(String.init).filter(isIP)
            backup[s] = cur
            _ = run("/usr/sbin/networksetup", ["-setdnsservers", s] + servers)
        }
        if let d = try? JSONSerialization.data(withJSONObject: backup) { FileManager.default.createFile(atPath: dnsBackupPath, contents: d, attributes: [.posixPermissions: 0o600]) }
    }

    private func restoreDNS() {
        guard let d = FileManager.default.contents(atPath: dnsBackupPath),
              let backup = (try? JSONSerialization.jsonObject(with: d)) as? [String: [String]] else { return }
        for (s, list) in backup {
            _ = run("/usr/sbin/networksetup", ["-setdnsservers", s] + (list.isEmpty ? ["Empty"] : list.filter(isIP)))
        }
        try? FileManager.default.removeItem(atPath: dnsBackupPath)
    }

    // MARK: Durum

    private func writeState() {
        var doc: [String: Any] = ["ts": Date().timeIntervalSince1970, "state": stateText(), "kind": kind, "server": server]
        if let i = iface { doc["iface"] = i; doc["bytes"] = ifaceBytes(i) }
        if let s = since { doc["since"] = s.timeIntervalSince1970 }
        if let e = error { doc["error"] = e }
        doc.merge(awgStats()) { a, _ in a }
        if let data = try? JSONSerialization.data(withJSONObject: doc) { writeAtomic(data, to: outDir + "/vpn.json") }
    }

    private func stateText() -> String {
        if error != nil { return "error" }
        if process?.isRunning == true, iface != nil { return "connected" }
        return current == nil ? "off" : "connecting"
    }

    private func ifaceBytes(_ name: String) -> [Int] {
        for line in run("/usr/sbin/netstat", ["-ibn", "-I", name]).split(separator: "\n").dropFirst() {
            let c = line.split(separator: " ", omittingEmptySubsequences: true)
            if c.count >= 10, c[0] == name { return [Int(c[6]) ?? 0, Int(c[9]) ?? 0] }
        }
        return [0, 0]
    }

    // MARK: Yardımcılar

    private func freeUtun() -> String {
        let used = Set(run("/sbin/ifconfig", ["-l"]).split(separator: " ").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) })
        for n in 42...99 where !used.contains("utun\(n)") { return "utun\(n)" }
        return "utun100"
    }

    private func interfaceExists(_ name: String) -> Bool {
        run("/sbin/ifconfig", ["-l"]).split(separator: " ").contains { $0.trimmingCharacters(in: .whitespacesAndNewlines) == name }
    }

    private func defaultGateway() -> String? {
        for line in run("/sbin/route", ["-n", "get", "default"]).split(separator: "\n") {
            let l = line.trimmingCharacters(in: .whitespaces)
            if l.hasPrefix("gateway:") { return l.dropFirst(8).trimmingCharacters(in: .whitespaces) }
        }
        return nil
    }

    private func splitEndpoint(_ e: String) throws -> (String, Int) {
        if e.hasPrefix("["), let r = e.range(of: "]:"), let p = Int(e[r.upperBound...]) { return (String(e[e.index(after: e.startIndex)..<r.lowerBound]), p) }
        guard let i = e.lastIndex(of: ":"), let p = Int(e[e.index(after: i)...]), (1...65535).contains(p) else { throw VPNError.msg("bad endpoint") }
        let h = String(e[..<i])
        guard !h.isEmpty, h.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == ":" }) else { throw VPNError.msg("bad host") }
        return (h, p)
    }

    private func resolve(_ host: String) -> String? {
        if isIP(host) { return host }
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let r = res else { return nil }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(r.pointee.ai_addr, r.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: buf)
    }

    private func b64hex(_ s: String) -> String? {
        if s.count == 64, s.allSatisfy(\.isHexDigit) { return s.lowercased() }
        guard let d = Data(base64Encoded: s), d.count == 32 else { return nil }
        return d.map { String(format: "%02x", $0) }.joined()
    }
}

enum VPNError: Error {
    case msg(String)
    var text: String { if case .msg(let s) = self { return s }; return "" }
}

func isIP(_ s: String) -> Bool {
    var a = in_addr(), b = in6_addr()
    return inet_pton(AF_INET, s, &a) == 1 || inet_pton(AF_INET6, s, &b) == 1
}
