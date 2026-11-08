// Paket yakalama motoru: hem uygulama (kullanıcı modu) hem permwatch-root (yönetici modu)
// tarafından derlenir. libpcap ile yakalar, Wireshark'ın ilk bakışta gösterdiği özeti çıkarır
// (protokol, adresler, DNS adı, TLS SNI, HTTP isteği) ve isteğe bağlı olarak .pcap dosyasına yazar.
import Darwin
import Foundation

struct Packet: Codable, Identifiable, Hashable {
    var seq: Int
    var ts: Double
    var pid: Int32?
    var proc: String?
    var epid: Int32?
    var eproc: String?
    var iface: String?
    var dir: String?            // "in" / "out"
    var l3: String              // IPv4, IPv6, ARP, …
    var proto: String           // gösterilen protokol: TCP, UDP, DNS, TLS, HTTP, QUIC, ICMP…
    var src: String
    var dst: String
    var sport: Int?
    var dport: Int?
    var len: Int
    var info: String
    var host: String?           // TLS SNI, HTTP Host ya da DNS sorgu adı
    var dns: [String]?          // DNS yanıtındaki adresler
    var tcp: String?            // TCP bayrakları
    var flags: [String]?        // pkt.flag.* anahtarları
    var hex: String?            // çerçevenin ilk baytları
    /// Uygulama verisinin (başlıklardan sonrası) arabellekteki başlangıcı; dosyaya yazılmaz.
    var payloadStart: Int?

    var id: Int { seq }

    enum CodingKeys: String, CodingKey {
        case seq, ts, pid, proc, epid, eproc, iface, dir, l3, proto, src, dst, sport, dport, len, info, host, dns, tcp, flags, hex
    }
}

enum PacketParser {
    /// Apple PKTAP başlığı (xnu bsd/net/pktap.h) alan konumları.
    private enum PT {
        static let length = 0, dlt = 8, ifname = 12, flags = 36, pid = 52, comm = 56, epid = 84, ecomm = 88
        static let minLength = 108
        static let dirIn: UInt32 = 0x1, dirOut: UInt32 = 0x2
    }
    static let dltPktapApple: Int32 = 149, dltPktap: Int32 = 258

    /// payload false: hex dökümü yalnızca başlıkları içerir (uygulama verisi, ör. parolalar, saklanmaz).
    static func parse(link: Int32, _ b: UnsafeRawBufferPointer, wire: Int, ts: Double, seq: Int, payload: Bool = false) -> Packet? {
        var frame = 0
        guard var p = parseFrame(link: link, b, wire: wire, ts: ts, seq: seq, frame: &frame) else { return nil }
        let full = ["ARP", "ICMP", "ICMPv6"].contains(p.proto)
        let end = payload ? b.count : (p.payloadStart ?? (full ? b.count : min(b.count, frame + 40)))
        p.payloadStart = end
        p.hex = Reader(b).hex(frame, max(0, min(payload ? 1024 : 160, end - frame)))
        return p
    }

    private static func parseFrame(link: Int32, _ b: UnsafeRawBufferPointer, wire: Int, ts: Double, seq: Int, frame outFrame: inout Int) -> Packet? {
        var r = Reader(b)
        var pkt = Packet(seq: seq, ts: ts, l3: "?", proto: "?", src: "", dst: "", len: wire, info: "")
        var link = link
        var off = 0
        if link == dltPktapApple || link == dltPktap {
            let hl = Int(r.le32(PT.length))
            guard hl >= PT.minLength, hl <= b.count else { return nil }
            link = Int32(bitPattern: r.le32(PT.dlt))
            pkt.iface = r.cstr(PT.ifname, 24)
            let f = r.le32(PT.flags)
            pkt.dir = f & PT.dirIn != 0 ? "in" : (f & PT.dirOut != 0 ? "out" : nil)
            let pid = Int32(bitPattern: r.le32(PT.pid))
            if pid > 0 { pkt.pid = pid; pkt.proc = r.cstr(PT.comm, 17) }
            let epid = Int32(bitPattern: r.le32(PT.epid))
            if epid > 0, epid != pid { pkt.epid = epid; pkt.eproc = r.cstr(PT.ecomm, 17) }
            off = hl
            pkt.len = max(0, wire - hl)
        }
        let frame = off
        outFrame = frame

        // Bağlantı katmanı → ağ katmanı
        var l3 = -1, ethType: UInt16 = 0
        switch link {
        case 1:  // Ethernet
            guard r.has(off, 14) else { return pkt.with(info: "Ethernet") }
            ethType = r.be16(off + 12); l3 = off + 14
            if ethType == 0x8100, r.has(off, 18) { ethType = r.be16(off + 16); l3 = off + 18 }
        case 0, 108:  // NULL / LOOP (lo0, utun)
            guard r.has(off, 4) else { return nil }
            let fam = link == 0 ? r.le32(off) : UInt32(r.be16(off + 2))
            ethType = fam == 2 ? 0x0800 : ([24, 28, 30].contains(fam) ? 0x86DD : 0)
            l3 = off + 4
        case 12, 14, 101, 228, 229:  // ham IP
            guard r.has(off, 1) else { return nil }
            // macOS "pktap,all" PKTAP'sız açılınca tünel/loopback çerçevelerini 4 baytlık NULL başlığıyla
            // bırakabiliyor: bunu tanı.
            if r.has(off, 5), [2, 24, 28, 30].contains(r.le32(off)), [4, 6].contains(r.u8(off + 4) >> 4) {
                off += 4
            }
            ethType = r.u8(off) >> 4 == 6 ? 0x86DD : 0x0800
            l3 = off
        default:
            pkt.l3 = "DLT \(link)"; pkt.proto = pkt.l3; pkt.info = "—"
            return pkt
        }

        var proto: UInt8 = 0, l4 = -1, end = b.count
        switch ethType {
        case 0x0800:
            guard r.has(l3, 20) else { return nil }
            let ihl = Int(r.u8(l3) & 0x0f) * 4
            let total = Int(r.be16(l3 + 2))
            if total >= ihl { end = min(end, l3 + total) }
            proto = r.u8(l3 + 9)
            pkt.l3 = "IPv4"
            pkt.src = r.ip4(l3 + 12); pkt.dst = r.ip4(l3 + 16)
            if r.be16(l3 + 6) & 0x1fff == 0 { l4 = l3 + ihl }
        case 0x86DD:
            guard r.has(l3, 40) else { return nil }
            pkt.l3 = "IPv6"
            pkt.src = r.ip6(l3 + 8); pkt.dst = r.ip6(l3 + 24)
            end = min(end, l3 + 40 + Int(r.be16(l3 + 4)))
            proto = r.u8(l3 + 6); l4 = l3 + 40
            var hops = 0
            while [0, 43, 60, 44].contains(proto), r.has(l4, 8), hops < 6 {
                let next = r.u8(l4)
                if proto == 44 {
                    if r.be16(l4 + 2) & 0xfff8 != 0 { l4 = -1; break }
                    l4 += 8
                } else {
                    l4 += (Int(r.u8(l4 + 1)) + 1) * 8
                }
                proto = next; hops += 1
            }
        case 0x0806:
            pkt.l3 = "ARP"; pkt.proto = "ARP"
            guard r.has(l3, 28) else { return pkt }
            let op = r.be16(l3 + 6)
            pkt.src = r.ip4(l3 + 14); pkt.dst = r.ip4(l3 + 24)
            pkt.info = op == 1 ? "Who has \(pkt.dst)? Tell \(pkt.src)" : "\(pkt.src) is at \(r.mac(l3 + 8))"
            return pkt
        default:
            pkt.l3 = String(format: "0x%04x", ethType); pkt.proto = pkt.l3; pkt.info = "—"
            return pkt
        }

        r.limit = end
        guard l4 >= 0 else { return pkt.with(proto: pkt.l3, info: "Fragment") }
        switch proto {
        case 6: tcp(&pkt, &r, l4)
        case 17: udp(&pkt, &r, l4)
        case 1: pkt.proto = "ICMP"; pkt.info = icmp4(r.u8(l4))
        case 58: pkt.proto = "ICMPv6"; pkt.info = icmp6(r.u8(l4))
        default: pkt.proto = "IP/\(proto)"; pkt.info = "—"
        }
        return pkt
    }

    // MARK: TCP

    private static func tcp(_ p: inout Packet, _ r: inout Reader, _ t: Int) {
        p.proto = "TCP"
        guard r.has(t, 20) else { p.info = "TCP"; return }
        let sp = Int(r.be16(t)), dp = Int(r.be16(t + 2))
        p.sport = sp; p.dport = dp
        let doff = Int(r.u8(t + 12) >> 4) * 4
        let fl = r.u8(t + 13)
        let names: [(UInt8, String)] = [(2, "SYN"), (1, "FIN"), (4, "RST"), (8, "PSH"), (16, "ACK"), (32, "URG")]
        let fs = names.filter { fl & $0.0 != 0 }.map(\.1)
        p.tcp = fs.joined(separator: " ")
        let pl = t + doff
        p.payloadStart = min(pl, r.limit)
        let n = max(0, r.limit - pl)
        p.info = "\(sp) → \(dp) [\(p.tcp ?? "")] Len=\(n)"
        guard n > 0, r.has(pl, 1) else { return }
        let ports = [sp, dp]

        // TLS
        if r.u8(pl) == 0x16, r.has(pl, 6), r.u8(pl + 1) == 3 {
            p.proto = "TLS"
            switch r.u8(pl + 5) {
            case 1:
                p.host = sni(&r, pl + 5)
                p.info = "Client Hello" + (p.host.map { " (\($0))" } ?? "")
            case 2: p.info = "Server Hello"
            default: p.info = "Handshake"
            }
            return
        }
        if [0x14, 0x15, 0x17].contains(r.u8(pl)), r.has(pl, 3), r.u8(pl + 1) == 3, ports.contains(443) || ports.contains(8443) || ports.contains(993) {
            p.proto = "TLS"
            p.info = r.u8(pl) == 0x17 ? "Application Data" : (r.u8(pl) == 0x15 ? "Alert" : "Change Cipher Spec")
            return
        }
        let text = r.ascii(pl, min(n, 1400))
        // HTTP
        let methods = ["GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT "]
        if methods.contains(where: text.hasPrefix) {
            p.proto = "HTTP"
            let lines = text.components(separatedBy: "\r\n")
            p.info = String(lines.first?.prefix(160) ?? "")
            if let h = lines.first(where: { $0.lowercased().hasPrefix("host:") }) {
                p.host = h.dropFirst(5).trimmingCharacters(in: .whitespaces)
            }
            let low = text.lowercased()
            if low.contains("\r\nauthorization: basic") || (text.hasPrefix("POST") &&
                ["password=", "passwd=", "pwd=", "pass="].contains(where: low.contains)) {
                p.flags = ["pkt.flag.cleartextCreds"]
            } else {
                p.flags = ["pkt.flag.cleartextHTTP"]
            }
            return
        }
        if text.hasPrefix("HTTP/1.") {
            p.proto = "HTTP"
            p.info = String(text.components(separatedBy: "\r\n").first?.prefix(160) ?? "")
            return
        }
        if text.hasPrefix("SSH-") {
            p.proto = "SSH"; p.info = String(text.prefix(60)).trimmingCharacters(in: .whitespacesAndNewlines)
            return
        }
        // Şifresiz oturum açma protokolleri
        let up = text.uppercased()
        let plain: [Int: String] = [21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 25: "SMTP", 587: "SMTP"]
        if let name = plain.first(where: { ports.contains($0.key) })?.value {
            p.proto = name
            if up.hasPrefix("PASS ") || up.contains(" LOGIN ") || up.hasPrefix("AUTH PLAIN") || up.hasPrefix("AUTH LOGIN") {
                p.flags = ["pkt.flag.cleartextCreds"]
                p.info = name + ": " + (up.hasPrefix("PASS") ? "PASS ****" : "AUTH ****")
            } else {
                p.flags = ["pkt.flag.cleartextProto"]
                p.info = String(text.prefix(80)).trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }
    }

    private static func sni(_ r: inout Reader, _ hs: Int) -> String? {
        var o = hs + 4 + 2 + 32
        guard r.has(o, 1) else { return nil }
        o += 1 + Int(r.u8(o))
        guard r.has(o, 2) else { return nil }
        o += 2 + Int(r.be16(o))
        guard r.has(o, 1) else { return nil }
        o += 1 + Int(r.u8(o))
        guard r.has(o, 2) else { return nil }
        let extEnd = o + 2 + Int(r.be16(o))
        o += 2
        while o + 4 <= extEnd, r.has(o, 4) {
            let type = r.be16(o), len = Int(r.be16(o + 2))
            if type == 0, r.has(o + 4, 5) {
                let nl = Int(r.be16(o + 7))
                if r.has(o + 9, nl) { return r.ascii(o + 9, nl) }
                return nil
            }
            o += 4 + len
        }
        return nil
    }

    // MARK: UDP

    private static func udp(_ p: inout Packet, _ r: inout Reader, _ u: Int) {
        p.proto = "UDP"
        guard r.has(u, 8) else { p.info = "UDP"; return }
        let sp = Int(r.be16(u)), dp = Int(r.be16(u + 2))
        p.sport = sp; p.dport = dp
        let pl = u + 8
        p.payloadStart = min(pl, r.limit)
        let n = max(0, r.limit - pl)
        p.info = "\(sp) → \(dp) Len=\(n)"
        let ports = Set([sp, dp])
        if !ports.isDisjoint(with: [53, 5353, 5355]) {
            p.proto = ports.contains(5353) ? "mDNS" : (ports.contains(5355) ? "LLMNR" : "DNS")
            dns(&p, &r, pl)
        } else if ports.contains(443) {
            p.proto = "QUIC"
            if r.has(pl, 1) { p.info = r.u8(pl) & 0x80 != 0 ? "Long Header" : "Protected Payload" }
        } else if !ports.isDisjoint(with: [67, 68]) {
            p.proto = "DHCP"
        } else if ports.contains(123) {
            p.proto = "NTP"
        } else if ports.contains(1900) {
            p.proto = "SSDP"
        } else if !ports.isDisjoint(with: [137, 138]) {
            p.proto = "NetBIOS"
        } else if ports.contains(51820) {
            p.proto = "WireGuard"
        }
    }

    private static let qtypes: [UInt16: String] = [1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
                                                    16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"]

    private static func dns(_ p: inout Packet, _ r: inout Reader, _ d: Int) {
        guard r.has(d, 12) else { return }
        let id = r.be16(d + 2), isResp = id & 0x8000 != 0
        let rcode = id & 0x000f
        let qd = Int(r.be16(d + 4)), an = Int(r.be16(d + 6))
        var o = d + 12
        var qname = "", qtype = ""
        if qd > 0, case let (qn, next)? = name(&r, d, o), r.has(next, 4) {
            qname = qn
            qtype = qtypes[r.be16(next)] ?? "TYPE\(r.be16(next))"
            o = next + 4
        }
        p.host = qname.isEmpty ? nil : qname
        if !isResp {
            p.info = "Standard query \(qtype) \(qname)"
            return
        }
        var answers: [String] = []
        for _ in 0..<min(an, 32) {
            guard case let (_, next)? = name(&r, d, o), r.has(next, 10) else { break }
            let type = r.be16(next), rdlen = Int(r.be16(next + 8))
            let rd = next + 10
            guard r.has(rd, rdlen) else { break }
            if type == 1, rdlen == 4 { answers.append(r.ip4(rd)) }
            if type == 28, rdlen == 16 { answers.append(r.ip6(rd)) }
            if type == 5, case let (cn, _)? = name(&r, d, rd) { answers.append("CNAME " + cn) }
            o = rd + rdlen
        }
        p.dns = answers.isEmpty ? nil : answers
        let errs: [UInt16: String] = [2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"]
        if let e = errs[rcode] {
            p.info = "Response \(qtype) \(qname) \(e)"
        } else {
            let ips = answers.filter { !$0.hasPrefix("CNAME") }
            p.info = "Response \(qtype) \(qname)" + (ips.isEmpty ? "" : " → " + ips.prefix(3).joined(separator: ", "))
        }
    }

    /// DNS adı (sıkıştırma işaretçileriyle). Dönüş: ad ve adın ardındaki konum.
    private static func name(_ r: inout Reader, _ base: Int, _ start: Int) -> (String, Int)? {
        var labels: [String] = []
        var o = start, next = -1, jumps = 0
        while r.has(o, 1) {
            let l = Int(r.u8(o))
            if l == 0 { if next < 0 { next = o + 1 }; return (labels.joined(separator: "."), next) }
            if l & 0xc0 == 0xc0 {
                guard r.has(o, 2), jumps < 16 else { return nil }
                if next < 0 { next = o + 2 }
                o = base + (Int(r.be16(o)) & 0x3fff); jumps += 1
                continue
            }
            guard l < 64, r.has(o + 1, l), labels.count < 64 else { return nil }
            labels.append(r.ascii(o + 1, l)); o += 1 + l
        }
        return nil
    }

    private static func icmp4(_ t: UInt8) -> String {
        [0: "Echo (ping) reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo (ping) request",
         11: "Time-to-live exceeded"][t] ?? "Type \(t)"
    }
    private static func icmp6(_ t: UInt8) -> String {
        [1: "Destination unreachable", 3: "Time exceeded", 128: "Echo (ping) request", 129: "Echo (ping) reply",
         133: "Router Solicitation", 134: "Router Advertisement", 135: "Neighbor Solicitation",
         136: "Neighbor Advertisement", 143: "Multicast Listener Report v2"][t] ?? "Type \(t)"
    }
}

private extension Packet {
    func with(proto: String? = nil, info: String) -> Packet {
        var p = self
        if let proto { p.proto = proto }
        p.info = info
        return p
    }
}

/// Sınır denetimli bayt okuyucu.
struct Reader {
    let b: UnsafeRawBufferPointer
    var limit: Int
    init(_ b: UnsafeRawBufferPointer) { self.b = b; limit = b.count }

    func has(_ o: Int, _ n: Int) -> Bool { o >= 0 && n >= 0 && o + n <= min(limit, b.count) }
    func u8(_ o: Int) -> UInt8 { o >= 0 && o < b.count ? b[o] : 0 }
    func be16(_ o: Int) -> UInt16 { UInt16(u8(o)) << 8 | UInt16(u8(o + 1)) }
    func le32(_ o: Int) -> UInt32 {
        UInt32(u8(o)) | UInt32(u8(o + 1)) << 8 | UInt32(u8(o + 2)) << 16 | UInt32(u8(o + 3)) << 24
    }
    func cstr(_ o: Int, _ n: Int) -> String? {
        guard o + n <= b.count else { return nil }
        var bytes: [UInt8] = []
        for i in o..<(o + n) { if b[i] == 0 { break }; bytes.append(b[i]) }
        return bytes.isEmpty ? nil : String(decoding: bytes, as: UTF8.self)
    }
    func ascii(_ o: Int, _ n: Int) -> String {
        guard o >= 0, n > 0 else { return "" }
        let e = min(o + n, b.count)
        guard o < e else { return "" }
        return String(decoding: b[o..<e].map { ($0 >= 0x20 && $0 < 0x7f) || $0 == 0x0d || $0 == 0x0a ? $0 : 0x2e }, as: UTF8.self)
    }
    func ip4(_ o: Int) -> String { "\(u8(o)).\(u8(o + 1)).\(u8(o + 2)).\(u8(o + 3))" }
    func ip6(_ o: Int) -> String {
        guard o + 16 <= b.count else { return "?" }
        var a = in6_addr()
        withUnsafeMutableBytes(of: &a) { $0.copyMemory(from: UnsafeRawBufferPointer(rebasing: b[o..<(o + 16)])) }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count))
        return String(cString: buf)
    }
    func mac(_ o: Int) -> String { (0..<6).map { String(format: "%02x", u8(o + $0)) }.joined(separator: ":") }
    func hex(_ o: Int, _ n: Int) -> String {
        guard o < b.count else { return "" }
        return b[o..<min(o + n, b.count)].map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - libpcap oturumu

struct CaptureError: Error { let message: String }

final class CaptureEngine: @unchecked Sendable {
    let device: String
    private(set) var linkType: Int32 = 0
    private var handle: OpaquePointer?
    private var dumper: OpaquePointer?
    private let lock = NSLock()
    private var stopping = false
    private var seq = 0
    /// Saniyede bundan fazla paket listeye özetlenmez (hepsi yine .pcap dosyasına yazılır).
    var maxPerSecond = 1500
    private(set) var skipped = 0
    /// true (varsayılan): paketler .pcap dosyasına eksiksiz yazılır. false: yalnızca başlıklar.
    var storePayload = true
    /// Apple uzantısı: her pakete PKTAP başlığı (süreç adı/PID, arayüz, yön) eklenir ve .pcap dosyası
    /// LINKTYPE_PKTAP olarak yazılır. Olmadan "pktap,all" başlıkları atar, farklı bağlantı türlerini
    /// tek bir "ham IP" dosyasına karıştırır ve süreç bilgisi kaybolur.
    var wantPktap = false
    var onPacket: (Packet) -> Void = { _ in }

    init(device: String) { self.device = device }

    func open(snaplen: Int32 = 65535) throws {
        var err = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let h = pcap_create(device, &err) else { throw CaptureError(message: String(cString: err)) }
        pcap_set_snaplen(h, snaplen)
        pcap_set_promisc(h, 0)
        pcap_set_timeout(h, 250)
        pcap_set_immediate_mode(h, 1)
        pcap_set_buffer_size(h, 8 << 20)
        if wantPktap {
            typealias SetWant = @convention(c) (OpaquePointer?, Int32) -> Int32
            guard let lib = dlopen("/usr/lib/libpcap.A.dylib", RTLD_NOW), let sym = dlsym(lib, "pcap_set_want_pktap") else {
                pcap_close(h)
                throw CaptureError(message: "pcap_set_want_pktap")
            }
            _ = unsafeBitCast(sym, to: SetWant.self)(h, 1)
        }
        let rc = pcap_activate(h)
        if rc < 0 {
            let msg = String(cString: pcap_geterr(h))
            pcap_close(h)
            throw CaptureError(message: msg.isEmpty ? "pcap_activate \(rc)" : msg)
        }
        handle = h
        linkType = pcap_datalink(h)
        if wantPktap, linkType != PacketParser.dltPktapApple, linkType != PacketParser.dltPktap {
            pcap_close(h)
            handle = nil
            throw CaptureError(message: "PKTAP etkinleşmedi (DLT \(linkType))")
        }
    }

    /// Ham paketleri Wireshark'ın açabileceği .pcap dosyasına da yaz.
    @discardableResult
    func dump(to path: String) -> Bool {
        guard let h = handle else { return false }
        unlink(path)
        dumper = pcap_dump_open(h, path)
        return dumper != nil
    }

    func start() {
        let t = Thread { [self] in loop() }
        t.name = "permwatch.capture"
        t.qualityOfService = .userInitiated
        t.start()
    }

    func stop() {
        lock.lock(); stopping = true; lock.unlock()
    }

    private var stopped: Bool { lock.lock(); defer { lock.unlock() }; return stopping }

    private func loop() {
        guard let h = handle else { return }
        var second = 0, inSecond = 0
        var lastFlush = Date()
        while !stopped {
            var hdr: UnsafeMutablePointer<pcap_pkthdr>?
            var data: UnsafePointer<UInt8>?
            let rc = pcap_next_ex(h, &hdr, &data)
            if rc == 1, let hdr, let data {
                let ts = Double(hdr.pointee.ts.tv_sec) + Double(hdr.pointee.ts.tv_usec) / 1e6
                let buf = UnsafeRawBufferPointer(start: data, count: Int(hdr.pointee.caplen))
                let p = PacketParser.parse(link: linkType, buf, wire: Int(hdr.pointee.len), ts: ts, seq: seq + 1,
                                           payload: storePayload)
                if let d = dumper {
                    var h = hdr.pointee
                    var start = data
                    // Ham IP dosyasına NULL başlıklı çerçeve yazma: başlığı at, dosya tutarlı kalsın.
                    if [12, 14, 101].contains(linkType), h.caplen > 5,
                       [2, 24, 28, 30].contains(Reader(buf).le32(0)), [4, 6].contains(data[4] >> 4) {
                        start = data + 4; h.caplen -= 4; h.len -= 4
                    }
                    if !storePayload { h.caplen = UInt32(min(Int(h.caplen), max(0, (p?.payloadStart ?? 64) - (start - data)))) }
                    pcap_dump(UnsafeMutablePointer<UInt8>(d), &h, start)
                }
                let s = Int(ts)
                if s != second { second = s; inSecond = 0 }
                inSecond += 1
                if inSecond > maxPerSecond { skipped += 1; continue }
                seq += 1
                if let p { onPacket(p) }
            } else if rc < 0 {
                break
            }
            if let d = dumper, Date().timeIntervalSince(lastFlush) > 1 {
                pcap_dump_flush(d); lastFlush = Date()
            }
        }
        if let d = dumper { pcap_dump_close(d); dumper = nil }
        pcap_close(h)
        handle = nil
    }

    /// Yakalanabilecek arayüzler (ad, açıklama).
    static func devices() -> [(name: String, desc: String)] {
        var list: UnsafeMutablePointer<pcap_if_t>?
        var err = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard pcap_findalldevs(&list, &err) == 0 else { return [] }
        defer { pcap_freealldevs(list) }
        var out: [(String, String)] = []
        var cur = list
        while let d = cur {
            let name = String(cString: d.pointee.name)
            let up = d.pointee.flags & UInt32(PCAP_IF_UP) != 0
            if up, !name.hasPrefix("pktap") {
                out.append((name, d.pointee.description.map { String(cString: $0) } ?? ""))
            }
            cur = d.pointee.next
        }
        return out
    }
}
