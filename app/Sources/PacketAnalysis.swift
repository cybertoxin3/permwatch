import Darwin
import Foundation
import Security
import SwiftUI

// MARK: - Filtre dili

/// Paket filtresi. Boşlukla ayrılan her terim sağlanmalı (VE). Terimler:
///   serbest metin          süreç, adres, ad, protokol, bilgi içinde arar
///   ip:1.2.3.4             kaynak ya da hedef adres (önek de olur: ip:192.168.)
///   src:… dst:…            yalnızca kaynak / hedef
///   port:443               kaynak ya da hedef kapı
///   proto:dns              protokol (TCP, UDP, TLS, HTTP, ARP…)
///   proc:chrome            süreç adı
///   host:google            alan adı (SNI, DNS, HTTP Host ya da çözülmüş ad)
///   dir:in | dir:out       yön
///   len>1000  len<60       uzunluk
///   flag:syn               TCP bayrağı
///   seq:12,15,20           paket numaraları (analizdeki "Paketleri göster")
///   stream:A|B             iki uç arasındaki akış (ör. 10.0.0.2:5000|1.1.1.1:443)
///   -terim  !terim         hariç tut
enum PacketFilter {
    static func matches(_ p: Packet, query: String, names: [String: String]) -> Bool {
        let terms = query.split(separator: " ").map(String.init).filter { !$0.isEmpty }
        return terms.allSatisfy { term in
            var t = term.lowercased()
            var negate = false
            if t.count > 1, t.hasPrefix("-") || t.hasPrefix("!") { negate = true; t.removeFirst() }
            let hit = match(p, t, names: names)
            return negate ? !hit : hit
        }
    }

    private static func match(_ p: Packet, _ t: String, names: [String: String]) -> Bool {
        func val(_ k: String) -> String? { t.hasPrefix(k) ? String(t.dropFirst(k.count)) : nil }
        let src = p.src.lowercased(), dst = p.dst.lowercased()
        if let v = val("ip:") { return src.hasPrefix(v) || dst.hasPrefix(v) }
        if let v = val("src:") { return src.hasPrefix(v) || (names[p.src]?.lowercased().contains(v) ?? false) }
        if let v = val("dst:") { return dst.hasPrefix(v) || (names[p.dst]?.lowercased().contains(v) ?? false) }
        if let v = val("port:"), let n = Int(v) { return p.sport == n || p.dport == n }
        if let v = val("proto:") { return p.proto.lowercased() == v || p.l3.lowercased() == v }
        if let v = val("proc:") { return [p.proc, p.eproc].compactMap { $0?.lowercased() }.contains { $0.contains(v) } }
        if let v = val("host:") {
            return [p.host, names[p.src], names[p.dst]].compactMap { $0?.lowercased() }.contains { $0.contains(v) }
        }
        if let v = val("dir:") { return p.dir == v }
        if let v = val("flag:") { return p.tcp?.lowercased().split(separator: " ").contains { $0 == v } ?? false }
        if let v = val("len>"), let n = Int(v) { return p.len > n }
        if let v = val("len<"), let n = Int(v) { return p.len < n }
        if let v = val("seq:") { return v.split(separator: ",").compactMap { Int($0) }.contains(p.seq) }
        if let v = val("stream:") {
            let ends = v.split(separator: "|").map(String.init)
            guard ends.count == 2 else { return false }
            let a = "\(src):\(p.sport ?? 0)", b = "\(dst):\(p.dport ?? 0)"
            return Set([a, b]) == Set(ends)
        }
        var hay: [String?] = [p.proc, p.eproc, p.src, p.dst, p.proto, p.l3, p.info, p.host, p.iface]
        hay.append(names[p.src]); hay.append(names[p.dst])
        if let sp = p.sport { hay.append(String(sp)) }
        if let dp = p.dport { hay.append(String(dp)) }
        return hay.contains { ($0 ?? "").lowercased().contains(t) }
    }

    /// Bir paketin ait olduğu akışın filtre terimi.
    static func stream(of p: Packet) -> String {
        "stream:\(p.src):\(p.sport ?? 0)|\(p.dst):\(p.dport ?? 0)".lowercased()
    }
}

// MARK: - Güvenlik analizi

struct SecFinding: Identifiable, Hashable {
    enum Severity: Int, Comparable {
        case info = 0, medium = 1, high = 2
        static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
        var color: Color { self == .high ? .red : self == .medium ? .orange : .blue }
        var icon: String { self == .high ? "xmark.octagon.fill" : self == .medium ? "exclamationmark.triangle.fill" : "info.circle.fill" }
        var label: String { L("pa.sev.\(rawValue)") }
    }
    let id: String
    let severity: Severity
    let title: String
    let detail: String
    /// MITRE ATT&CK tekniği (ör. T1046).
    let technique: String?
    /// Ne yapılmalı.
    let advice: String
    /// "Paketleri göster": paket listesine uygulanacak filtre.
    let filter: String?
    let count: Int
}

enum PacketAnalyzer {
    /// Bu Mac'in adresleri (kendi taramamızı "saldırı" sanmamak için).
    static func localAddresses() -> Set<String> {
        var out = Set<String>()
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return out }
        defer { freeifaddrs(list) }
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let i = cur {
            if let a = i.pointee.ifa_addr {
                var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let len = socklen_t(a.pointee.sa_family == UInt8(AF_INET6) ? MemoryLayout<sockaddr_in6>.size : MemoryLayout<sockaddr_in>.size)
                if [UInt8(AF_INET), UInt8(AF_INET6)].contains(a.pointee.sa_family),
                   getnameinfo(a, len, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                    out.insert(String(cString: buf).components(separatedBy: "%").first ?? "")
                }
            }
            cur = i.pointee.ifa_next
        }
        return out
    }

    static func entropy(_ s: String) -> Double {
        let chars = Array(s)
        guard !chars.isEmpty else { return 0 }
        var freq: [Character: Int] = [:]
        for c in chars { freq[c, default: 0] += 1 }
        return freq.values.reduce(0) { acc, n in
            let p = Double(n) / Double(chars.count)
            return acc - p * log2(p)
        }
    }

    static func seqFilter(_ ps: [Packet]) -> String { "seq:" + ps.prefix(400).map { String($0.seq) }.joined(separator: ",") }

    static func analyze(_ packets: [Packet], names: [String: String]) -> [SecFinding] {
        let me = localAddresses()
        var out: [SecFinding] = []
        func add(_ id: String, _ sev: SecFinding.Severity, _ title: String, _ detail: String, _ tech: String?, _ advice: String,
                 _ filter: String?, _ n: Int) {
            out.append(SecFinding(id: id, severity: sev, title: title, detail: detail, technique: tech, advice: advice, filter: filter, count: n))
        }

        // 1) ARP: tarama ve zehirlenme
        var asks: [String: Set<String>] = [:], askPkts: [String: [Packet]] = [:]
        var ipToMac: [String: Set<String>] = [:], macToIP: [String: Set<String>] = [:], replyPkts: [String: [Packet]] = [:]
        for p in packets where p.proto == "ARP" {
            if p.info.hasPrefix("Who has") {
                asks[p.src, default: []].insert(p.dst); askPkts[p.src, default: []].append(p)
            } else if let r = p.info.range(of: " is at ") {
                let mac = String(p.info[r.upperBound...]).lowercased()
                ipToMac[p.src, default: []].insert(mac); macToIP[mac, default: []].insert(p.src)
                replyPkts[p.src, default: []].append(p)
            }
        }
        // Büyük ağlarda cihazlar sürekli komşu sorar; tarama hızla çok sayıda farklı adres sormaktır:
        // toplam 100+ farklı adres ya da herhangi bir 10 saniyede 40+ farklı adres.
        func burst(_ ps: [Packet]) -> Int {
            let s = ps.sorted { $0.ts < $1.ts }
            var best = 0, lo = 0
            var window: [String: Int] = [:]
            for (hi, p) in s.enumerated() {
                window[p.dst, default: 0] += 1
                while s[hi].ts - s[lo].ts > 10 {
                    window[s[lo].dst]! -= 1
                    if window[s[lo].dst] == 0 { window[s[lo].dst] = nil }
                    lo += 1
                }
                best = max(best, window.count)
            }
            return best
        }
        for (src, targets) in asks where targets.count >= 100 || (targets.count >= 40 && burst(askPkts[src] ?? []) >= 40) {
            let mine = me.contains(src)
            add("arpscan.\(src)", mine ? .info : .medium, L("pa.arpScan.title", src),
                L(mine ? "pa.arpScan.mine" : "pa.arpScan.body", targets.count), "T1018",
                L(mine ? "pa.arpScan.mineAdvice" : "pa.arpScan.advice"), seqFilter(askPkts[src] ?? []), targets.count)
        }
        for (ip, macs) in ipToMac where macs.count > 1 {
            add("arpspoof.\(ip)", .high, L("pa.arpSpoof.title", ip), L("pa.arpSpoof.body", macs.sorted().joined(separator: ", ")),
                "T1557.002", L("pa.arpSpoof.advice"), seqFilter(replyPkts[ip] ?? []), macs.count)
        }
        for (mac, ips) in macToIP where ips.count >= 4 {
            add("arpmulti.\(mac)", .medium, L("pa.arpMulti.title", mac), L("pa.arpMulti.body", ips.count, ips.sorted().prefix(6).joined(separator: ", ")),
                "T1557.002", L("pa.arpSpoof.advice"), "proto:arp " + mac, ips.count)
        }

        // 2) Port taraması (yanıtsız SYN'ler): dikey (bir hedefte çok kapı) ve yatay (çok hedefte bir kapı)
        let syns = packets.filter { $0.tcp == "SYN" }
        var vertical: [String: Set<Int>] = [:], vPkts: [String: [Packet]] = [:]
        var horizontal: [String: Set<String>] = [:], hPkts: [String: [Packet]] = [:]
        for p in syns {
            guard let dp = p.dport else { continue }
            let vk = p.src + ">" + p.dst
            vertical[vk, default: []].insert(dp); vPkts[vk, default: []].append(p)
            let hk = p.src + ">" + String(dp)
            horizontal[hk, default: []].insert(p.dst); hPkts[hk, default: []].append(p)
        }
        for (k, ports) in vertical where ports.count >= 15 {
            let parts = k.components(separatedBy: ">"); let src = parts[0], dst = parts[1]
            let inbound = me.contains(dst) && !me.contains(src)
            add("portscan.\(k)", inbound ? .high : .medium, L("pa.portScan.title", src, dst),
                L("pa.portScan.body", ports.count, ports.sorted().prefix(12).map(String.init).joined(separator: ", ")), "T1046",
                L(inbound ? "pa.portScan.adviceIn" : "pa.portScan.adviceOut"), seqFilter(vPkts[k] ?? []), ports.count)
        }
        for (k, hosts) in horizontal where hosts.count >= 20 {
            let parts = k.components(separatedBy: ">")
            add("sweep.\(k)", .medium, L("pa.sweep.title", parts[0], parts[1]), L("pa.sweep.body", hosts.count, parts[1]), "T1046",
                L("pa.portScan.adviceOut"), seqFilter(hPkts[k] ?? []), hosts.count)
        }

        // 3) Şifresiz parola ve şifresiz protokoller
        let creds = packets.filter { $0.flags?.contains("pkt.flag.cleartextCreds") == true }
        if !creds.isEmpty {
            let where_ = Set(creds.map { (names[$0.dst] ?? $0.dst) + ":\($0.dport ?? 0)" }).sorted().prefix(5).joined(separator: ", ")
            add("creds", .high, L("pa.creds.title"), L("pa.creds.body", creds.count, where_), "T1040", L("pa.creds.advice"),
                seqFilter(creds), creds.count)
        }
        let plainProtos: Set<String> = ["HTTP", "FTP", "Telnet", "POP3", "IMAP", "SMTP"]
        let plain = packets.filter { plainProtos.contains($0.proto) && !($0.flags?.contains("pkt.flag.cleartextCreds") ?? false) }
        if !plain.isEmpty {
            let hosts = Set(plain.map { $0.host ?? names[$0.dst] ?? $0.dst }).sorted()
            add("plain", .medium, L("pa.plain.title"), L("pa.plain.body", Set(plain.map(\.proto)).sorted().joined(separator: ", "),
                hosts.prefix(6).joined(separator: ", ")), "T1040", L("pa.plain.advice"), seqFilter(plain), plain.count)
        }

        // 4) Sahte DHCP sunucusu: birden fazla sunucu teklif veriyor
        let dhcpServers = Set(packets.filter { $0.proto == "DHCP" && $0.sport == 67 && $0.src != "0.0.0.0" }.map(\.src))
        if dhcpServers.count > 1 {
            add("dhcp", .high, L("pa.dhcp.title"), L("pa.dhcp.body", dhcpServers.sorted().joined(separator: ", ")), "T1557.003",
                L("pa.dhcp.advice"), "proto:dhcp port:67", dhcpServers.count)
        }

        // 5) Ad çözümleme zehirlenmesine açık protokoller (Responder)
        let poison = packets.filter { $0.proto == "LLMNR" || $0.proto == "NetBIOS" }
        if !poison.isEmpty {
            add("llmnr", .info, L("pa.llmnr.title"), L("pa.llmnr.body", poison.count), "T1557.001", L("pa.llmnr.advice"),
                "proto:llmnr", poison.count)
        }

        // 6) DNS: tünelleme / rastgele üretilmiş adlar
        var oddNames: [Packet] = [], perDomain: [String: Set<String>] = [:]
        for p in packets where p.proto == "DNS" {
            guard let h = p.host?.lowercased(), h.contains(".") else { continue }
            let labels = h.split(separator: ".").map(String.init)
            let first = labels.first ?? ""
            if first.count >= 40 || (first.count >= 20 && entropy(first) >= 4.0) { oddNames.append(p) }
            if labels.count >= 3 { perDomain[labels.suffix(2).joined(separator: "."), default: []].insert(h) }
        }
        if !oddNames.isEmpty {
            let sample = Set(oddNames.compactMap(\.host)).sorted().prefix(3).joined(separator: "\n")
            add("dnsodd", .medium, L("pa.dnsOdd.title"), L("pa.dnsOdd.body", oddNames.count, sample), "T1071.004",
                L("pa.dnsOdd.advice"), seqFilter(oddNames), oddNames.count)
        }
        for (dom, subs) in perDomain where subs.count >= 60 {
            add("dnsmany.\(dom)", .medium, L("pa.dnsMany.title", dom), L("pa.dnsMany.body", subs.count), "T1071.004",
                L("pa.dnsOdd.advice"), "host:" + dom, subs.count)
        }

        // 7) Tehdit listeleri (zararlı yazılım / oltalama sunucuları)
        var intelHits: [String: (String, [Packet])] = [:]
        for p in packets {
            for (ip, host) in [(p.dst, p.host ?? names[p.dst]), (p.src, names[p.src])] where !Conversation.isLocal(ip) {
                if let m = ThreatIntel.store.match(ip: ip, host: host) {
                    intelHits[m.0, default: (m.1, [])].1.append(p)
                }
            }
        }
        for (what, v) in intelHits {
            add("intel.\(what)", .high, L("pa.intel.title", what), L("pa.intel.body", v.0, v.1.count), "T1071",
                L("pa.intel.advice"), seqFilter(v.1), v.1.count)
        }

        // 8) Şüpheli kapılar (arka kapı / IRC / Tor)
        let bad = packets.filter { p in [p.dport, p.sport].compactMap { $0 }.contains { NetworkMonitor.badPorts.contains($0) } }
        if !bad.isEmpty {
            let ports = Set(bad.compactMap { p in [p.dport, p.sport].compactMap { $0 }.first { NetworkMonitor.badPorts.contains($0) } })
            add("badport", .medium, L("pa.badPort.title"), L("pa.badPort.body", ports.sorted().map(String.init).joined(separator: ", ")),
                "T1571", L("pa.badPort.advice"), seqFilter(bad), bad.count)
        }

        // 9) Düzenli aralıklı bağlantı (komuta-kontrol "beacon" belirtisi)
        var starts: [String: [Packet]] = [:]
        for p in syns where me.contains(p.src) && !Conversation.isLocal(p.dst) {
            starts["\(p.eproc ?? p.proc ?? "?")>\(p.dst):\(p.dport ?? 0)", default: []].append(p)
        }
        for (k, ps) in starts where ps.count >= 6 {
            let t = ps.map(\.ts).sorted()
            let gaps = zip(t.dropFirst(), t).map { $0 - $1 }.filter { $0 > 0.5 }
            guard gaps.count >= 5 else { continue }
            let mean = gaps.reduce(0, +) / Double(gaps.count)
            let sd = sqrt(gaps.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(gaps.count))
            guard mean >= 5, sd / mean < 0.15 else { continue }
            let parts = k.components(separatedBy: ">")
            add("beacon.\(k)", .medium, L("pa.beacon.title", parts[0]), L("pa.beacon.body", parts[1], Int(mean.rounded()), ps.count),
                "T1071", L("pa.beacon.advice"), seqFilter(ps), ps.count)
        }

        // 10) Büyük yükleme (veri sızdırma belirtisi)
        var upload: [String: (Int, [Packet])] = [:]
        for p in packets where p.dir == "out" && !Conversation.isLocal(p.dst) && me.contains(p.src) {
            let k = "\(p.eproc ?? p.proc ?? "?")>\(p.dst)"
            upload[k, default: (0, [])].0 += p.len
            if upload[k]!.1.count < 400 { upload[k]!.1.append(p) }
        }
        for (k, v) in upload where v.0 >= 50 << 20 {
            let parts = k.components(separatedBy: ">")
            add("upload.\(k)", .medium, L("pa.upload.title", parts[0]),
                L("pa.upload.body", ByteCountFormatter.string(fromByteCount: Int64(v.0), countStyle: .file), names[parts[1]] ?? parts[1]),
                "T1041", L("pa.upload.advice"), "proc:\(parts[0].lowercased()) dst:\(parts[1]) dir:out", v.1.count)
        }

        // 11) Büyük ICMP paketleri (ICMP tünelleme)
        let bigICMP = packets.filter { ($0.proto == "ICMP" || $0.proto == "ICMPv6") && $0.len > 300 }
        if bigICMP.count >= 5 {
            add("icmp", .medium, L("pa.icmp.title"), L("pa.icmp.body", bigICMP.count), "T1095", L("pa.icmp.advice"),
                seqFilter(bigICMP), bigICMP.count)
        }

        // 12) Şifresiz DNS (bilgi)
        let plainDNS = packets.filter { $0.proto == "DNS" && !Conversation.isLocal($0.dst) && $0.dir == "out" }
        if plainDNS.count >= 10 {
            add("dnsplain", .info, L("pa.dnsPlain.title"), L("pa.dnsPlain.body", plainDNS.count, Set(plainDNS.map(\.dst)).sorted().prefix(3).joined(separator: ", ")),
                nil, L("pa.dnsPlain.advice"), "proto:dns dir:out", plainDNS.count)
        }

        return out.sorted { ($0.severity, $0.count) > ($1.severity, $1.count) }
    }
}

// MARK: - İstatistik

struct PacketStats {
    struct Row: Identifiable { var id: String { name }; let name: String; let packets: Int; let bytes: Int }
    var protocols: [Row] = []
    var talkers: [Row] = []
    var processes: [Row] = []
    var ports: [Row] = []
    /// Saniye başına paket (zaman ekseni), en fazla 120 dilim.
    var timeline: [Int] = []
    var duration: Double = 0

    static func compute(_ packets: [Packet], names: [String: String]) -> PacketStats {
        var s = PacketStats()
        func top(_ d: [String: (Int, Int)], _ n: Int = 10) -> [Row] {
            d.map { Row(name: $0.key, packets: $0.value.0, bytes: $0.value.1) }.sorted { $0.bytes > $1.bytes }.prefix(n).map { $0 }
        }
        var proto: [String: (Int, Int)] = [:], talk: [String: (Int, Int)] = [:], proc: [String: (Int, Int)] = [:], port: [String: (Int, Int)] = [:]
        func bump(_ d: inout [String: (Int, Int)], _ k: String, _ len: Int) { let v = d[k] ?? (0, 0); d[k] = (v.0 + 1, v.1 + len) }
        for p in packets {
            bump(&proto, p.proto, p.len)
            if !p.src.isEmpty { bump(&talk, names[p.src].map { "\($0) (\(p.src))" } ?? p.src, p.len) }
            if !p.dst.isEmpty { bump(&talk, names[p.dst].map { "\($0) (\(p.dst))" } ?? p.dst, p.len) }
            if let n = p.eproc ?? p.proc { bump(&proc, n, p.len) }
            if let d = [p.dport, p.sport].compactMap({ $0 }).min() { bump(&port, "\(d)/\(p.tcp != nil ? "tcp" : "udp")", p.len) }
        }
        s.protocols = top(proto, 14); s.talkers = top(talk); s.processes = top(proc); s.ports = top(port)
        if let a = packets.map(\.ts).min(), let b = packets.map(\.ts).max(), b > a {
            s.duration = b - a
            let n = min(120, max(1, Int((b - a).rounded(.up))))
            var buckets = [Int](repeating: 0, count: n)
            for p in packets { buckets[min(n - 1, Int((p.ts - a) / (b - a) * Double(n)))] += 1 }
            s.timeline = buckets
        }
        return s
    }
}

// MARK: - Görünümler

struct PacketAnalysisPane: View {
    @EnvironmentObject var cap: PacketMonitor
    /// "Paketleri göster": filtreyi uygular ve paket listesine geçer.
    let show: (String) -> Void
    @State private var findings: [SecFinding] = []
    @State private var stats = PacketStats()
    @State private var computedAt = -1

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Label(L("pa.title"), systemImage: "shield.lefthalf.filled").font(.system(size: 15, weight: .bold))
                    Spacer()
                    Text(L("pa.based", cap.packets.count.formatted())).font(.system(size: 11)).foregroundStyle(.secondary)
                    Button { recompute() } label: { Image(systemName: "arrow.clockwise") }.help(L("disk.rescan"))
                }
                if findings.isEmpty {
                    Label(L("pa.none"), systemImage: "checkmark.seal.fill").foregroundStyle(.green).font(.system(size: 13))
                } else {
                    ForEach(findings) { f in FindingCard(f: f, show: show) }
                }
                Divider()
                TLSAuditView()
                Divider()
                Label(L("pa.stats"), systemImage: "chart.bar.xaxis").font(.system(size: 15, weight: .bold))
                if !stats.timeline.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(L("pa.timeline", Int(stats.duration.rounded()))).font(.system(size: 11)).foregroundStyle(.secondary)
                        Sparkline(values: stats.timeline).frame(height: 54)
                    }
                }
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 16), GridItem(.flexible())], alignment: .leading, spacing: 16) {
                    StatList(title: L("pa.protocols"), rows: stats.protocols) { show("proto:" + $0.lowercased()) }
                    StatList(title: L("pa.talkers"), rows: stats.talkers) { n in
                        let ip = n.components(separatedBy: "(").last?.trimmingCharacters(in: CharacterSet(charactersIn: ") ")) ?? n
                        show("ip:" + ip)
                    }
                    StatList(title: L("pa.processes"), rows: stats.processes) { show("proc:" + $0.lowercased()) }
                    StatList(title: L("pa.ports"), rows: stats.ports) { show("port:" + ($0.components(separatedBy: "/").first ?? $0)) }
                }
            }
            .padding(18)
            .frame(maxWidth: 1100, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .onAppear { recompute() }
        .onChange(of: cap.packets.count) { _, n in
            // Canlı yakalamada her pakette değil, belirgin artışta yeniden hesapla.
            if n == 0 || abs(n - computedAt) >= max(200, computedAt / 10) { recompute() }
        }
    }

    private func recompute() {
        let ps = cap.packets, names = cap.names
        computedAt = ps.count
        Task.detached(priority: .userInitiated) {
            let f = PacketAnalyzer.analyze(ps, names: names)
            let s = PacketStats.compute(ps, names: names)
            await MainActor.run { findings = f; stats = s }
        }
    }
}

struct FindingCard: View {
    let f: SecFinding
    let show: (String) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: f.severity.icon).font(.system(size: 18)).foregroundStyle(f.severity.color).frame(width: 22)
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(f.title).font(.system(size: 13, weight: .semibold))
                    Text(f.severity.label).font(.system(size: 10, weight: .semibold)).padding(.horizontal, 6).padding(.vertical, 1)
                        .foregroundStyle(f.severity.color).background(f.severity.color.opacity(0.14), in: Capsule())
                    if let t = f.technique {
                        Link("MITRE \(t)", destination: URL(string: "https://attack.mitre.org/techniques/\(t.replacingOccurrences(of: ".", with: "/"))/")!)
                            .font(.system(size: 10.5))
                    }
                }
                Text(f.detail).font(.system(size: 12)).foregroundStyle(.secondary).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(f.advice).font(.system(size: 12)).frame(maxWidth: .infinity, alignment: .leading)
                if let q = f.filter {
                    Button(L("pa.showPackets", f.count.formatted())) { show(q) }.controlSize(.small)
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(f.severity.color.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(f.severity.color.opacity(0.25)))
    }
}

struct StatList: View {
    let title: String
    let rows: [PacketStats.Row]
    let tap: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased(with: .current)).font(.system(size: 10.5, weight: .semibold)).foregroundStyle(.secondary)
            let maxB = Double(rows.first?.bytes ?? 1)
            ForEach(rows) { r in
                Button { tap(r.name) } label: {
                    HStack(spacing: 8) {
                        Text(r.name).lineLimit(1).truncationMode(.middle).frame(maxWidth: .infinity, alignment: .leading)
                        Bar(fraction: Double(r.bytes) / max(maxB, 1), color: .accentColor).frame(width: 70)
                        Text(ByteCountFormatter.string(fromByteCount: Int64(r.bytes), countStyle: .file))
                            .monospacedDigit().foregroundStyle(.secondary).frame(width: 64, alignment: .trailing)
                    }
                    .font(.system(size: 11.5))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(L("pa.packetsCount", r.packets.formatted()))
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .controlBackgroundColor)))
    }
}

struct Sparkline: View {
    let values: [Int]

    var body: some View {
        GeometryReader { g in
            let m = Double(values.max() ?? 1)
            HStack(alignment: .bottom, spacing: 1) {
                ForEach(Array(values.enumerated()), id: \.offset) { _, v in
                    RoundedRectangle(cornerRadius: 1).fill(Color.accentColor.opacity(0.75))
                        .frame(height: max(1, g.size.height * Double(v) / max(m, 1)))
                }
            }
            .frame(maxHeight: .infinity, alignment: .bottom)
        }
    }
}

// MARK: - Akışı izle

struct StreamView: View {
    @EnvironmentObject var cap: PacketMonitor
    @Environment(\.dismiss) private var dismiss
    let anchor: Packet
    @State private var hexMode = false

    private var packets: [Packet] {
        let q = PacketFilter.stream(of: anchor)
        return cap.packets.filter { PacketFilter.matches($0, query: q, names: cap.names) }
    }

    var body: some View {
        let ps = packets
        let a = "\(anchor.src):\(anchor.sport ?? 0)"
        let toB = ps.filter { "\($0.src):\($0.sport ?? 0)" == a }.reduce(0) { $0 + $1.len }
        let toA = ps.reduce(0) { $0 + $1.len } - toB
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L("pa.stream.title")).font(.system(size: 15, weight: .bold))
                    Text("\(cap.displayName(anchor.src)):\(anchor.sport ?? 0)  ⇄  \(cap.displayName(anchor.dst)):\(anchor.dport ?? 0)")
                        .font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Spacer()
                Picker("", selection: $hexMode) {
                    Text("ASCII").tag(false)
                    Text("Hex").tag(true)
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 140)
            }
            HStack(spacing: 14) {
                Label(L("pa.stream.out", ByteCountFormatter.string(fromByteCount: Int64(toB), countStyle: .file)), systemImage: "arrow.up")
                    .foregroundStyle(.red)
                Label(L("pa.stream.in", ByteCountFormatter.string(fromByteCount: Int64(toA), countStyle: .file)), systemImage: "arrow.down")
                    .foregroundStyle(.blue)
                Text(L("pa.packetsCount", ps.count.formatted())).foregroundStyle(.secondary)
            }
            .font(.system(size: 12))
            if ps.allSatisfy({ $0.pl == nil }) {
                Label(L("pa.stream.noPayload"), systemImage: "info.circle").font(.system(size: 11.5)).foregroundStyle(.orange)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(ps) { p in
                        let fromA = "\(p.src):\(p.sport ?? 0)" == a
                        VStack(alignment: .leading, spacing: 2) {
                            Text("#\(p.seq)  \(Fmt.packetTime.string(from: Date(timeIntervalSince1970: p.ts)))  \(fromA ? "→" : "←")  \(p.proto)  \(p.len) B  \(p.tcp ?? "")")
                                .font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.secondary)
                            let body = Self.payload(p, hex: hexMode)
                            if !body.isEmpty {
                                Text(body).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                                    .foregroundStyle(fromA ? Color.red : Color.blue)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding(6)
                        .background((fromA ? Color.red : Color.blue).opacity(0.05), in: RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            HStack {
                Button(L("pa.stream.copy")) {
                    let t = ps.map { Self.payload($0, hex: hexMode) }.filter { !$0.isEmpty }.joined(separator: "\n")
                    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(t, forType: .string)
                }
                Spacer()
                Button(L("common.ok")) { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(18)
        .frame(width: 760, height: 560)
    }

    /// Paketin uygulama verisi (başlıklar atlanır). İçerik saklanmadıysa boş.
    static func payload(_ p: Packet, hex: Bool) -> String {
        guard let h = p.hex, let start = p.pl else { return "" }
        let bytes = stride(from: start * 2, to: h.count - 1, by: 2).compactMap { i -> UInt8? in
            let s = h.index(h.startIndex, offsetBy: i)
            return UInt8(h[s..<h.index(s, offsetBy: 2)], radix: 16)
        }
        guard !bytes.isEmpty else { return "" }
        if hex { return PacketDetail.dump(bytes.map { String(format: "%02x", $0) }.joined()) }
        return String(bytes.map { b -> Character in
            b == 0x0a ? "\n" : (b >= 0x20 && b < 0x7f ? Character(UnicodeScalar(b)) : "·")
        })
    }
}

// MARK: - Sürekli ağ izleme (uygulama tarafı)

/// Yönetici yardımcısının sürekli topladığı ARP/DHCP/SYN özetlerini analiz motorundan geçirir ve yeni
/// (uyarı ya da kritik) bulguları tehdit penceresinde gösterir. Paket yakalama açık olmasa da çalışır.
@MainActor
final class NetWatchMonitor: ObservableObject {
    static let shared = NetWatchMonitor()
    static let enabledKey = "netWatch"

    @Published var enabled: Bool = UserDefaults.standard.object(forKey: NetWatchMonitor.enabledKey) as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(enabled, forKey: Self.enabledKey)
            RootBridge.shared.set("netwatch", enabled)
        }
    }
    @Published private(set) var findings: [SecFinding] = []
    @Published private(set) var lastCheck: Date?
    private var timer: Timer?
    private var busy = false

    private init() {
        RootBridge.shared.set("netwatch", enabled)
        guard Snapshot.section == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 20, repeats: true) { _ in
            MainActor.assumeIsolated { NetWatchMonitor.shared.check() }
        }
    }

    var active: Bool { enabled && (RootBridge.shared.data?.netWatchActive ?? false) && RootBridge.shared.active }

    func check() {
        guard enabled, !busy, let d = RootBridge.shared.data, d.fresh, !d.netPackets.isEmpty else { return }
        busy = true
        let ps = d.netPackets
        Task.detached(priority: .utility) {
            // Yalnızca saldırı türleri: tarama, zehirlenme, sahte DHCP (bilgi düzeyindekiler uyarı olmaz).
            let f = PacketAnalyzer.analyze(ps, names: [:]).filter { $0.severity >= .medium }
            await MainActor.run {
                self.busy = false
                self.findings = f
                self.lastCheck = Date()
                for x in f {
                    ThreatCenter.shared.report(Threat(id: "netwatch.\(x.id)", risk: x.severity == .high ? .high : .caution,
                                                      title: x.title, detail: x.detail, iconKey: nil,
                                                      section: .packets, focus: .none))
                }
            }
        }
    }
}

// MARK: - TLS sertifika denetimi

/// TLS 1.3'te sertifika şifreli gider; yakalanan paketlerden okunamaz. Bu yüzden görülen sunuculara kısa bir
/// TLS el sıkışması yapılır (veri gönderilmez, hemen kesilir) ve zincir macOS'un kendi doğrulamasından geçirilir.
struct TLSCheck: Identifiable, Hashable {
    enum Verdict: Int { case ok = 0, expiring = 1, untrustedRoot = 2, invalid = 3, unreachable = 4 }
    var id: String { host }
    let host: String
    let verdict: Verdict
    let issuer: String?
    let root: String?
    let expires: Date?
    let error: String?
}

final class TLSProbe: NSObject, URLSessionDelegate, @unchecked Sendable {
    private var trust: SecTrust?

    /// Sistemin hazır güvendiği kök sertifikalar (kullanıcının sonradan eklediği kökler bunlarda yok).
    static let systemRoots: Set<Data> = {
        var out: CFArray?
        guard SecTrustCopyAnchorCertificates(&out) == errSecSuccess, let list = out as? [SecCertificate] else { return [] }
        return Set(list.map { SecCertificateCopyData($0) as Data })
    }()

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            trust = challenge.protectionSpace.serverTrust
        }
        // Sertifikayı aldık: isteği hiç göndermeden kes.
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    static func check(_ host: String) async -> TLSCheck {
        let probe = TLSProbe()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 8
        cfg.urlCache = nil
        let session = URLSession(configuration: cfg, delegate: probe, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        guard let url = URL(string: "https://\(host)/") else {
            return TLSCheck(host: host, verdict: .unreachable, issuer: nil, root: nil, expires: nil, error: nil)
        }
        var req = URLRequest(url: url)
        req.httpMethod = "HEAD"
        _ = try? await session.data(for: req)
        guard let trust = probe.trust else {
            return TLSCheck(host: host, verdict: .unreachable, issuer: nil, root: nil, expires: nil, error: nil)
        }
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
        var err: CFError?
        let valid = SecTrustEvaluateWithError(trust, &err)
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        let leaf = chain.first
        let issuer = chain.count > 1 ? SecCertificateCopySubjectSummary(chain[1]) as String? : nil
        let anchor = chain.last
        let rootName = anchor.flatMap { SecCertificateCopySubjectSummary($0) as String? }
        let systemRoot = anchor.map { systemRoots.contains(SecCertificateCopyData($0) as Data) } ?? false
        var expires: Date?
        if let leaf, let vals = SecCertificateCopyValues(leaf, [kSecOIDX509V1ValidityNotAfter] as CFArray, nil) as? [CFString: Any],
           let na = vals[kSecOIDX509V1ValidityNotAfter] as? [CFString: Any], let n = na[kSecPropertyKeyValue] as? NSNumber {
            expires = Date(timeIntervalSinceReferenceDate: n.doubleValue)
        }
        let verdict: TLSCheck.Verdict
        if !valid { verdict = .invalid }
        else if !systemRoot { verdict = .untrustedRoot }
        else if let e = expires, e.timeIntervalSinceNow < 14 * 86400 { verdict = .expiring }
        else { verdict = .ok }
        return TLSCheck(host: host, verdict: verdict, issuer: issuer, root: rootName, expires: expires,
                        error: valid ? nil : (err.map { CFErrorCopyDescription($0) as String }))
    }
}

struct TLSAuditView: View {
    @EnvironmentObject var cap: PacketMonitor
    @State private var results: [TLSCheck] = []
    @State private var running = false

    /// Yakalamada TLS ile konuşulan sunucular (SNI), çok konuşulandan aza; en fazla 25.
    private var hosts: [String] {
        var seen = Set<String>(), out: [String] = []
        for c in cap.conversationList where c.protos.contains("TLS") || c.port == 443 {
            guard let h = c.host?.lowercased(), h.contains("."), !h.hasSuffix(".local"), seen.insert(h).inserted else { continue }
            out.append(h)
            if out.count >= 25 { break }
        }
        return out
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(L("tls.title"), systemImage: "lock.shield").font(.system(size: 15, weight: .bold))
                Spacer()
                if running { ProgressView().controlSize(.small) }
                Button(L("tls.run", hosts.count)) { run() }.disabled(running || hosts.isEmpty)
            }
            Text(L("tls.desc")).font(.system(size: 11.5)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            ForEach(results.sorted { ($0.verdict.rawValue, $0.host) > ($1.verdict.rawValue, $1.host) }) { r in
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: icon(r.verdict)).foregroundStyle(color(r.verdict)).frame(width: 18)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(r.host).font(.system(size: 12.5, weight: .semibold))
                        Text(text(r)).font(.system(size: 11.5)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
    }

    private func run() {
        running = true
        let list = hosts
        Task {
            var out: [TLSCheck] = []
            await withTaskGroup(of: TLSCheck.self) { g in
                for h in list { g.addTask { await TLSProbe.check(h) } }
                for await r in g { out.append(r) }
            }
            results = out
            running = false
        }
    }

    private func icon(_ v: TLSCheck.Verdict) -> String {
        switch v {
        case .ok: return "checkmark.seal.fill"
        case .expiring: return "clock.badge.exclamationmark"
        case .untrustedRoot, .invalid: return "xmark.octagon.fill"
        case .unreachable: return "questionmark.circle"
        }
    }

    private func color(_ v: TLSCheck.Verdict) -> Color {
        switch v {
        case .ok: return .green
        case .expiring: return .orange
        case .untrustedRoot, .invalid: return .red
        case .unreachable: return .secondary
        }
    }

    private func text(_ r: TLSCheck) -> String {
        let exp = r.expires.map { Fmt.relativeDay.string(from: $0) } ?? "—"
        switch r.verdict {
        case .ok: return L("tls.ok", r.issuer ?? "?", exp)
        case .expiring: return L("tls.expiring", exp)
        case .untrustedRoot: return L("tls.mitm", r.root ?? "?")
        case .invalid: return L("tls.invalid", r.error ?? "")
        case .unreachable: return L("tls.unreachable")
        }
    }
}
