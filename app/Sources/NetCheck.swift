import AppKit
import Foundation
import SwiftUI

/// Yerel ağdaki bir cihaz (ARP tablosundan).
struct LanDevice: Identifiable, Hashable {
    var id: String { mac }
    let ip: String
    let mac: String
    let isGateway: Bool
    var isNew: Bool
    /// Üretici (MAC adresinin ilk yarısından, IEEE listesi) ve cihazın ağa duyurduğu ad.
    var vendor: String?
    var name: String?
    /// iPhone/Android/Mac'lerin gizli (rastgele) donanım adresi: yerel olarak atanmış bit.
    var privateMAC: Bool {
        guard let first = mac.split(separator: ":").first, let v = UInt8(first, radix: 16) else { return false }
        return v & 0x02 != 0
    }
}

/// Bağlı olunan ağın güvenliği: Wi-Fi şifrelemesi, ağ geçidinin taklit edilmesi (ARP zehirlenmesi, araya girme)
/// ve ağdaki cihazlar. Yalnızca macOS'un kendi araçlarını okur (ipconfig, route, arp); "Ağı tara" dışında
/// ağa hiçbir şey göndermez.
@MainActor
final class NetCheck: ObservableObject {
    static let shared = NetCheck()

    enum Issue: Hashable {
        case openWifi
        case weakWifi(String)
        case arpSpoof(String)                 // ağ geçidinin donanım adresini kullanan başka IP
    }

    @Published private(set) var iface: String?
    @Published private(set) var wifiSecurity: String?     // nil: Wi-Fi değil
    @Published private(set) var gatewayIP: String?
    @Published private(set) var gatewayMAC: String?
    @Published private(set) var issues: [Issue] = []
    @Published private(set) var devices: [LanDevice] = []
    @Published private(set) var scanning = false
    /// Son taramanın özeti: kaç adres denendi, kaçına hiç gönderilemedi (yerel ağ izni yok).
    @Published private(set) var lastScan: (probed: Int, blocked: Int)?
    private var ownIP: String?
    private var netmask: String?
    @Published private(set) var lastCheck: Date?

    private var timer: Timer?
    private var busy = false
    private let knownKey = "netKnownDevices"      // [ağ anahtarı: [mac]]
    /// IP → ad (yerel ters DNS / Bonjour). Bir kez çözülür.
    private var names: [String: String] = [:]
    private var resolving = Set<String>()

    private init() {
        guard Snapshot.section == nil else { return }
        Vendors.prepare()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    var issueCount: Int { issues.count }

    func refresh() {
        guard !busy else { return }
        busy = true
        Task.detached(priority: .utility) {
            let snap = NetCheck.read()
            await MainActor.run { self.busy = false; self.apply(snap) }
        }
    }

    struct Snapshot_: Sendable {
        var iface: String?
        var security: String?
        var gateway: String?
        var arp: [(ip: String, mac: String)]
        var ownIP: String?
        var netmask: String?
    }

    nonisolated static func read() -> Snapshot_ {
        let route = Shell.run("/sbin/route", ["-n", "get", "default"]).1
        let gw = field(route, "gateway:")
        let ifc = field(route, "interface:")
        var sec: String?
        if let ifc {
            let sum = Shell.run("/usr/sbin/ipconfig", ["getsummary", ifc]).1
            if sum.contains("SSID") { sec = field(sum, "Security :") ?? "?" }
        }
        let arp = parseARP(Shell.run("/usr/sbin/arp", ["-an"]).1, iface: ifc)
        var own: String?, mask: String?
        if let ifc {
            let ic = Shell.run("/sbin/ifconfig", [ifc]).1
            for line in ic.split(separator: "\n") where line.contains("inet ") && !line.contains("inet6") {
                let p = line.split(separator: " ")
                if let i = p.firstIndex(of: "inet"), i + 1 < p.count { own = String(p[i + 1]) }
                if let i = p.firstIndex(of: "netmask"), i + 1 < p.count { mask = String(p[i + 1]) }
            }
        }
        return Snapshot_(iface: ifc, security: sec, gateway: gw, arp: arp, ownIP: own, netmask: mask)
    }

    nonisolated static func field(_ text: String, _ key: String) -> String? {
        for line in text.split(separator: "\n") {
            let l = line.trimmingCharacters(in: .whitespaces)
            if l.hasPrefix(key) { return l.dropFirst(key.count).trimmingCharacters(in: .whitespaces) }
        }
        return nil
    }

    /// "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]" → (ip, normalleştirilmiş mac)
    nonisolated static func parseARP(_ text: String, iface: String?) -> [(ip: String, mac: String)] {
        var out: [(String, String)] = []
        for line in text.split(separator: "\n") {
            let s = String(line)
            guard let l = s.firstIndex(of: "("), let r = s.firstIndex(of: ")"), let at = s.range(of: " at ") else { continue }
            if let iface, !s.contains(" on \(iface)") { continue }
            let ip = String(s[s.index(after: l)..<r])
            let rest = s[at.upperBound...]
            let mac = String(rest.prefix { $0 != " " })
            guard mac.contains(":"), !s.contains("permanent") else { continue }   // kendi adresimiz ve çok noktaya yayın
            let norm = mac.split(separator: ":").map { $0.count == 1 ? "0" + $0 : String($0) }.joined(separator: ":").lowercased()
            if norm == "ff:ff:ff:ff:ff:ff" || norm.hasPrefix("01:00:5e") || ip.hasPrefix("224.") || ip.hasPrefix("239.") { continue }
            out.append((ip, norm))
        }
        return out
    }

    /// Ağ geçidinin donanım adresini başka bir IP de kullanıyorsa: biri kendini yönlendirici gibi gösteriyor
    /// (ARP zehirlenmesi, araya girme saldırısının klasik belirtisi).
    nonisolated static func gatewayIssues(gateway: String?, arp: [(ip: String, mac: String)]) -> [Issue] {
        guard let gw = gateway, let gmac = arp.first(where: { $0.ip == gw })?.mac else { return [] }
        if let other = arp.first(where: { $0.mac == gmac && $0.ip != gw }) { return [.arpSpoof(other.ip)] }
        return []
    }

    /// Ağın kimliği: yönlendiricinin donanım adresi (192.168.1.1 gibi adresler her evde aynı olabilir).
    private func netKey(_ s: Snapshot_) -> String? {
        s.arp.first { $0.ip == s.gateway }?.mac
    }

    private func apply(_ s: Snapshot_) {
        lastCheck = Date()
        iface = s.iface
        ownIP = s.ownIP
        netmask = s.netmask
        wifiSecurity = s.security
        gatewayIP = s.gateway
        gatewayMAC = s.arp.first { $0.ip == s.gateway }?.mac
        var found: [Issue] = []
        if let sec = s.security?.uppercased() {
            if sec == "NONE" || sec.contains("OPEN") { found.append(.openWifi) }
            else if sec.contains("WEP") || (sec.contains("WPA") && !sec.contains("WPA2") && !sec.contains("WPA3")) {
                found.append(.weakWifi(s.security ?? sec))
            }
        }
        let key = netKey(s)
        found += Self.gatewayIssues(gateway: s.gateway, arp: s.arp)
        // Cihazlar: bu ağda ilk kez görülenler "yeni"
        var known = UserDefaults.standard.dictionary(forKey: knownKey) as? [String: [String]] ?? [:]
        let seen = Set(key.flatMap { known[$0] } ?? [])
        let first = seen.isEmpty
        devices = s.arp.map { LanDevice(ip: $0.ip, mac: $0.mac, isGateway: $0.ip == s.gateway, isNew: !first && !seen.contains($0.mac),
                                         vendor: Vendors.lookup($0.mac), name: names[$0.ip].flatMap { $0.isEmpty ? nil : $0 }) }
            .sorted { $0.isGateway != $1.isGateway ? $0.isGateway : Self.ipSortKey($0.ip).lexicographicallyPrecedes(Self.ipSortKey($1.ip)) }
        resolveNames(s.arp.map(\.ip))
        if let key {
            known[key] = Array(seen.union(s.arp.map(\.mac))).sorted()
            UserDefaults.standard.set(known, forKey: knownKey)
        }
        if found != issues {
            issues = found
            report(found, key: key ?? "?")
        }
    }

    private func report(_ list: [Issue], key: String) {
        for i in list {
            let (risk, title, detail): (Risk, String, String) = {
                switch i {
                case .openWifi: return (.caution, L("net.openWifi"), L("net.openWifiBody"))
                case .weakWifi(let s): return (.caution, L("net.weakWifi", s), L("net.openWifiBody"))
                case .arpSpoof(let ip): return (.high, L("net.arpSpoof"), L("net.arpSpoofBody", ip))
                }
            }()
            ThreatCenter.shared.report(Threat(id: "lan.\(key).\(i)", risk: risk, title: title, detail: detail,
                                              iconKey: nil, section: .security, focus: .none))
        }
    }

    nonisolated static func ipSortKey(_ ip: String) -> [Int] { ip.split(separator: ".").map { Int($0) ?? 0 } }

    /// Adı bilinmeyen cihazları arka planda çözer (aynı anda en fazla 8), sonra listeyi günceller.
    private func resolveNames(_ ips: [String]) {
        let todo = ips.filter { names[$0] == nil && !resolving.contains($0) }.prefix(64)
        guard !todo.isEmpty else { return }
        resolving.formUnion(todo)
        let list = Array(todo)
        Task.detached(priority: .utility) {
            var found: [String: String] = [:]
            await withTaskGroup(of: (String, String?).self) { g in
                var i = 0
                for ip in list {
                    if i >= 8, let r = await g.next(), let n = r.1 { found[r.0] = n }
                    g.addTask { (ip, NetCheck.reverseName(ip)) }
                    i += 1
                }
                for await r in g { if let n = r.1 { found[r.0] = n } }
            }
            let result = found
            await MainActor.run {
                for ip in list { self.names[ip] = result[ip] ?? "" }   // boş: çözülemedi, bir daha deneme
                self.devices = self.devices.map { var d = $0; let n = self.names[d.ip]; d.name = (n?.isEmpty ?? true) ? nil : n; return d }
                self.resolving.subtract(list)
            }
        }
    }

    /// Yerel ağda ters ad çözümü (mDNSResponder .local adlarını da çözer).
    nonisolated static func reverseName(_ ip: String) -> String? {
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, ip, &sa.sin_addr) == 1 else { return nil }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = withUnsafePointer(to: &sa) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
            }
        }
        guard rc == 0 else { return nil }
        var n = String(cString: host)
        if n.hasSuffix(".") { n.removeLast() }
        if n.hasSuffix(".local") { n = String(n.dropLast(6)) }
        return n == ip ? nil : n
    }

    /// "Ağı tara": alt ağdaki her adrese tek bir küçük UDP paketi gönderir; yanıt veren cihazlar ARP tablosuna düşer.
    func scan() {
        guard !scanning else { return }
        let targets = Self.scanTargets(ownIP: ownIP, netmask: netmask, gateway: gatewayIP)
        guard !targets.isEmpty else { return }
        scanning = true
        Task.detached(priority: .utility) {
            var blocked = 0
            let fd = socket(AF_INET, SOCK_DGRAM, 0)
            if fd >= 0 {
                // Büyük ağlarda (binlerce adres) daha sık gönder; küçük ağda yavaş ve nazik.
                let pause: UInt32 = targets.count > 1024 ? 1000 : 4000
                for addr in targets {
                    var a = sockaddr_in()
                    a.sin_family = sa_family_t(AF_INET)
                    a.sin_port = in_port_t(9).bigEndian      // "discard" kapısı
                    a.sin_addr.s_addr = addr.bigEndian
                    var b: UInt8 = 0
                    let n = withUnsafePointer(to: &a) { p in
                        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, &b, 1, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                    }
                    // macOS "Yerel Ağ" izni yoksa gönderim EHOSTUNREACH/EPERM ile reddedilir.
                    if n < 0, errno == EHOSTUNREACH || errno == EPERM || errno == EACCES { blocked += 1 }
                    usleep(pause)
                }
                close(fd)
            }
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            let snap = NetCheck.read()
            let summary = (targets.count, blocked)
            await MainActor.run { self.scanning = false; self.lastScan = summary; self.apply(snap) }
        }
    }

    /// Taranacak adresler: kendi alt ağımızın tamamı (ağ maskesine göre). Çok büyük ağlarda (/18'den geniş)
    /// kendi adresimizi içeren 16 bin adreslik dilimle sınırlanır. Maske okunamazsa ağ geçidinin /24'ü.
    nonisolated static func scanTargets(ownIP: String?, netmask: String?, gateway: String?) -> [UInt32] {
        func ip4(_ s: String?) -> UInt32? {
            guard let p = s?.split(separator: ".").compactMap({ UInt32($0) }), p.count == 4, p.allSatisfy({ $0 < 256 }) else { return nil }
            return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]
        }
        var mask: UInt32 = 0xffff_ff00
        if let m = netmask {
            if m.hasPrefix("0x"), let v = UInt32(m.dropFirst(2), radix: 16) { mask = v } else if let v = ip4(m) { mask = v }
        }
        guard let base = ip4(ownIP) ?? ip4(gateway) else { return [] }
        if mask == 0xffff_ffff || mask == 0 { mask = 0xffff_ff00 }
        mask |= 0xffff_c000                       // en fazla /18 (16 382 adres)
        let net = base & mask, last = net | ~mask
        guard last > net + 1 else { return [] }
        let own = ip4(ownIP)
        return ((net + 1)..<last).filter { $0 != own }
    }

    /// Geniş bir tarama yalnızca yönlendiriciyi (ve en çok bir cihazı) bulduysa: ağ büyük olasılıkla
    /// cihazları birbirinden yalıtıyor (misafir/yurt/otel ağlarındaki "client isolation").
    var looksIsolated: Bool {
        guard let s = lastScan, s.probed >= 200, s.blocked < s.probed / 2 else { return false }
        return devices.filter { !$0.isGateway }.count <= 1
    }

    var scanBlocked: Bool {
        guard let s = lastScan, s.probed > 0 else { return false }
        return s.blocked >= s.probed / 2
    }

    func forgetDevices() {
        UserDefaults.standard.removeObject(forKey: knownKey)
        refresh()
    }
}

// MARK: - Görünüm (Güvenlik sayfasında)

struct NetCheckCard: View {
    @ObservedObject var net = NetCheck.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(L("net.cardTitle"), systemImage: "wifi").font(.system(size: 14, weight: .bold))
                Spacer()
                Button { net.refresh() } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.borderless)
            }
            row(icon: wifiIcon, color: wifiColor, title: wifiTitle, detail: wifiDetail)
            if let gw = net.gatewayIP {
                let bad = net.issues.contains { if case .arpSpoof = $0 { return true }; return false }
                row(icon: bad ? "exclamationmark.triangle.fill" : "checkmark.circle.fill", color: bad ? .red : .green,
                    title: bad ? L("net.arpSpoof") : L("net.gwOK"),
                    detail: bad ? issueDetail : L("net.gwDetail", gw, net.gatewayMAC ?? "?"))
            }
            Divider()
            HStack {
                Text(L("net.devices", net.devices.count as Int)).font(.system(size: 13, weight: .semibold))
                Spacer()
                if net.scanning { ProgressView().controlSize(.small) }
                Button(L("net.scan")) { net.scan() }.controlSize(.small).disabled(net.scanning || net.gatewayIP == nil)
            }
            ForEach(net.devices) { d in
                HStack(spacing: 10) {
                    Image(systemName: d.isGateway ? "wifi.router" : (d.privateMAC ? "iphone" : "desktopcomputer"))
                        .foregroundStyle(.secondary).frame(width: 20)
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 6) {
                            Text(d.ip).font(.system(size: 12, design: .monospaced))
                            if let n = d.name { Text(n).font(.system(size: 12, weight: .medium)).lineLimit(1) }
                        }
                        HStack(spacing: 6) {
                            Text(d.mac).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                            if let v = d.vendor { Text(v).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1) }
                        }
                    }
                    if d.isGateway { Text(L("net.router")).font(.system(size: 11)).foregroundStyle(.secondary) }
                    else if d.privateMAC { Text(L("net.privateMAC")).font(.system(size: 11)).foregroundStyle(.secondary) }
                    Spacer()
                    if d.isNew {
                        Text(L("net.new")).font(.system(size: 10.5, weight: .semibold)).padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Color.orange.opacity(0.2), in: Capsule())
                    }
                }
            }
            if net.scanBlocked {
                Label(L("net.scanBlocked"), systemImage: "hand.raised.fill").font(.system(size: 12)).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            } else if net.looksIsolated, let s = net.lastScan {
                Label(L("net.isolated", s.probed), systemImage: "person.2.slash").font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(L("net.devicesHint")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.secondary.opacity(0.2)))
    }

    private func row(icon: String, color: Color, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).font(.system(size: 18)).foregroundStyle(color).frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(detail).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var weak: Bool { net.issues.contains { if case .openWifi = $0 { return true }; if case .weakWifi = $0 { return true }; return false } }
    private var wifiIcon: String { net.wifiSecurity == nil ? "cable.connector" : (weak ? "wifi.exclamationmark" : "lock.fill") }
    private var wifiColor: Color { weak ? .orange : .green }
    private var wifiTitle: String {
        guard let s = net.wifiSecurity else { return L("net.wired") }
        if net.issues.contains(.openWifi) { return L("net.openWifi") }
        if weak { return L("net.weakWifi", s) }
        return L("net.wifiOK", s)
    }
    private var wifiDetail: String {
        guard net.wifiSecurity != nil else { return L("net.wiredDetail") }
        return weak ? L("net.openWifiBody") : L("net.wifiOKDetail")
    }
    private var issueDetail: String {
        for i in net.issues {
            if case .arpSpoof(let ip) = i { return L("net.arpSpoofBody", ip) }
        }
        return ""
    }
}

// MARK: - Üretici listesi (IEEE OUI)

/// MAC adresinin ilk 3 baytından üretici adı. IEEE'nin resmi listesi bir kez indirilir (yaklaşık 4 MB) ve
/// ayda bir yenilenir; hiçbir şey gönderilmez. Gizli (rastgele) MAC adreslerinin üreticisi yoktur.
enum Vendors {
    static let url = URL(string: "https://standards-oui.ieee.org/oui/oui.csv")!
    static var path: String { ThreatIntel.dir + "/oui.csv" }
    private static let lock = NSLock()
    nonisolated(unsafe) private static var table: [String: String]?

    static func lookup(_ mac: String) -> String? {
        let parts = mac.lowercased().split(separator: ":")
        guard parts.count >= 3, let first = UInt8(parts[0], radix: 16), first & 0x02 == 0 else { return nil }
        let key = parts.prefix(3).map { $0.count == 1 ? "0" + $0 : String($0) }.joined().uppercased()
        lock.lock(); let t = table; lock.unlock()
        return t?[key]
    }

    /// Listeyi yükler; yoksa ya da 30 günden eskiyse indirir.
    static func prepare() {
        Task.detached(priority: .utility) {
            let fm = FileManager.default
            let age = (try? fm.attributesOfItem(atPath: path)[.modificationDate] as? Date).map { Date().timeIntervalSince($0) } ?? .infinity
            if age > 30 * 86400 {
                var req = URLRequest(url: url, timeoutInterval: 60)
                req.setValue("permwatch", forHTTPHeaderField: "User-Agent")
                if let (d, r) = try? await URLSession.shared.data(for: req), (r as? HTTPURLResponse)?.statusCode == 200, d.count > 500_000 {
                    try? fm.createDirectory(atPath: ThreatIntel.dir, withIntermediateDirectories: true)
                    try? d.write(to: URL(fileURLWithPath: path), options: .atomic)
                }
            }
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return }
            let t = parse(text)
            setTable(t)
            await MainActor.run { NetCheck.shared.refresh() }
        }
    }

    private static func setTable(_ t: [String: String]) { lock.lock(); table = t; lock.unlock() }

    /// "MA-L,001122,Örnek A.Ş.,Adres" (ad tırnaklı olabilir).
    static func parse(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        out.reserveCapacity(40000)
        // Dosya "\r\n" kullanıyor; Swift bunu tek karakter sayar, bu yüzden her tür satır sonunda böl.
        for line in text.split(whereSeparator: \.isNewline).dropFirst() {
            let f = line.split(separator: ",", maxSplits: 2, omittingEmptySubsequences: false)
            guard f.count == 3, f[1].count == 6 else { continue }
            var rest = Substring(f[2])
            var name: Substring
            if rest.hasPrefix("\"") {
                rest = rest.dropFirst()
                name = rest.prefix { $0 != "\"" }
            } else {
                name = rest.prefix { $0 != "," }
            }
            let n = name.trimmingCharacters(in: .whitespaces)
            if !n.isEmpty { out[String(f[1]).uppercased()] = n }
        }
        return out
    }
}
