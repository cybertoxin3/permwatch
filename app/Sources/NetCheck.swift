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
    @Published private(set) var lastCheck: Date?

    private var timer: Timer?
    private var busy = false
    private let knownKey = "netKnownDevices"      // [ağ anahtarı: [mac]]

    private init() {
        guard Snapshot.section == nil else { return }
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
        devices = s.arp.map { LanDevice(ip: $0.ip, mac: $0.mac, isGateway: $0.ip == s.gateway, isNew: !first && !seen.contains($0.mac)) }
            .sorted { $0.isGateway != $1.isGateway ? $0.isGateway : Self.ipSortKey($0.ip).lexicographicallyPrecedes(Self.ipSortKey($1.ip)) }
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

    /// "Ağı tara": alt ağdaki her adrese tek bir küçük UDP paketi gönderir; yanıt veren cihazlar ARP tablosuna düşer.
    func scan() {
        guard !scanning, let own = devicesBase() else { return }
        scanning = true
        Task.detached(priority: .utility) {
            let fd = socket(AF_INET, SOCK_DGRAM, 0)
            if fd >= 0 {
                for host in 1...254 {
                    var a = sockaddr_in()
                    a.sin_family = sa_family_t(AF_INET)
                    a.sin_port = in_port_t(9).bigEndian      // "discard" kapısı
                    inet_pton(AF_INET, own + ".\(host)", &a.sin_addr)
                    var b: UInt8 = 0
                    _ = withUnsafePointer(to: &a) { p in
                        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, &b, 1, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                    }
                    usleep(4000)
                }
                close(fd)
            }
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            let snap = NetCheck.read()
            await MainActor.run { self.scanning = false; self.apply(snap) }
        }
    }

    /// Kendi IP'mizin ilk üç kümesi (/24 tarama).
    private func devicesBase() -> String? {
        guard let gw = gatewayIP else { return nil }
        let p = gw.split(separator: ".")
        return p.count == 4 ? p.prefix(3).joined(separator: ".") : nil
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
                    Text(d.ip).font(.system(size: 12, design: .monospaced))
                    Text(d.mac).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    if d.isGateway { Text(L("net.router")).font(.system(size: 11)).foregroundStyle(.secondary) }
                    else if d.privateMAC { Text(L("net.privateMAC")).font(.system(size: 11)).foregroundStyle(.secondary) }
                    Spacer()
                    if d.isNew {
                        Text(L("net.new")).font(.system(size: 10.5, weight: .semibold)).padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Color.orange.opacity(0.2), in: Capsule())
                    }
                }
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
