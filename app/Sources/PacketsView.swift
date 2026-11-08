import SwiftUI

/// Wireshark tarzı canlı paket listesi, konuşmalar ve paket ayrıntısı.
struct PacketsView: View {
    @EnvironmentObject var cap: PacketMonitor
    @EnvironmentObject var root: RootBridge
    @EnvironmentObject var center: ThreatCenter
    @State private var filter = ""
    @State private var selection: Int?
    @State private var showConversations = false
    @State private var devices: [String] = []

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if let e = cap.error, !cap.running {
                banner(e)
                Divider()
            }
            if !cap.packets.isEmpty { insights; Divider() }
            if cap.packets.isEmpty {
                emptyState
            } else if showConversations {
                ConversationsPane(rows: conversations)
            } else {
                HStack(spacing: 0) {
                    packetTable
                    if let p = cap.packets.last(where: { $0.seq == selection }) {
                        Divider()
                        PacketDetail(p: p).frame(width: 380)
                    }
                }
            }
        }
        .navigationTitle(L("nav.packets"))
        .navigationSubtitle(subtitle)
        .onAppear {
            devices = PacketMonitor.devices()
            if Snapshot.section == "packets", !cap.running { cap.start() }
            applyFocus()
        }
        .onChange(of: center.navToken) { applyFocus() }
    }

    // MARK: Üst çubuk

    private var toolbar: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                if cap.running {
                    Button { cap.stop() } label: { Label(L("pkt.stop"), systemImage: "stop.fill") }
                        .tint(.red)
                } else {
                    Button { cap.start() } label: { Label(L("pkt.start"), systemImage: "record.circle") }
                        .buttonStyle(.borderedProminent)
                }
                if !root.active {
                    Picker("", selection: $cap.localDevice) {
                        ForEach(devices.contains(cap.localDevice) ? devices : [cap.localDevice] + devices, id: \.self) { Text($0).tag($0) }
                    }
                    .labelsHidden().frame(width: 110).disabled(cap.running)
                }
                Picker("", selection: $showConversations) {
                    Text(L("pkt.packets")).tag(false)
                    Text(L("pkt.conversations")).tag(true)
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 220)
                Spacer()
                Button { cap.clear(); selection = nil } label: { Image(systemName: "trash") }
                    .help(L("pkt.clear")).disabled(cap.packets.isEmpty)
                Button { cap.openInWireshark() } label: { Label(L("pkt.openWireshark"), systemImage: "arrow.up.forward.app") }
                    .disabled(cap.pcapURL == nil)
            }
            HStack(spacing: 8) {
                Image(systemName: "line.3.horizontal.decrease.circle").foregroundStyle(.secondary)
                TextField(L("pkt.filter"), text: $filter).textFieldStyle(.roundedBorder)
                if cap.running {
                    Circle().fill(Color.red).frame(width: 7, height: 7)
                    Text(L("pkt.capturing")).font(.system(size: 11, weight: .semibold)).foregroundStyle(.red)
                }
                Text(modeText).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }

    /// Tek bakışta: ne kadarı şifreli, kaç izleyici, şifresiz bağlantı var mı.
    private var insights: some View {
        let convs = conversations
        let enc = cap.packets.filter { ["TLS", "QUIC", "SSH"].contains($0.proto) }.reduce(0) { $0 + $1.len }
        let tcpudp = cap.packets.filter { $0.sport != nil }.reduce(0) { $0 + $1.len }
        let pct = tcpudp == 0 ? 100 : Int((Double(enc) / Double(tcpudp) * 100).rounded())
        let trackers = Set(convs.compactMap { Trackers.match($0.host)?.company })
        let plain = convs.filter { !$0.protos.isDisjoint(with: ["HTTP", "FTP", "Telnet", "POP3", "IMAP", "SMTP"]) }.count
        let creds = convs.filter(\.creds).count
        return HStack(spacing: 16) {
            Label(L("pkt.insight.encrypted", "\(pct)%"), systemImage: "lock.fill")
                .foregroundStyle(pct >= 80 ? Color.green : Color.orange)
                .help(L("pkt.insight.encryptedHelp"))
            Button { filter = ""; showConversations = true } label: {
                Label(L("pkt.insight.trackers", trackers.count.formatted()), systemImage: "eye.trianglebadge.exclamationmark")
            }
            .buttonStyle(.plain).foregroundStyle(trackers.isEmpty ? Color.secondary : Color.orange)
            .help(trackers.sorted().joined(separator: ", "))
            Label(L("pkt.insight.cleartext", plain.formatted()), systemImage: "lock.open")
                .foregroundStyle(plain == 0 ? Color.secondary : Color.orange)
            if creds > 0 {
                Label(L("pkt.insight.creds", creds.formatted()), systemImage: "key.fill").foregroundStyle(.red)
            }
            Spacer()
        }
        .font(.system(size: 11.5, weight: .medium))
        .padding(.horizontal, 16).padding(.vertical, 7)
    }

    private var modeText: String {
        if root.active { return L("pkt.modeRoot") }
        return L("pkt.modeLocal", cap.localDevice)
    }

    private var subtitle: String {
        var s = L("pkt.summary", cap.totalPackets.formatted(), ByteCountFormatter.string(fromByteCount: Int64(cap.totalBytes), countStyle: .file))
        if cap.skipped > 0 { s += " · " + L("pkt.skipped", cap.skipped.formatted()) }
        return s
    }

    private func banner(_ e: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: cap.needsRoot ? "lock.shield" : "exclamationmark.triangle").font(.system(size: 22))
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(cap.needsRoot ? L("pkt.needRoot") : L("pkt.error", e)).font(.system(size: 13, weight: .semibold))
                if cap.needsRoot { Text(L("pkt.needRootBody")).font(.system(size: 12)).foregroundStyle(.secondary) }
            }
            Spacer()
            if !root.active {
                Button(L("pkt.enableRoot")) { root.enable() }.disabled(root.starting)
            }
        }
        .padding(14)
        .background(Color.orange.opacity(0.08))
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label(cap.running ? L("pkt.waiting") : L("pkt.empty"), systemImage: "waveform.path.ecg")
        } description: {
            Text(L("pkt.emptyBody"))
        } actions: {
            if !cap.running {
                Button(L("pkt.start")) { cap.start() }.buttonStyle(.borderedProminent)
                if !root.active { Button(L("pkt.enableRoot")) { root.enable() }.disabled(root.starting) }
            }
        }
    }

    // MARK: Paket tablosu

    private var visible: [Packet] {
        let tokens = filter.lowercased().split(separator: " ").map(String.init)
        var rows = cap.packets
        if !tokens.isEmpty {
            rows = rows.filter { p in
                let hay = [p.proc, p.eproc, p.src, p.dst, cap.names[p.src], cap.names[p.dst], p.proto, p.l3, p.info, p.host,
                           p.sport.map(String.init), p.dport.map(String.init), p.iface]
                    .compactMap { $0?.lowercased() }
                return tokens.allSatisfy { t in hay.contains { $0.contains(t) } }
            }
        }
        // En yenisi üstte; tablo en fazla 5000 satır çizer (hepsi bellekte ve .pcap'te).
        return Array(rows.suffix(5000).reversed())
    }

    private var packetTable: some View {
        Table(visible, selection: $selection) {
            TableColumn("") { p in
                let e = Explainer.packet(p, host: cap.names[p.dst], app: p.eproc ?? p.proc ?? "—")
                if e.verdict == .caution || e.verdict == .danger {
                    Image(systemName: e.verdict.icon).foregroundStyle(e.verdict.color).help(e.what)
                }
            }
            .width(18)
            TableColumn(L("col.no")) { p in Text(String(p.seq)).monospacedDigit().foregroundStyle(.secondary) }
                .width(56)
            TableColumn(L("col.time")) { p in
                Text(Fmt.packetTime.string(from: Date(timeIntervalSince1970: p.ts))).monospacedDigit()
            }
            .width(92)
            TableColumn(L("net.process")) { p in
                HStack(spacing: 6) {
                    if let n = p.eproc ?? p.proc {
                        AppIcon(name: n, risk: .normal, key: cap.path(for: p.epid ?? p.pid).map { PathUtil.appBundle($0) ?? $0 }, size: 16)
                        Text(n).lineLimit(1)
                    } else {
                        Text("—").foregroundStyle(.secondary)
                    }
                }
            }
            .width(min: 100, ideal: 140)
            TableColumn(L("col.source")) { p in addr(p.src, p.sport) }.width(min: 120, ideal: 170)
            TableColumn(L("col.destination")) { p in addr(p.dst, p.dport) }.width(min: 120, ideal: 190)
            TableColumn(L("col.protocol")) { p in
                Text(p.proto).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(protoColor(p))
            }
            .width(70)
            TableColumn(L("col.length")) { p in Text(String(p.len)).monospacedDigit() }.width(56)
            TableColumn(L("col.info")) { p in
                HStack(spacing: 4) {
                    if p.flags?.contains("pkt.flag.cleartextCreds") == true {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                    Text(p.info).lineLimit(1).truncationMode(.tail)
                }
            }
            .width(min: 200, ideal: 380)
        }
        .font(.system(size: 11.5))
    }

    private func addr(_ ip: String, _ port: Int?) -> some View {
        let name = cap.names[ip]
        return Text((name ?? ip) + (port.map { ":\($0)" } ?? ""))
            .font(.system(size: 11.5, design: name == nil ? .monospaced : .default))
            .lineLimit(1).truncationMode(.middle)
            .help(ip)
    }

    // MARK: Konuşmalar

    private var conversations: [Conversation] {
        var map: [String: Conversation] = [:]
        for p in cap.packets {
            let remoteIsSrc = p.dir == "in" || (p.dir == nil && Conversation.isLocal(p.dst) && !Conversation.isLocal(p.src))
            let ip = remoteIsSrc ? p.src : p.dst
            let port = remoteIsSrc ? p.sport : p.dport
            let proc = p.eproc ?? p.proc ?? "—"
            let key = "\(proc)|\(ip)|\(port ?? 0)"
            var c = map[key] ?? Conversation(id: key, proc: proc, pid: p.epid ?? p.pid, remote: ip,
                                             host: cap.names[ip], port: port, first: p.ts, last: p.ts)
            c.packets += 1
            c.bytes += p.len
            if remoteIsSrc { c.bytesIn += p.len } else { c.bytesOut += p.len }
            c.last = p.ts
            c.protos.insert(p.proto)
            if c.host == nil { c.host = cap.names[ip] ?? (p.proto == "TLS" || p.proto == "HTTP" ? p.host : nil) }
            if p.flags?.contains("pkt.flag.cleartextCreds") == true { c.creds = true }
            map[key] = c
        }
        return map.values.sorted { $0.bytes > $1.bytes }
    }

    private func protoColor(_ p: Packet) -> Color {
        if p.flags?.contains("pkt.flag.cleartextCreds") == true { return .red }
        switch p.proto {
        case "TLS", "QUIC", "SSH": return .green
        case "DNS", "mDNS", "LLMNR": return .blue
        case "HTTP", "FTP", "Telnet", "POP3", "IMAP", "SMTP": return .orange
        case "ARP", "ICMP", "ICMPv6": return .purple
        default: return .primary
        }
    }

    private func applyFocus() {
        if case .packet(let s) = center.navFocus { filter = ""; showConversations = false; selection = s }
    }
}

struct Conversation: Identifiable {
    let id: String
    let proc: String
    let pid: Int32?
    let remote: String
    var host: String?
    let port: Int?
    var first: Double
    var last: Double
    var packets = 0
    var bytes = 0
    var bytesIn = 0
    var bytesOut = 0
    var protos: Set<String> = []
    var creds = false

    /// Çok veri gönderip az alan bağlantı (yükleme/sızdırma belirtisi olabilir).
    var uploadHeavy: Bool { bytesOut > 20 << 20 && bytesOut > bytesIn * 5 }

    static func isLocal(_ ip: String) -> Bool {
        if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("127.") || ip.hasPrefix("169.254.")
            || ip.hasPrefix("fe80") || ip.hasPrefix("fd") || ip == "::1" { return true }
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        if parts.count == 4 {
            if parts[0] == 172 && (16...31).contains(parts[1]) { return true }
            if parts[0] == 100 && (64...127).contains(parts[1]) { return true }
        }
        return false
    }
}

struct ConversationsPane: View {
    @EnvironmentObject var cap: PacketMonitor
    let rows: [Conversation]
    @State private var selection: String?

    var body: some View {
        HStack(spacing: 0) {
            ConversationsTable(rows: rows, selection: $selection)
            if let c = rows.first(where: { $0.id == selection }) {
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 10) {
                            AppIcon(name: c.proc, risk: .normal, key: cap.path(for: c.pid).map { PathUtil.appBundle($0) ?? $0 }, size: 32)
                            VStack(alignment: .leading) {
                                Text(c.proc).font(.system(size: 14, weight: .bold))
                                Text(c.host ?? c.remote).font(.system(size: 12)).foregroundStyle(.secondary)
                            }
                        }
                        ExplanationCard(e: Explainer.conversation(c))
                        if let t = Trackers.match(c.host) {
                            Label("\(t.company) · \(t.kindText)", systemImage: "eye.trianglebadge.exclamationmark")
                                .font(.system(size: 12)).foregroundStyle(.orange)
                        }
                        Text(L("pkt.convStats", c.packets.formatted(),
                               ByteCountFormatter.string(fromByteCount: Int64(c.bytesOut), countStyle: .file),
                               ByteCountFormatter.string(fromByteCount: Int64(c.bytesIn), countStyle: .file)))
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                        Text(c.remote + (c.port.map { ":\($0)" } ?? "")).font(.system(size: 11.5, design: .monospaced)).textSelection(.enabled)
                        if let path = cap.path(for: c.pid) {
                            Button(L("action.virustotal")) { Lookup.virusTotal(path: PathUtil.appBundle(path) ?? path) }.controlSize(.small)
                        }
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(width: 340)
            }
        }
    }
}

struct ConversationsTable: View {
    @EnvironmentObject var cap: PacketMonitor
    let rows: [Conversation]
    @Binding var selection: String?

    var body: some View {
        Table(rows, selection: $selection) {
            TableColumn("") { c in
                let e = Explainer.conversation(c)
                Image(systemName: e.verdict.icon).foregroundStyle(e.verdict.color).help(e.what)
            }
            .width(18)
            TableColumn(L("net.process")) { c in
                HStack(spacing: 6) {
                    AppIcon(name: c.proc, risk: c.creds ? .high : .normal,
                            key: cap.path(for: c.pid).map { PathUtil.appBundle($0) ?? $0 }, size: 16)
                    Text(c.proc).lineLimit(1)
                }
            }
            .width(min: 110, ideal: 160)
            TableColumn(L("col.host")) { c in
                VStack(alignment: .leading, spacing: 1) {
                    Text(c.host ?? c.remote).lineLimit(1).truncationMode(.middle)
                    if c.host != nil { Text(c.remote).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.secondary) }
                }
            }
            .width(min: 160, ideal: 260)
            TableColumn(L("col.port")) { c in Text(c.port.map(String.init) ?? "—").monospacedDigit() }.width(54)
            TableColumn(L("col.protocol")) { c in Text(c.protos.sorted().joined(separator: ", ")).lineLimit(1) }.width(min: 70, ideal: 110)
            TableColumn(L("col.packets")) { c in Text(c.packets.formatted()).monospacedDigit() }.width(70)
            TableColumn(L("pkt.out")) { c in Text(ByteCountFormatter.string(fromByteCount: Int64(c.bytesOut), countStyle: .file)).monospacedDigit() }.width(76)
            TableColumn(L("pkt.in")) { c in Text(ByteCountFormatter.string(fromByteCount: Int64(c.bytesIn), countStyle: .file)).monospacedDigit() }.width(76)
            TableColumn(L("col.tracker")) { c in
                if let t = Trackers.match(c.host) { Text(t.company).foregroundStyle(.orange).lineLimit(1) }
            }
            .width(min: 70, ideal: 110)
        }
        .font(.system(size: 11.5))
    }
}

// MARK: - Paket ayrıntısı

struct PacketDetail: View {
    @EnvironmentObject var cap: PacketMonitor
    let p: Packet

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ExplanationCard(e: Explainer.packet(p, host: cap.names[p.dst], app: p.eproc ?? p.proc ?? L("x.someApp")))
                group(L("pkt.frame")) {
                    row(L("col.no"), String(p.seq))
                    row(L("col.time"), Fmt.packetTime.string(from: Date(timeIntervalSince1970: p.ts)))
                    row(L("col.length"), "\(p.len) B")
                    if let i = p.iface { row(L("pkt.interface"), i) }
                    if let d = p.dir { row(L("pkt.direction"), d == "in" ? L("pkt.in") : L("pkt.out")) }
                }
                if p.proc != nil || p.eproc != nil {
                    group(L("net.process")) {
                        if let n = p.proc { row(n, p.pid.map { "pid \($0)" } ?? "") }
                        if let n = p.eproc { row(L("pkt.onBehalf"), "\(n)" + (p.epid.map { " (pid \($0))" } ?? "")) }
                        if let path = cap.path(for: p.epid ?? p.pid) {
                            Text(PathUtil.abbreviate(path)).font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary).textSelection(.enabled)
                            Button(L("action.virustotal")) { Lookup.virusTotal(path: PathUtil.appBundle(path) ?? path) }
                                .controlSize(.small)
                        }
                    }
                }
                group(p.l3) {
                    row(L("col.source"), p.src + (cap.names[p.src].map { "  (\($0))" } ?? ""))
                    row(L("col.destination"), p.dst + (cap.names[p.dst].map { "  (\($0))" } ?? ""))
                }
                if p.sport != nil {
                    group(p.tcp != nil ? "TCP" : "UDP") {
                        row(L("pkt.ports"), "\(p.sport ?? 0) → \(p.dport ?? 0)")
                        if let t = p.tcp, !t.isEmpty { row(L("pkt.tcpFlags"), t) }
                    }
                }
                group(p.proto) {
                    Text(p.info).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                    if let h = p.host { row(L("col.host"), h) }
                    if let d = p.dns { row(L("pkt.dnsAnswers"), d.joined(separator: "\n")) }
                }
                if let hex = p.hex, !hex.isEmpty {
                    group(L("pkt.bytes")) {
                        Text(Self.dump(hex)).font(.system(size: 10.5, design: .monospaced)).textSelection(.enabled)
                            .fixedSize(horizontal: true, vertical: false)
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .underPageBackgroundColor).opacity(0.25))
    }

    private func group<C: View>(_ title: String, @ViewBuilder _ c: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title.uppercased(with: .current)).font(.system(size: 10.5, weight: .semibold)).foregroundStyle(.secondary)
            c()
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).font(.system(size: 12)).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
            Text(v).font(.system(size: 12)).textSelection(.enabled)
        }
    }

    /// Wireshark'taki gibi: konum, 16 bayt onaltılık, ASCII.
    static func dump(_ hex: String) -> String {
        let bytes: [UInt8] = stride(from: 0, to: hex.count - 1, by: 2).compactMap { i in
            let s = hex.index(hex.startIndex, offsetBy: i)
            return UInt8(hex[s..<hex.index(s, offsetBy: 2)], radix: 16)
        }
        var lines: [String] = []
        for off in stride(from: 0, to: bytes.count, by: 16) {
            let chunk = bytes[off..<min(off + 16, bytes.count)]
            let h = chunk.map { String(format: "%02x", $0) }.joined(separator: " ")
            let a = String(chunk.map { $0 >= 0x20 && $0 < 0x7f ? Character(UnicodeScalar($0)) : "." })
            lines.append(String(format: "%04x  ", off) + h.padding(toLength: 48, withPad: " ", startingAt: 0) + " " + a)
        }
        return lines.joined(separator: "\n")
    }
}
