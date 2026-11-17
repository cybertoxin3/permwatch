import SwiftUI

/// Wireshark tarzı canlı paket listesi, konuşmalar ve paket ayrıntısı.
struct PacketsView: View {
    @EnvironmentObject var cap: PacketMonitor
    @EnvironmentObject var root: RootBridge
    @EnvironmentObject var center: ThreatCenter
    @State private var filter = ""
    @State private var selection: Int?
    /// 0: paketler, 1: konuşmalar, 2: güvenlik analizi
    @State private var tab = 0
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
            } else if tab == 1 {
                ConversationsPane(rows: conversations)
            } else if tab == 2 {
                PacketAnalysisPane { q in filter = q; tab = 0; selection = nil }
            } else {
                HStack(spacing: 0) {
                    packetTable
                    if let p = cap.packets.last(where: { $0.seq == selection }) {
                        Divider()
                        PacketDetail(p: p) { q in filter = q }
                            .frame(width: 420)
                            .clipped()
                    }
                }
            }
        }
        .navigationTitle(L("nav.packets"))
        .navigationSubtitle(subtitle)
        .onAppear {
            rows = Self.compute(cap.packets, filter, cap.names)
            devices = PacketMonitor.devices()
            // Görsel deneme: kayıt dosyasını açıp bir paketi ya da analiz sekmesini göster.
            if Snapshot.section == "packets-file", let f = ProcessInfo.processInfo.environment["PERMWATCH_PCAP"] {
                cap.load(URL(fileURLWithPath: f))
                let t = Int(ProcessInfo.processInfo.environment["PERMWATCH_PKTTAB"] ?? "0") ?? 0
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                    tab = t
                    selection = cap.packets.first(where: { $0.proto == "ARP" })?.seq
                    // Deneme: filtreyi harf harf yazıp sil (donma ölçümü).
                    if ProcessInfo.processInfo.environment["PERMWATCH_FILTERTEST"] != nil {
                        let word = "proto:llmnr"
                        var steps: [String] = (1...word.count).map { String(word.prefix($0)) }
                        steps += (0..<word.count).reversed().map { String(word.prefix($0)) }
                        for (i, s) in steps.enumerated() {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1 + Double(i) * 0.25) {
                                filter = s
                                FileHandle.standardError.write(Data("filtre: '\(s)' \(Date().timeIntervalSince1970)\n".utf8))
                            }
                        }
                    }
                }
            }
            if Snapshot.section == "packets", !cap.running {
                cap.start()
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) { cap.stop() }
            }
            applyFocus()
        }
        .onChange(of: center.navToken) { applyFocus() }
        .onChange(of: filter) { refilter() }
        .onChange(of: cap.packets.count) { old, new in
            // Canlı yakalamada az sayıda yeni paket: tablo yerinde güncellensin. Toplu değişiklik (dosya açma,
            // temizleme, 5000 sınırını aşan akış): tablo baştan kurulsun.
            refilter(rebuild: new < old || new - old > 200 || rows.count >= 5000, delay: 0.3)
        }
    }

    // MARK: Üst çubuk

    private var toolbar: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                if cap.running {
                    Button { cap.stop() } label: { Label(L("pkt.stop"), systemImage: "stop.fill") }
                        .tint(.red)
                } else if cap.waitingForRoot {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text(L("pkt.waitingRoot")).font(.system(size: 12))
                        Button(L("confirm.cancel")) { cap.cancelWaiting() }.controlSize(.small)
                    }
                } else {
                    Button { cap.start() } label: { Label(L("pkt.start"), systemImage: "record.circle") }
                        .buttonStyle(.borderedProminent)
                }
                Picker("", selection: $tab) {
                    Text(L("pkt.packets")).tag(0)
                    Text(L("pkt.conversations")).tag(1)
                    Text(L("pa.tab")).tag(2)
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 330)
                Spacer()
                Button { cap.openFile(); selection = nil } label: { Label(L("pa.openFile"), systemImage: "folder") }
                    .disabled(cap.loadingFile)
                    .help(L("pa.openFileMessage"))
                Button { cap.clear(); selection = nil } label: { Image(systemName: "trash") }
                    .help(L("pkt.clear")).disabled(cap.packets.isEmpty)
                Menu {
                    Button(L("pkt.saveAs")) { cap.saveAs() }.disabled(cap.pcapURL == nil)
                    if let dir = cap.saveFolder {
                        Button(L("pkt.saveToFolder", PathUtil.abbreviate(dir))) { cap.copyCapture(toFolder: dir) }
                            .disabled(cap.pcapURL == nil)
                    }
                    Divider()
                    Button(cap.saveFolder == nil ? L("pkt.autoFolder") : L("pkt.changeFolder")) { cap.chooseSaveFolder() }
                    if let dir = cap.saveFolder {
                        Button(L("pkt.showFolder")) { NSWorkspace.shared.open(URL(fileURLWithPath: dir)) }
                        Button(L("pkt.autoOff")) { cap.saveFolder = nil }
                    }
                } label: {
                    Label(L("pkt.save"), systemImage: "square.and.arrow.down")
                }
                .fixedSize()
                .help(cap.saveFolder.map { L("pkt.autoOn", PathUtil.abbreviate($0)) } ?? L("pkt.saveAs"))
                Button { cap.openInWireshark() } label: { Label(L("pkt.openWireshark"), systemImage: "arrow.up.forward.app") }
                    .disabled(cap.pcapURL == nil)
            }
            HStack(spacing: 8) {
                Image(systemName: "line.3.horizontal.decrease.circle").foregroundStyle(.secondary)
                TextField(L("pkt.filter"), text: $filter).textFieldStyle(.roundedBorder)
                    .help(L("pa.filterHelp"))
                if !filter.isEmpty {
                    Button { filter = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(.secondary).help(L("pa.clearFilter"))
                }
                if cap.running {
                    Circle().fill(Color.red).frame(width: 7, height: 7)
                    Text(L("pkt.capturing")).font(.system(size: 11, weight: .semibold)).foregroundStyle(.red)
                }
                Text(modeText).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
            }
            if let f = cap.openedFile {
                Label(L("pa.fileOpened", f.lastPathComponent) + (cap.fileNote.map { " · " + $0 } ?? ""), systemImage: "doc")
                    .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            } else if cap.loadingFile {
                HStack(spacing: 6) { ProgressView().controlSize(.mini); Text(L("pa.loading")).font(.system(size: 11)) }
            }
            if let e = cap.noProcessInfo, cap.running {
                Label(L("pkt.noPktap", e), systemImage: "exclamationmark.triangle")
                    .font(.system(size: 11)).foregroundStyle(.orange)
            }
            if cap.saving {
                HStack(spacing: 6) { ProgressView().controlSize(.mini); Text(L("pkt.saving")).font(.system(size: 11)) }
            } else if let u = cap.lastSaved {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    Text(L("pkt.saved", PathUtil.abbreviate(u.path))).lineLimit(1).truncationMode(.middle)
                    Button(L("action.showInFinder")) { NSWorkspace.shared.activateFileViewerSelecting([u]) }
                        .buttonStyle(.link)
                }
                .font(.system(size: 11))
            } else if let e = cap.saveError {
                Text(e).font(.system(size: 11)).foregroundStyle(.red)
            } else if let dir = cap.saveFolder {
                Label(L("pkt.autoOn", PathUtil.abbreviate(dir)), systemImage: "folder")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }

    /// Tek bakışta: ne kadarı şifreli, kaç izleyici, şifresiz bağlantı var mı.
    private var insights: some View {
        let convs = cap.conversations.values
        let pct = cap.transportBytes == 0 ? 100 : Int((Double(cap.encryptedBytes) / Double(cap.transportBytes) * 100).rounded())
        let trackers = Set(convs.compactMap { Trackers.match($0.host)?.company })
        let plain = convs.filter { !$0.protos.isDisjoint(with: ["HTTP", "FTP", "Telnet", "POP3", "IMAP", "SMTP"]) }.count
        let creds = convs.filter(\.creds).count
        return HStack(spacing: 16) {
            Label(L("pkt.insight.encrypted", "\(pct)%"), systemImage: "lock.fill")
                .foregroundStyle(pct >= 80 ? Color.green : Color.orange)
                .help(L("pkt.insight.encryptedHelp"))
            Button { filter = ""; tab = 1 } label: {
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

    private var modeText: String { L("pkt.modeRoot") }

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
            Button(L("pkt.start")) { cap.start() }.disabled(cap.waitingForRoot)
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
                Button(L("pkt.start")) { cap.start() }.buttonStyle(.borderedProminent).disabled(cap.waitingForRoot)
            }
        }
    }

    // MARK: Paket tablosu

    /// Tablodaki satırlar. Her çizimde değil, filtre (yazma bitince) ya da paket listesi değişince hesaplanır.
    @State private var rows: [Packet] = []
    /// Filtre değişince tablo baştan kurulur: binlerce satır "eklendi" diye işlenirse tablo her satırın
    /// yüksekliğini tek tek hesaplıyor ve uygulama donuyordu (ör. proto:llmnr silinince 50 → 5000 satır).
    @State private var tableID = 0
    @State private var pendingFilter: DispatchWorkItem?

    private static func compute(_ packets: [Packet], _ filter: String, _ names: [String: String]) -> [Packet] {
        var list = packets
        let q = filter.trimmingCharacters(in: .whitespaces)
        if !q.isEmpty { list = list.filter { PacketFilter.matches($0, query: q, names: names) } }
        // En yenisi üstte; tablo en fazla 5000 satır çizer (hepsi bellekte ve .pcap'te).
        return Array(list.suffix(5000).reversed())
    }

    /// Filtre: yazma bitince (0,25 sn) arka planda süz, sonra tabloyu yeniden kur.
    private func refilter(rebuild: Bool = true, delay: Double = 0.25) {
        pendingFilter?.cancel()
        let (ps, f, n) = (cap.packets, filter, cap.names)
        let w = DispatchWorkItem {
            DispatchQueue.global(qos: .userInitiated).async {
                let r = Self.compute(ps, f, n)
                DispatchQueue.main.async {
                    guard f == filter else { return }   // bu arada yine değiştiyse eskisini gösterme
                    rows = r
                    if rebuild { tableID += 1 }
                }
            }
        }
        pendingFilter = w
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: w)
    }

    private var packetTable: some View {
        Table(rows, selection: $selection) {
            TableColumn("") { p in
                let e = Explainer.packet(p, host: cap.names[p.dst], app: p.eproc ?? p.proc ?? "—", signature: cap.signature(for: p.epid ?? p.pid))
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
        .id(tableID)
    }

    private func addr(_ ip: String, _ port: Int?) -> some View {
        let name = cap.names[ip]
        return Text((name ?? ip) + (port.map { ":\($0)" } ?? ""))
            .font(.system(size: 11.5, design: name == nil ? .monospaced : .default))
            .lineLimit(1).truncationMode(.middle)
            .help(ip)
    }

    // MARK: Konuşmalar

    private var conversations: [Conversation] { cap.conversationList }

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
        if case .packet(let s) = center.navFocus { filter = ""; tab = 0; selection = s }
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
                        ExplanationCard(e: Explainer.conversation(c, signature: cap.signature(for: c.pid)))
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
                        BlockButton(ip: c.remote).controlSize(.small)
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
                let e = Explainer.conversation(c, signature: cap.signature(for: c.pid))
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
    /// Filtre uygula (ör. "Bu akışı filtrele").
    var apply: (String) -> Void = { _ in }
    @State private var showStream = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                actions
                ExplanationCard(e: Explainer.packet(p, host: cap.names[p.dst], app: p.eproc ?? p.proc ?? L("x.someApp"), signature: cap.signature(for: p.epid ?? p.pid)))
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
                        // Satırlar kırılmasın ama panel genişlemesin: döküm kendi içinde yatay kayar.
                        ScrollView(.horizontal) {
                            Text(Self.dump(hex)).font(.system(size: 10.5, design: .monospaced)).textSelection(.enabled)
                                .fixedSize(horizontal: true, vertical: false)
                                .padding(.bottom, 6)
                        }
                        if let pl = p.pl, pl * 2 < hex.count {
                            Text(L("pa.payloadAt", pl)).font(.system(size: 10.5)).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .underPageBackgroundColor).opacity(0.25))
        .sheet(isPresented: $showStream) { StreamView(anchor: p).environmentObject(cap) }
    }

    /// İnceleme kısayolları.
    private var actions: some View {
        FlowLayout(spacing: 6) {
            if p.sport != nil {
                Button { showStream = true } label: { Label(L("pa.followStream"), systemImage: "arrow.left.arrow.right") }
                Button(L("pa.filterStream")) { apply(PacketFilter.stream(of: p)) }
            }
            Button(L("pa.filterIP", p.dst.isEmpty ? p.src : p.dst)) { apply("ip:" + (Conversation.isLocal(p.dst) ? p.src : p.dst)) }
            Button(L("pa.filterProto", p.proto)) { apply("proto:" + p.proto.lowercased()) }
            Menu(L("pa.more")) {
                Button(L("pa.copyHex")) { copy(p.hex ?? "") }
                Button(L("pa.copySummary")) {
                    copy("#\(p.seq) \(p.proto) \(p.src):\(p.sport ?? 0) → \(p.dst):\(p.dport ?? 0) \(p.len)B \(p.info)")
                }
                let remote = Conversation.isLocal(p.dst) ? p.src : p.dst
                if !Conversation.isLocal(remote), !remote.isEmpty {
                    Divider()
                    Button(L("pa.lookupAbuse")) { open("https://www.abuseipdb.com/check/\(remote)") }
                    Button(L("pa.lookupVT")) { open("https://www.virustotal.com/gui/ip-address/\(remote)") }
                    Button(L("pa.lookupShodan")) { open("https://www.shodan.io/host/\(remote)") }
                }
            }
            .fixedSize()
            let remote = Conversation.isLocal(p.dst) ? p.src : p.dst
            if !remote.isEmpty, !Conversation.isLocal(remote) { BlockButton(ip: remote) }
        }
        .controlSize(.small)
    }

    private func copy(_ t: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(t, forType: .string) }
    private func open(_ u: String) { if let url = URL(string: u) { NSWorkspace.shared.open(url) } }

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
