import AppKit
import Foundation

/// Tek belgede güvenlik raporu (PDF): bir uzmana ya da kuruma göstermek için. Yalnızca bu Mac'te oluşturulur.
@MainActor
enum SecurityReport {
    static func html(posture: SecurityPosture, checks: SecurityChecks, scanner: MalwareScanner, store: Store) -> String {
        func esc(_ s: String) -> String {
            s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
                .replacingOccurrences(of: "\n", with: "<br>")
        }
        func badge(_ text: String, _ color: String) -> String { "<span style='color:\(color);font-weight:600'>\(esc(text))</span>" }
        var h = """
        <html><head><meta charset='utf-8'><style>
        body{font-family:-apple-system,Helvetica;font-size:10.5pt;color:#111;}
        h1{font-size:18pt;margin:0 0 4px 0} h2{font-size:13pt;margin:18px 0 6px 0;border-bottom:1px solid #ccc;padding-bottom:3px}
        p.r{margin:2px 0} p.d{margin:0 0 6px 14px;color:#555}
        .muted{color:#666}
        </style></head><body>
        """
        let host = Host.current().localizedName ?? "Mac"
        let os = ProcessInfo.processInfo.operatingSystemVersionString
        let ver = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        h += "<h1>\(esc(L("rep.title")))</h1><div class='muted'>\(esc(host)) · macOS \(esc(os)) · \(esc(Fmt.full.string(from: Date()))) · permwatch \(esc(ver))</div>"

        // 1) Güvenlik ayarları
        h += "<h2>\(esc(L("rep.posture")))</h2>"
        for c in posture.checks {
            let (t, col): (String, String) = switch c.state {
            case .on: (L("rep.on"), "#1a7f37")
            case .off: (L("rep.off"), "#c62828")
            case .warn: (L("rep.warn"), "#d97706")
            case .unknown: ("?", "#666")
            }
            h += "<p class='r'>\(badge(t, col)) · \(esc(c.title))" + (c.detail.map { " <span class='muted'>(\(esc($0)))</span>" } ?? "") + "</p>"
        }

        // 2) Bulgular (Mac'imi Kontrol Et)
        h += "<h2>\(esc(L("rep.findings")))</h2>"
        let f = checks.findings.filter { $0.verdict == .danger || $0.verdict == .caution }
        if f.isEmpty { h += "<p>\(esc(checks.lastRun == nil ? L("rep.notRun") : L("rep.none")))</p>" } else {
            h += f.map { x in
                "<p class='r'>\(badge(x.verdict == .danger ? L("rep.danger") : L("rep.caution"), x.verdict == .danger ? "#c62828" : "#d97706")) · <b>\(esc(x.title))</b></p><p class='d'>\(esc(x.body))</p>"
            }.joined()
        }

        // 3) Zararlı tarama
        h += "<h2>\(esc(L("rep.malware")))</h2>"
        if let d = scanner.lastScan {
            h += "<p>\(esc(L("rep.lastScan", Fmt.full.string(from: d), scanner.lastScanned.formatted())))</p>"
        } else { h += "<p>\(esc(L("rep.notRun")))</p>" }
        if !scanner.detections.isEmpty {
            h += scanner.detections.map { "<p class='r'>\(badge($0.name, "#c62828")) · \(esc(PathUtil.abbreviate($0.path)))</p>" }.joined()
        }

        // 4) Yüksek riskli olaylar
        let high = store.items.filter { $0.risk == .high && !$0.trusted }.sorted { $0.date > $1.date }
        h += "<h2>\(esc(L("rep.alerts", high.count)))</h2>"
        if !high.isEmpty {
            h += high.prefix(30).map { "<p class='r'><span class='muted'>\(esc(Fmt.relativeDay.string(from: $0.date)))</span> · <b>\(esc($0.title))</b></p><p class='d'>\(esc($0.subtitle))</p>" }.joined()
        }

        // 5) Güncel olmayan uygulamalar
        let up = AppUpdates.shared.outdated
        h += "<h2>\(esc(L("upd.apps.title", up.count)))</h2>"
        if !up.isEmpty {
            h += up.map { "<p class='r'>\($0.critical ? badge(L("upd.apps.critical"), "#d97706") + " · " : "")\(esc($0.name)) <span class='muted'>\(esc($0.installed)) → \(esc($0.latest))</span></p>" }.joined()
        }

        // 6) Ağ
        let net = NetCheck.shared
        h += "<h2>\(esc(L("rep.network")))</h2>"
        h += "<p class='r'>Wi-Fi: \(esc(net.wifiSecurity ?? L("net.wired")))</p>"
        if let g = net.gatewayIP { h += "<p class='r'>\(esc(L("net.router"))): \(esc(g)) · \(esc(net.gatewayMAC ?? "?"))</p>" }
        h += "<p class='r'>\(esc(L("rep.devices"))): \(net.devices.count)</p>"
        for x in NetWatchMonitor.shared.findings {
            h += "<p class='r'>\(badge(x.severity.label, x.severity == .high ? "#c62828" : "#d97706")) · <b>\(esc(x.title))</b></p><p class='d'>\(esc(x.detail))</p>"
        }
        h += "<p class='muted' style='margin-top:24px'>\(esc(L("rep.footer")))</p></body></html>"
        return h
    }

    /// HTML'i A4 sayfalara bölünmüş PDF olarak yazar.
    static func exportPDF(_ html: String, to url: URL) -> Bool {
        guard let data = html.data(using: .utf8),
              let attr = NSAttributedString(html: data, options: [.characterEncoding: String.Encoding.utf8.rawValue], documentAttributes: nil)
        else { return false }
        let info = NSPrintInfo()
        info.paperSize = NSSize(width: 595, height: 842)
        info.topMargin = 40; info.bottomMargin = 40; info.leftMargin = 40; info.rightMargin = 40
        info.horizontalPagination = .fit
        info.verticalPagination = .automatic
        info.isVerticallyCentered = false
        info.isHorizontallyCentered = false
        info.jobDisposition = .save
        info.dictionary()[NSPrintInfo.AttributeKey.jobSavingURL] = url
        // Yükseklik içeriğe göre: sabit sayfa yüksekliği verilirse sonda boş bir sayfa çıkıyordu.
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: 595 - 80, height: 10))
        view.isVerticallyResizable = true
        view.textStorage?.setAttributedString(attr)
        view.sizeToFit()
        let op = NSPrintOperation(view: view, printInfo: info)
        op.showsPrintPanel = false
        op.showsProgressPanel = false
        return op.run()
    }

    static func save(posture: SecurityPosture, checks: SecurityChecks, scanner: MalwareScanner, store: Store) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.pdf]
        let df = DateFormatter(); df.dateFormat = "yyyy-MM-dd"
        panel.nameFieldStringValue = "permwatch-\(L("rep.file"))-\(df.string(from: Date())).pdf"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let h = html(posture: posture, checks: checks, scanner: scanner, store: store)
        if exportPDF(h, to: url) { NSWorkspace.shared.open(url) }
    }
}
