import AppKit
import SwiftUI

/// Geliştirme kancası: PERMWATCH_SNAPSHOT=<dosya.png> ile başlatılırsa ana pencereyi
/// (başlık çubuğuyla birlikte) PNG olarak kaydeder ve çıkar. Ekran kaydı izni gerektirmez.
/// PERMWATCH_SECTION=apps|timeline ile hangi bölümün gösterileceği seçilir.
enum Snapshot {
    static var target: String? { ProcessInfo.processInfo.environment["PERMWATCH_SNAPSHOT"] }
    static var section: String? { ProcessInfo.processInfo.environment["PERMWATCH_SECTION"] }

    /// Tek bir görünümü pencereden bağımsız çizer (cam efektlerinden etkilenmez).
    @MainActor
    static func renderView(_ store: Store, selection: Int?, to path: String) {
        let scheme: ColorScheme = Theme.current.colorScheme
            ?? (ProcessInfo.processInfo.environment["PERMWATCH_DARK"] == nil ? .light : .dark)
        let view: AnyView
        switch section {
        case "detail":
            guard let it = store.item(selection) else { exit(5) }
            view = AnyView(DetailView(item: it, scrollable: false).frame(width: 400, alignment: .top))
        case "cards":
            let apps = Array(store.apps.sorted { ($0.risk, $0.lastSeen) > ($1.risk, $1.lastSeen) }.prefix(6))
            view = AnyView(LazyVGrid(columns: [GridItem(.fixed(520), spacing: 16), GridItem(.fixed(520))], spacing: 16) {
                ForEach(apps) { AppCard(app: $0) }
            }.padding(20).frame(width: 1100))
        default:
            view = AnyView(MenuBarPanel())
        }
        let r = ImageRenderer(content: view.environmentObject(store)
            .background(Color(nsColor: .windowBackgroundColor))
            .environment(\.colorScheme, scheme))
        r.scale = 2
        guard let cg = r.cgImage,
              let png = NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:]) else { exit(6) }
        try? png.write(to: URL(fileURLWithPath: path))
        exit(0)
    }

    @MainActor
    static func scheduleIfRequested(store: Store, selection: Int?) {
        guard let path = target else { return }
        if section == "uninstall-run", let app = ProcessInfo.processInfo.environment["PERMWATCH_APP"] {
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
                let items = Uninstaller.candidates(appPath: app, launchPlists: [])
                Uninstaller.run(items, bundleID: nil, resetPermissions: false) { failed in
                    let out = "aday: \(items.map(\.path))\nkalan: \(failed)\nhâlâ var mı: \(FileManager.default.fileExists(atPath: app))\n"
                    try? out.write(toFile: path, atomically: true, encoding: .utf8)
                    exit(0)
                }
            }
            return
        }
        if section == "uninstall-dry", let app = ProcessInfo.processInfo.environment["PERMWATCH_APP"] {
            // Kuru çalıştırma: hiçbir şey silmeden kaldırılacak öğeleri listeler.
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) {
                print("engel: \(String(describing: Uninstaller.blockReason(app)))  bundle: \(store.bundleID(forKey: app) ?? "-")")
                for c in Uninstaller.candidates(appPath: app, launchPlists: store.launchPlists(forApp: app)) {
                    print(ByteCountFormatter.string(fromByteCount: c.size, countStyle: .file), PathUtil.abbreviate(c.path))
                }
                exit(0)
            }
            return
        }
        if section == "fullscan" {
            // Tam tarama izleme: 15 sn'de bir ilerleme, bakılan/taranan dosya ve o anki yol.
            let m = MalwareScanner.shared
            m.start(.full)
            let t0 = Date()
            Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { _ in
                MainActor.assumeIsolated {
                    let line = String(format: "%5.0f sn  %%%.1f  bakılan %d  taranan %d  okunamayan %d  %@",
                                      Date().timeIntervalSince(t0), max(0, m.progress) * 100, m.examined, m.scanned, m.unreadable, m.current)
                    print(line); fflush(stdout)
                    if !m.running { print("BİTTİ"); exit(0) }
                }
            }
            return
        }
        if section == "scanprobe" {
            // Yavaşlık ölçümü: klasörler için listeleme + tür kontrolü süresi, dosyalar için YARA tarama süresi.
            Thread.detachNewThread {
                let engine = YaraEngine.shared
                _ = engine.load()
                for p in (ProcessInfo.processInfo.environment["PERMWATCH_PROBE"] ?? "").split(separator: "|").map(String.init) {
                    var isDir: ObjCBool = false
                    FileManager.default.fileExists(atPath: p, isDirectory: &isDir)
                    let t = Date()
                    if isDir.boolValue {
                        var n = 0, s = 0, slowest = (0.0, "")
                        Targets.walk(p, maxDepth: 40, executablesOnly: false) { f in
                            n += 1
                            let t1 = Date()
                            if Targets.isScannable(f) { s += 1 }
                            let d = Date().timeIntervalSince(t1)
                            if d > slowest.0 { slowest = (d, f) }
                        }
                        print(String(format: "KLASÖR %6.1f sn  dosya %d  taranacak %d  en yavaş açılan %.1f sn %@", Date().timeIntervalSince(t), n, s, slowest.0, slowest.1))
                    } else {
                        let r = engine.scan(p)
                        print(String(format: "DOSYA  %6.1f sn  %@  %@", Date().timeIntervalSince(t), r == nil ? "okunamadı/zaman aşımı" : "ok", p))
                    }
                    fflush(stdout)
                }
                exit(0)
            }
            return
        }
        if section == "pcapanalyze", let f = ProcessInfo.processInfo.environment["PERMWATCH_PCAP"] {
            // Kayıt dosyasını analiz motorundan geçirir ve bulguları yazar.
            let (ps, total, err) = PacketMonitor.readPcap(URL(fileURLWithPath: f), limit: 20000)
            if let err { print("hata: \(err)"); exit(1) }
            print("okunan: \(ps.count)/\(total) paket, içerikli: \(ps.filter { $0.pl != nil }.count)")
            for x in PacketAnalyzer.analyze(ps, names: [:]) {
                print("[\(x.severity.label)] \(x.title) — \(x.count) — \(x.technique ?? "-")")
                print("    \(x.detail.replacingOccurrences(of: "\n", with: " | "))")
            }
            let st = PacketStats.compute(ps, names: [:])
            print("protokoller: " + st.protocols.prefix(8).map { "\($0.name)=\($0.packets)" }.joined(separator: " "))
            let q = "proto:arp -who"
            print("filtre testi '\(q)': \(ps.filter { PacketFilter.matches($0, query: q, names: [:]) }.count)")
            exit(0)
        }
        if section == "tlscheck" {
            // TLS denetimi: verilen sunucuları denetler.
            Task {
                for h in (ProcessInfo.processInfo.environment["PERMWATCH_HOSTS"] ?? "").split(separator: ",").map(String.init) {
                    let r = await TLSProbe.check(h)
                    print("\(h)\t\(r.verdict)\tveren=\(r.issuer ?? "-")\tkök=\(r.root ?? "-")\tbitiş=\(r.expires.map { "\($0)" } ?? "-")\t\(r.error ?? "")")
                }
                exit(0)
            }
            return
        }
        if section == "origin" {
            // Kalıcılık kaynağı: son giriş öğesi olayları için ipuçlarını yazar.
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) {
                let adds = store.items.filter { $0.kind == .btmAdd }.sorted { $0.date > $1.date }.prefix(6)
                print("giriş öğesi olayı: \(store.items.filter { $0.kind == .btmAdd }.count)")
                for it in adds {
                    print("• \(it.title) — \(it.date) — \(it.removablePlist ?? it.revealPath ?? "-")")
                    for h in Origin.hints(itemDate: it.date, plist: it.removablePlist ?? it.revealPath, appKey: it.appKey).prefix(4) {
                        print("     \(h.kind): \(h.title) | \(h.detail)")
                    }
                }
                exit(0)
            }
            return
        }
        if section == "netscan" {
            // "Ağı tara"yı gerçek ağda çalıştırır ve sonucu yazar.
            let n = NetCheck.shared
            Vendors.prepare()
            n.refresh()
            DispatchQueue.main.asyncAfter(deadline: .now() + 8) {
                n.scan()
                @MainActor func wait() {
                    guard !n.scanning else { DispatchQueue.main.asyncAfter(deadline: .now() + 0.5, execute: wait); return }
                    print("denenen: \(n.lastScan?.probed ?? 0), engellenen: \(n.lastScan?.blocked ?? 0), cihaz: \(n.devices.count), yalıtılmış: \(n.looksIsolated), izin yok: \(n.scanBlocked)")
                    Thread.sleep(forTimeInterval: 3)   // ad çözümü bitsin
                    for d in n.devices.prefix(40) { print("  \(d.ip)\t\(d.mac)\t\(d.isGateway ? "yönlendirici" : "")\t\(d.vendor ?? "-")\t\(d.name ?? "-")") }
                    exit(0)
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: wait)
            }
            return
        }
        if section == "disk-dry" {
            // Disk bölümü kuru çalıştırma: tarar ve sonuçları yazar, hiçbir şey silmez.
            let d = DiskManager.shared
            d.scan()
            @MainActor func wait() {
                guard !d.scanning else { DispatchQueue.main.asyncAfter(deadline: .now() + 0.5, execute: wait); return }
                let f = { (b: Int64) in DiskSize.string(b) }
                for v in d.volumes { print("birim\t\(v.name)\ttoplam \(f(v.total))\tboş \(f(v.availableImportant))\ttemizlenebilir \(f(v.purgeable))") }
                for c in d.categories { print("kategori\t\(c.id)\t\(f(c.size))") }
                print("uygulama: \(d.apps.count), toplam \(f(d.appsSize))")
                for a in d.apps.prefix(12) { print("  \(a.name)\tuyg \(f(a.appSize))\tveri \(f(a.dataSize))\tson \(a.lastUsed.map { Fmt.relative($0) } ?? "-")") }
                for g in JunkGroup.allCases {
                    let l = d.junk.filter { $0.group == g }
                    if !l.isEmpty { print("çöp\t\(g.rawValue)\t\(l.count) öğe\t\(f(l.reduce(0) { $0 + $1.size }))") }
                }
                print("temizlenebilir (seçili): \(f(d.cleanable))")
                print("sahipsiz: \(d.orphans.count), \(f(d.orphanSize))")
                for o in d.orphans.prefix(15) { print("  \(o.id)\t\(f(o.size))\t\(o.paths.count) yer") }
                if let app = ProcessInfo.processInfo.environment["PERMWATCH_APP"], let a = d.adopt(app) {
                    Task {
                        for c in await d.leftovers(for: a, extraLaunch: store.launchPlists(forApp: app)) {
                            print("kalıntı\t\(c.group)\t\(c.byName ? "zayıf" : "kesin")\t\(f(c.size))\t\(PathUtil.abbreviate(c.path))")
                        }
                        exit(0)
                    }
                } else { exit(0) }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: wait)
            return
        }
        if section == "watchtest", let dir = ProcessInfo.processInfo.environment["PERMWATCH_WATCH_TEST"] {
            // İzlenen test klasörüne dosya yazıp taramanın kendiliğinden tetiklendiğini doğrular.
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) {
                let before = store.scanCount
                let t0 = Date()
                FileManager.default.createFile(atPath: dir + "/tetikle.plist", contents: Data())
                @MainActor func check() {
                    if store.scanCount > before {
                        print(String(format: "tetiklendi: %.1f sn sonra tarama yapıldı (%d → %d)",
                                     Date().timeIntervalSince(t0), before, store.scanCount))
                        exit(0)
                    }
                    if Date().timeIntervalSince(t0) > 10 { print("tetiklenmedi"); exit(1) }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.1, execute: check)
                }
                check()
            }
            return
        }
        if section == "dlguard" {
            // DownloadGuard'ı gerçek haliyle çalıştırır (Spotlight + klasörler) ve sonucu yazar.
            let g = DownloadGuard()
            DispatchQueue.main.asyncAfter(deadline: .now() + 8) {
                print("izlenen klasörler: " + g.folders.map { "\(PathUtil.abbreviate($0.path))[\($0.source)]" }.joined(separator: ", "))
                for i in g.items {
                    print("bulundu\t\(PathUtil.abbreviate(i.path))\tkabul=\(String(describing: i.accepted))\tkaynak=\(i.source ?? "-")\trisk=\(i.risk)")
                }
                print("toplam: \(g.items.count)")
                exit(0)
            }
            return
        }
        if section == "guards" {
            for c in SecurityPosture.evaluate() { print("güvenlik\t\(c.id)\t\(c.state)\t\(c.detail ?? "")") }
            print("mikrofon kullanan pid: \(MediaMonitor.micPIDs())  kamera açık: \(MediaMonitor.cameraRunning())")
            let net = NetworkMonitor.collect(rootLsof: RootBridge.parse()?.lsof)
            print("ağ: \(net.count) bağlantı, riskli: \(net.filter { $0.risk >= .caution }.count), dinleyen: \(net.filter { $0.state.contains("LISTEN") }.count)")
            for c in net where c.risk >= .caution { print("  ağ-risk\t\(c.name)\t\(c.remote ?? c.local)\t\(c.rules)") }
            let dir = ProcessInfo.processInfo.environment["PERMWATCH_DL_TEST"] ?? (NSHomeDirectory() + "/Downloads")
            for n in (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
            where ["app", "pkg", "dmg"].contains((n as NSString).pathExtension.lowercased()) {
                let d = DownloadGuard.assess(path: dir + "/" + n, date: Date())
                print("indirme\t\(d.name)\tkabul=\(String(describing: d.accepted))\tkaynak=\(d.source ?? "-")\tkarantina=\(d.quarantined)\trisk=\(d.risk)")
            }
            let extras = SystemScanner.extraPersistence()
            print("kalıcılık: " + Dictionary(grouping: extras, by: \.type).map { "\($0.key)=\($0.value.count)" }.sorted().joined(separator: " "))
            for x in extras where x.note != nil { print("  işaretli\t\(x.type)\t\(x.name)\t\(x.note!)") }
            exit(0)
        }
        if section == "hud" {
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                ThreatCenter.shared.report(Threat(id: "test-hud", risk: .high, title: "\(Risk.high.label): \(L("alert.process"))",
                    detail: "syslogd (pid 4242) · " + L("prule.masquerade"), iconKey: nil, section: .running, focus: .process(4242)))
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                    guard let w = NSApp.windows.first(where: { $0 is NSPanel && $0.isVisible }), let v = w.contentView else { print("panel yok"); exit(2) }
                    print("panel konumu: \(w.frame)  ekran: \(NSScreen.main?.visibleFrame ?? .zero)")
                    let rep = v.bitmapImageRepForCachingDisplay(in: v.bounds)!
                    v.cacheDisplay(in: v.bounds, to: rep)
                    try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
                    exit(0)
                }
            }
            return
        }
        if section == "procdump" {
            // Çalışan süreçlerin özeti (test için)
            let (_, first) = ProcessMonitor.collect(prev: [:], trusted: [])
            usleep(500_000)
            let (rows, _) = ProcessMonitor.collect(prev: first, trusted: [])
            let withMem = rows.filter { $0.memory != nil }.count
            print("süreç: \(rows.count), bellek/CPU okunabilen: \(withMem), imzalar: " +
                  Dictionary(grouping: rows, by: { $0.signature ?? "yok" }).map { "\($0.key)=\($0.value.count)" }.sorted().joined(separator: " "))
            for r in rows.sorted(by: { ($0.cpu ?? 0) > ($1.cpu ?? 0) }).prefix(5) {
                print(String(format: "  en yoğun: %@ pid %d cpu %.1f mem %@", r.name, r.pid, r.cpu ?? -1,
                             r.memory.map { ByteCountFormatter.string(fromByteCount: Int64($0), countStyle: .memory) } ?? "-"))
            }
            for r in rows where r.risk >= .caution {
                print("\(r.risk == .high ? "YÜKSEK" : "dikkat")\t\(r.name) (\(r.pid))\t\(r.path ?? "-")\t\(r.rules.map(\.rawValue).joined(separator: ","))")
            }
            exit(0)
        }
        if section == "dump" {
            // Uyarıların düz metin dökümü (test için): risk, tarih, başlık, kurallar.
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) {
                for it in store.items where it.risk >= .caution {
                    print("\(it.risk == .high ? "YÜKSEK" : "dikkat")\t\(it.title)\t\(it.subtitle)\t\(it.rules.map(\.rawValue).joined(separator: ","))")
                }
                print("toplam olay: \(store.items.count), uygulama: \(store.apps.count)")
                exit(0)
            }
            return
        }
        if let s = section, ["detail", "cards", "menu"].contains(s) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) { renderView(store, selection: selection, to: path) }
            return
        }
        let delay = Double(ProcessInfo.processInfo.environment["PERMWATCH_SNAPSHOT_DELAY"] ?? "") ?? 6
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            guard let win = NSApp.windows.first(where: { $0.isVisible && $0.contentView != nil && $0.frame.width > 600 }),
                  let frameView = win.contentView?.superview else {
                for w in NSApp.windows { FileHandle.standardError.write(Data("pencere: \(type(of: w)) görünür=\(w.isVisible) \(w.frame)\n".utf8)) }
                exit(2)
            }
            // Katman ağacını doğrudan çiz: cacheDisplay yarı saydam (vibrancy) arka planları boş bırakıyor.
            frameView.wantsLayer = true
            frameView.layoutSubtreeIfNeeded()
            frameView.displayIfNeeded()
            let scale = win.backingScaleFactor
            let size = frameView.bounds.size
            guard let layer = frameView.layer,
                  let ctx = CGContext(data: nil, width: Int(size.width * scale), height: Int(size.height * scale),
                                      bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { exit(3) }
            ctx.scaleBy(x: scale, y: scale)
            ctx.setFillColor(win.backgroundColor.cgColor)
            ctx.fill(CGRect(origin: .zero, size: size))
            layer.render(in: ctx)
            guard let cg = ctx.makeImage(),
                  let png = NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:]) else { exit(4) }
            try? png.write(to: URL(fileURLWithPath: path))
            exit(0)
        }
    }
}
