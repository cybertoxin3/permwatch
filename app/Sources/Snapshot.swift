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
        if section == "guards" {
            for c in SecurityPosture.evaluate() { print("güvenlik\t\(c.id)\t\(c.state)\t\(c.detail ?? "")") }
            print("mikrofon kullanan pid: \(MediaMonitor.micPIDs())  kamera açık: \(MediaMonitor.cameraRunning())")
            let net = NetworkMonitor.collect()
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
        DispatchQueue.main.asyncAfter(deadline: .now() + 6) {
            guard let win = NSApp.windows.first(where: { $0.isVisible && $0.contentView != nil && $0.frame.width > 600 }),
                  let frameView = win.contentView?.superview else {
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
