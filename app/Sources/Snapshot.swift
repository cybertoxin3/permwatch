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
        let scheme: ColorScheme = ProcessInfo.processInfo.environment["PERMWATCH_DARK"] == nil ? .light : .dark
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
