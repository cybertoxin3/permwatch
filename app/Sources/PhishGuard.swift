import AppKit
import Foundation
import SwiftUI

// MARK: - Sahte site tanıma

/// Bir alan adının gerçek bir bankayı, devlet sitesini ya da büyük bir markayı taklit edip etmediğine bakar.
/// Hiçbir şey göndermez: yalnızca yerel liste ve kurallar.
enum Phish {
    enum Reason: Equatable {
        case lookalike(String)   // taklit ettiği gerçek alan adı
        case listed(String)      // kaynak (OpenPhish/PhishTank)
    }

    /// Bankalara ek olarak sıkça taklit edilen gerçek alan adları.
    static let extraLegit: [String] = [
        "apple.com", "google.com", "google.com.tr", "googleusercontent.com", "gstatic.com", "youtube.com", "gmail.com",
        "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "facebook.com", "instagram.com",
        "whatsapp.com", "netflix.com", "amazon.com", "amazon.com.tr", "amazon.de", "trendyol.com", "hepsiburada.com",
        "n11.com", "sahibinden.com", "ptt.gov.tr", "yurticikargo.com", "araskargo.com.tr", "mngkargo.com.tr",
        "steamcommunity.com", "steampowered.com", "epicgames.com", "roblox.com", "linkedin.com", "twitter.com", "x.com",
        "yandex.ru", "yandex.com.tr", "mail.ru", "vk.com", "ozon.ru", "wildberries.ru", "dhl.com", "ups.com", "fedex.com",
        "github.com", "dropbox.com", "adobe.com", "metamask.io", "trezor.io", "ledger.com",
    ]

    static let legit: [String] = SensitiveSites.domains + extraLegit

    /// Taklit edilen marka sözcükleri → gerçek alan adı. Genel sözcükler (turkiye, online…) dışarıda.
    static let tokens: [(token: String, domain: String)] = {
        let generic: Set = ["turkiye", "online", "param", "chase", "tosla", "office", "outlook", "github", "adobe", "ledger",
                            "mail", "live", "ozon", "steam", "trezor", "colendi", "kraken", "burgan", "icloud", "gstatic",
                            "googleusercontent", "microsoftonline", "steampowered", "steamcommunity"]
        var out: [(String, String)] = [("edevlet", "turkiye.gov.tr"), ("gosuslugi", "gosuslugi.ru")]
        var seen = Set(out.map(\.0))
        for d in legit where d.contains(".") {
            let t = registrable(d).label.replacingOccurrences(of: "-", with: "")
            guard t.count >= 5, !generic.contains(t), !seen.contains(t) else { continue }
            seen.insert(t); out.append((t, d))
        }
        return out
    }()

    /// Taklit sitelerde marka adının yanına eklenen sözcükler (applesupport-id.com, akbankgiris.com).
    static let lureWords = ["giris", "login", "signin", "secure", "guvenli", "guvenlik", "verify", "dogrula", "onay", "destek",
                            "support", "update", "guncelle", "hesap", "account", "id", "mobil", "sube", "odeme",
                            "pay", "bonus", "kampanya", "puan", "iade", "refund", "wallet", "auth", "service", "help",
                            "musteri", "kart", "card", "login", "giris", "sifre", "password", "unlock", "kilit", "ceza", "kargo", "aidat"]

    static let twoLevelSuffixes: Set = ["com.tr", "gov.tr", "org.tr", "net.tr", "edu.tr", "biz.tr", "web.tr", "gen.tr",
                                        "av.tr", "co.uk", "org.uk", "ac.uk", "gov.uk", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.il", "com.sg",
                                        "com.tw", "com.hk", "com.pl", "co.id", "com.my", "com.vn", "com.sa", "com.eg", "com.au", "co.jp", "co.kr", "com.br", "com.ua",
                                        "org.ua", "gov.ua", "com.ru", "co.in", "com.cn", "com.mx", "co.za", "co.nz", "com.ar"]

    /// "online.isbank.com.tr" → ("isbank", "isbank.com.tr")
    static func registrable(_ host: String) -> (label: String, domain: String) {
        let parts = host.lowercased().split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return (host, host) }
        let lastTwo = parts.suffix(2).joined(separator: ".")
        let second = parts[parts.count - 2], last = parts[parts.count - 1]
        let generic2 = last.count == 2 && ["com", "co", "net", "org", "gov", "edu", "ac", "ne", "or", "go", "gob", "gv"].contains(second)
        let n = (twoLevelSuffixes.contains(lastTwo) || generic2) && parts.count >= 3 ? 3 : 2
        let dom = parts.suffix(n).joined(separator: ".")
        return (parts[parts.count - n], dom)
    }

    static func isLegit(_ host: String) -> Bool {
        let h = host.lowercased()
        return legit.contains { d in d.contains(".") ? (h == d || h.hasSuffix("." + d)) : h.split(separator: ".").contains { $0 == d } }
    }

    /// Benzer görünen karakterleri sadeleştirir: paypa1 → paypal, rn → m, 0 → o.
    static func normalize(_ s: String) -> String {
        var t = s.lowercased().replacingOccurrences(of: "-", with: "")
        for (a, b) in [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("ı", "i")] {
            t = t.replacingOccurrences(of: a, with: b)
        }
        return t
    }

    /// Bir marka adına bir harf uzaklıkta olan gerçek sözcükler/siteler.
    static let nearMissWords: Set = ["finance", "revolt", "pinance", "amazona", "paypay", "googie", "yandexe"]

    static func verdict(_ host: String, listed: (String) -> String? = { ThreatIntel.store.phishSource($0) }) -> Reason? {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard h.contains("."), !isLegit(h) else { return nil }
        if let src = listed(h) { return .listed(src) }
        let (reg, _) = registrable(h)
        let labels = h.split(separator: ".").map(String.init)
        let regIndex = labels.lastIndex(of: reg) ?? 0
        let subLabels = labels[..<regIndex]                     // registrable alan adından önceki etiketler
        let regParts = reg.split(separator: "-").map { normalize(String($0)) }
        let regWhole = normalize(reg)
        func lure(_ s: Substring) -> Bool { lureWords.contains { s.hasPrefix($0) || s.hasSuffix($0) } }
        for (t, d) in tokens {
            // 1) Harf taklidi: paypa1, rnicrosoft, g00gle (yazılış farklı, sadeleşince aynı)
            if regWhole == t, reg.replacingOccurrences(of: "-", with: "") != t { return .lookalike(d) }
            // 2) Marka başka bir alan adının alt etiketi: isbank.com.tr.hesap-onay.xyz, paypal.secure-login.top
            if subLabels.contains(where: { normalize($0) == t }) { return .lookalike(d) }
            // 3) Marka + tuzak sözcük: garantibbva-giris, secure-paypal, akbankgiris, applesupport-id
            if regParts.count > 1, regParts.contains(t), regParts.contains(where: { $0 != t && lure(Substring($0)) }) { return .lookalike(d) }
            if regWhole != t, let r = regWhole.range(of: t) {
                let rest = regWhole[r.upperBound...], before = regWhole[..<r.lowerBound]
                if (rest.isEmpty || lure(rest)) && (before.isEmpty || lure(before)) { return .lookalike(d) }
            }
            // 4) Yazım hatası: garantibbvva, yapikerdi, netfiix
            if t.count >= 7, regWhole != t, !nearMissWords.contains(regWhole), abs(regWhole.count - t.count) <= 2,
               distance(regWhole, t) <= (t.count >= 10 ? 2 : 1) { return .lookalike(d) }
        }
        return nil
    }

    /// Damerau-Levenshtein (bitişik harf yer değiştirmesi 1 sayılır).
    static func distance(_ a: String, _ b: String) -> Int {
        let x = Array(a), y = Array(b)
        if x.isEmpty { return y.count }
        if y.isEmpty { return x.count }
        var d = [[Int]](repeating: [Int](repeating: 0, count: y.count + 1), count: x.count + 1)
        for i in 0...x.count { d[i][0] = i }
        for j in 0...y.count { d[0][j] = j }
        for i in 1...x.count {
            for j in 1...y.count {
                let c = x[i - 1] == y[j - 1] ? 0 : 1
                d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
                if i > 1, j > 1, x[i - 1] == y[j - 2], x[i - 2] == y[j - 1] { d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1) }
            }
        }
        return d[x.count][y.count]
    }
}

// MARK: - Şifre alanı anında denetim

/// Bir tarayıcıda şifre alanına odaklanıldığı an (macOS güvenli klavye girişi) açık sekmenin adresine bakar;
/// sahte görünüyorsa kullanıcı şifreyi yazmadan önce uyarır. Saniyede bir, maliyeti yok denecek kadar az bir
/// sistem çağrısı yapar; adres yalnızca o an okunur.
@MainActor
final class PhishGuard: ObservableObject {
    static let shared = PhishGuard()
    static let enabledKey = "phishGuard"
    static let allowKey = "phishAllowed"

    @Published var enabled: Bool = UserDefaults.standard.object(forKey: PhishGuard.enabledKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(enabled, forKey: Self.enabledKey); restart() }
    }
    @Published private(set) var allowed: Set<String> = Set(UserDefaults.standard.stringArray(forKey: PhishGuard.allowKey) ?? [])
    @Published private(set) var current: (host: String, reason: Phish.Reason, browser: String)?
    @Published private(set) var blockedCount = UserDefaults.standard.integer(forKey: "phishBlocked")

    private var timer: Timer?
    private var wasOn = false
    private var lastHost: String?
    nonisolated static let testHost = ProcessInfo.processInfo.environment["PERMWATCH_PHISH_TEST_HOST"]

    private init() { restart() }

    private func restart() {
        timer?.invalidate(); timer = nil
        guard enabled, Snapshot.section == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }

    private func tick() {
        let on = SecureInput.isOn || Self.testHost != nil
        defer { wasOn = on }
        guard on, !wasOn else { if !on { lastHost = nil }; return }
        guard let (bid, name) = browserInFront() ?? (Self.testHost != nil ? ("test", "Safari") : nil) else { return }
        guard let host = Self.testHost ?? BrowserTab.host(bundleID: bid), host != lastHost else { return }
        lastHost = host
        guard !allowed.contains(registrableKey(host)), let reason = Phish.verdict(host) else { return }
        current = (host, reason, bid)
        if Self.testHost != nil { FileHandle.standardError.write(Data("phish: \(host) → \(reason) [\(name)]\n".utf8)) }
        PhishAlertController.shared.show(self)
    }

    /// Şifre alanının sahibi bir tarayıcı mı (öndeki uygulama)?
    private func browserInFront() -> (String, String)? {
        guard let app = NSWorkspace.shared.frontmostApplication, let bid = app.bundleIdentifier, BrowserTab.scripts[bid] != nil else { return nil }
        return (bid, app.localizedName ?? bid)
    }

    private func registrableKey(_ host: String) -> String { Phish.registrable(host).domain }

    /// "Sayfayı kapat": sekmeyi kapatır.
    func closePage() {
        if let c = current, c.browser != "test" { BrowserTab.closeTab(bundleID: c.browser) }
        blockedCount += 1
        UserDefaults.standard.set(blockedCount, forKey: "phishBlocked")
        current = nil
        PhishAlertController.shared.hide()
    }

    /// "Bu site güvenli": bu alan adı için bir daha uyarma.
    func trust() {
        if let c = current {
            allowed.insert(registrableKey(c.host))
            UserDefaults.standard.set(Array(allowed), forKey: Self.allowKey)
        }
        current = nil
        PhishAlertController.shared.hide()
    }

    func untrust(_ d: String) {
        allowed.remove(d)
        UserDefaults.standard.set(Array(allowed), forKey: Self.allowKey)
    }

    /// Ayarlardaki "Uyarıyı dene".
    func demo() {
        current = ("garantibbva-giris.com", .lookalike("garantibbva.com.tr"), "test")
        PhishAlertController.shared.show(self, demo: true)
    }
}

// MARK: - Uyarı kartı

@MainActor
final class PhishAlertController {
    static let shared = PhishAlertController()
    private var windows: [NSWindow] = []
    private(set) var demo = false

    func show(_ g: PhishGuard, demo: Bool = false) {
        self.demo = demo
        hide()
        for (i, screen) in NSScreen.screens.enumerated() {
            let w = NSWindow(contentRect: screen.frame, styleMask: [.borderless], backing: .buffered, defer: false, screen: screen)
            w.isReleasedWhenClosed = false
            w.backgroundColor = .clear
            w.isOpaque = false
            w.level = .screenSaver
            w.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
            w.contentView = NSHostingView(rootView: PhishAlertView(primary: i == 0, demo: demo).environmentObject(g))
            w.setFrame(screen.frame, display: true)
            w.makeKeyAndOrderFront(nil)
            windows.append(w)
        }
        NSApp.activate(ignoringOtherApps: true)
    }

    func hide() {
        for w in windows { w.orderOut(nil) }
        windows = []
    }
}

struct PhishAlertView: View {
    let primary: Bool
    var demo = false
    @EnvironmentObject var g: PhishGuard

    var body: some View {
        ZStack {
            Color.black.opacity(0.4).ignoresSafeArea()
            if primary, let c = g.current { card(c).padding(40) }
        }
    }

    private func card(_ c: (host: String, reason: Phish.Reason, browser: String)) -> some View {
        VStack(spacing: 16) {
            if demo {
                Text(L("sg.demoBanner")).font(.system(size: 11.5, weight: .semibold)).padding(.horizontal, 10).padding(.vertical, 4)
                    .background(Color.yellow.opacity(0.85), in: Capsule()).foregroundStyle(.black)
            }
            Image(systemName: "exclamationmark.shield.fill").font(.system(size: 40)).foregroundStyle(.orange)
            Text(L("ph.title")).font(.system(size: 19, weight: .bold)).multilineTextAlignment(.center)
            VStack(spacing: 6) {
                Text(c.host).font(.system(size: 14, weight: .semibold, design: .monospaced)).textSelection(.enabled)
                Group {
                    switch c.reason {
                    case .lookalike(let real): Text(L("ph.lookalike", real))
                    case .listed(let src): Text(L("ph.listed", src))
                    }
                }
                .font(.system(size: 12.5)).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            .padding(12).frame(maxWidth: .infinity)
            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            Text(L("ph.body")).font(.system(size: 13)).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            Button { demo ? PhishAlertController.shared.hide() : g.closePage() } label: {
                Text(L("ph.close")).frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent).controlSize(.large).keyboardShortcut(.defaultAction)
            Button(L("ph.trust")) { demo ? PhishAlertController.shared.hide() : g.trust() }
                .buttonStyle(.borderless).font(.system(size: 12)).foregroundStyle(.secondary)
        }
        .padding(28)
        .frame(width: 480)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Color.primary.opacity(0.08)))
        .shadow(color: .black.opacity(0.35), radius: 30, y: 10)
    }
}
