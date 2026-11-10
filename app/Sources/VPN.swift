import AppKit
import Compression
import Foundation
import Security

/// Bir VPN bağlantı profili (AmneziaWG ya da Xray). Özel anahtarlar içerir: Anahtar Zinciri'nde saklanır.
struct VPNProfile: Codable, Identifiable, Equatable {
    enum Kind: String, Codable { case awg, xray }
    enum Source: String, Codable { case paid, own }

    var id = UUID().uuidString
    var name: String
    var kind: Kind
    var server: String
    var source: Source = .own
    var dns: [String] = []
    var awg: AWG?
    var xrayOutbound: String?       // JSON metni (tek outbound)
    var added = Date()

    struct AWG: Codable, Equatable {
        var privateKey: String
        var publicKey: String
        var presharedKey: String?
        var endpoint: String
        var address: [String]
        var mtu: Int?
        var keepalive: Int?
        var params: [String: String]  // jc, jmin, s1, h1, i1, header_protection_key…
    }

    var kindLabel: String { kind == .awg ? "AWG" : "Xray Reality" }

    /// Yönetici yardımcısına gidecek istek (vpn/want.json).
    func request() -> [String: Any] {
        var r: [String: Any] = ["id": id, "kind": kind.rawValue, "dns": dns]
        if let a = awg {
            var o: [String: Any] = ["privateKey": a.privateKey, "publicKey": a.publicKey, "endpoint": a.endpoint,
                                    "address": a.address, "params": a.params]
            if let p = a.presharedKey { o["presharedKey"] = p }
            if let m = a.mtu { o["mtu"] = m }
            if let k = a.keepalive { o["keepalive"] = k }
            r["awg"] = o
        }
        if let x = xrayOutbound, let o = try? JSONSerialization.jsonObject(with: Data(x.utf8)) { r["outbound"] = o }
        return r
    }
}

enum VPNLinkError: Error { case unknown, noProfiles }

/// Bağlantı linklerini çözer:
///  - Amnezia "vpn://…" (base64url + Qt zlib sıkıştırması + JSON): AmneziaWG ve Xray kapları
///  - "[Interface] … [Peer]" metni (AmneziaWG/WireGuard yapılandırması)
///  - "vless://…" (Reality) linki
enum VPNLink {
    static func parse(_ raw: String) throws -> [VPNProfile] {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.lowercased().hasPrefix("vless://") { return [try vless(text)] }
        if text.contains("[Interface]") { return [try wgQuick(text, name: nil, dns: [])] }
        var body = text
        if body.lowercased().hasPrefix("vpn://") { body = String(body.dropFirst(6)) }
        guard let data = base64url(body) else { throw VPNLinkError.unknown }
        let json = qUncompress(data) ?? data
        guard let obj = (try? JSONSerialization.jsonObject(with: json)) as? [String: Any] else { throw VPNLinkError.unknown }
        let list = amnezia(obj)
        if list.isEmpty { throw VPNLinkError.noProfiles }
        return list
    }

    static func base64url(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            .filter { !$0.isWhitespace }
        while b.count % 4 != 0 { b += "=" }
        return Data(base64Encoded: b)
    }

    /// Qt qCompress: 4 bayt (büyük uçlu) açık boyut + zlib akışı (2 bayt başlık + deflate + 4 bayt adler32).
    static func qUncompress(_ d: Data) -> Data? {
        guard d.count > 6 else { return nil }
        let size = d.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        guard size > 0, size < 16 << 20 else { return nil }
        let deflate = d.dropFirst(6)
        var out = Data(count: size)
        let n = out.withUnsafeMutableBytes { dst in
            deflate.withUnsafeBytes { src in
                compression_decode_buffer(dst.bindMemory(to: UInt8.self).baseAddress!, size,
                                          src.bindMemory(to: UInt8.self).baseAddress!, deflate.count, nil, COMPRESSION_ZLIB)
            }
        }
        return n > 0 ? out.prefix(n) : nil
    }

    /// Amnezia sunucu yapılandırması → profiller.
    static func amnezia(_ o: [String: Any]) -> [VPNProfile] {
        let name = (o["description"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? (o["hostName"] as? String) ?? "Amnezia"
        let host = o["hostName"] as? String ?? ""
        let dns = [o["dns1"] as? String, o["dns2"] as? String].compactMap { $0 }.filter { !$0.isEmpty }
        var out: [VPNProfile] = []
        for c in (o["containers"] as? [[String: Any]]) ?? [] {
            let cname = (c["container"] as? String) ?? ""
            for (key, value) in c {
                guard let proto = value as? [String: Any], let lastStr = proto["last_config"] as? String,
                      let last = (try? JSONSerialization.jsonObject(with: Data(lastStr.utf8))) as? [String: Any] else { continue }
                if key.contains("awg") || key == "wireguard" || cname.contains("awg") && key != "xray" {
                    if let conf = last["config"] as? String, var p = try? wgQuick(conf, name: name, dns: dns) {
                        p.server = host.isEmpty ? p.server : host
                        out.append(p)
                    }
                } else if key == "xray" || cname.contains("xray") {
                    let outbound: Any? = (last["outbounds"] as? [[String: Any]])?.first { ($0["protocol"] as? String).map { ["vless", "vmess", "trojan", "shadowsocks"].contains($0) } ?? false }
                        ?? (last["protocol"] != nil ? last : nil)
                    if let ob = outbound, let d = try? JSONSerialization.data(withJSONObject: ob), let s = String(data: d, encoding: .utf8) {
                        out.append(VPNProfile(name: name, kind: .xray, server: host, dns: dns, xrayOutbound: s))
                    }
                }
            }
        }
        return out
    }

    /// wg-quick biçimi (AmneziaWG parametreleriyle).
    static func wgQuick(_ text: String, name: String?, dns: [String]) throws -> VPNProfile {
        var section = "", iface: [String: String] = [:], peer: [String: String] = [:], params: [String: String] = [:]
        var dnsList = dns
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") { section = line.lowercased(); continue }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let k = line[..<eq].trimmingCharacters(in: .whitespaces)
            let v = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if section == "[interface]" {
                switch k.lowercased() {
                case "privatekey", "address", "mtu", "listenport": iface[k.lowercased()] = v
                case "dns": dnsList = v.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                default: params[snake(k)] = v
                }
            } else if section == "[peer]" {
                peer[k.lowercased()] = v
            }
        }
        guard let priv = iface["privatekey"], let pub = peer["publickey"], let ep = peer["endpoint"], let addr = iface["address"] else {
            throw VPNLinkError.unknown
        }
        let host = ep.split(separator: ":").dropLast().joined(separator: ":").trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let awg = VPNProfile.AWG(privateKey: priv, publicKey: pub, presharedKey: peer["presharedkey"], endpoint: ep,
                                 address: addr.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) },
                                 mtu: iface["mtu"].flatMap { Int($0) }, keepalive: peer["persistentkeepalive"].flatMap { Int($0) },
                                 params: params)
        return VPNProfile(name: name ?? host, kind: .awg, server: host, dns: dnsList, awg: awg)
    }

    /// "HeaderProtectionKey" → "header_protection_key", "Jc" → "jc", "S1" → "s1"
    static func snake(_ k: String) -> String {
        var out = ""
        for (i, c) in k.enumerated() {
            if c.isUppercase, i > 0, !(k[k.index(k.startIndex, offsetBy: i - 1)].isUppercase) { out += "_" }
            out += c.lowercased()
        }
        return out
    }

    /// vless://uuid@host:port?security=reality&sni=…&pbk=…&sid=…&fp=chrome&flow=xtls-rprx-vision&type=tcp#ad
    static func vless(_ link: String) throws -> VPNProfile {
        guard let u = URLComponents(string: link), let id = u.user, let host = u.host, let port = u.port else { throw VPNLinkError.unknown }
        var q: [String: String] = [:]
        for i in u.queryItems ?? [] { q[i.name] = i.value ?? "" }
        let network = q["type"] ?? "tcp"
        var stream: [String: Any] = ["network": network]
        let security = q["security"] ?? "none"
        stream["security"] = security
        if security == "reality" {
            stream["realitySettings"] = ["serverName": q["sni"] ?? "", "publicKey": q["pbk"] ?? "", "shortId": q["sid"] ?? "",
                                         "fingerprint": q["fp"] ?? "chrome", "spiderX": q["spx"] ?? ""]
        } else if security == "tls" {
            stream["tlsSettings"] = ["serverName": q["sni"] ?? host, "fingerprint": q["fp"] ?? "chrome"]
        }
        if network == "grpc" { stream["grpcSettings"] = ["serviceName": q["serviceName"] ?? ""] }
        if network == "xhttp" { stream["xhttpSettings"] = ["path": q["path"] ?? "/", "host": q["host"] ?? ""] }
        if network == "ws" { stream["wsSettings"] = ["path": q["path"] ?? "/", "headers": ["Host": q["host"] ?? host]] }
        var user: [String: Any] = ["id": id, "encryption": q["encryption"] ?? "none"]
        if let f = q["flow"], !f.isEmpty { user["flow"] = f }
        let outbound: [String: Any] = ["protocol": "vless",
                                       "settings": ["vnext": [["address": host, "port": port, "users": [user]]]],
                                       "streamSettings": stream]
        let d = try JSONSerialization.data(withJSONObject: outbound)
        let name = u.fragment?.removingPercentEncoding.flatMap { $0.isEmpty ? nil : $0 } ?? host
        return VPNProfile(name: name, kind: .xray, server: host, xrayOutbound: String(data: d, encoding: .utf8))
    }
}

// MARK: - Yönetici

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()
    nonisolated static let keychainService = "permwatch.vpn"
    static let selectedKey = "vpnSelected"
    nonisolated static let statePath = "/Library/Application Support/permwatch/vpn.json"
    nonisolated static var wantPath: String { NSHomeDirectory() + "/Library/Application Support/permwatch/vpn/want.json" }

    enum State: String { case off, connecting, connected, error }

    @Published private(set) var profiles: [VPNProfile] = []
    @Published var selected: String? = UserDefaults.standard.string(forKey: VPNManager.selectedKey) {
        didSet { UserDefaults.standard.set(selected, forKey: Self.selectedKey) }
    }
    @Published private(set) var state: State = .off
    @Published private(set) var since: Date?
    @Published private(set) var error: String?
    @Published private(set) var rx = 0
    @Published private(set) var tx = 0
    @Published private(set) var connectedID: String?

    private var timer: Timer?

    var enginesBundled: Bool {
        let r = Bundle.main.resourcePath ?? ""
        return FileManager.default.isExecutableFile(atPath: r + "/vpn/amneziawg-go") && FileManager.default.isExecutableFile(atPath: r + "/vpn/xray")
    }

    private init() {
        profiles = Self.load()
        if selected == nil { selected = profiles.first?.id }
        connectedID = Self.readWantID()
        guard Snapshot.section == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.poll() }
        }
        poll()
    }

    func add(link: String, paid: Bool) throws -> Int {
        var list = try VPNLink.parse(link)
        for i in list.indices { list[i].source = paid ? .paid : .own }
        // Aynı sunucu ve tür zaten varsa yenisiyle değiştir (link yenilendiğinde).
        for p in list {
            profiles.removeAll { $0.server == p.server && $0.kind == p.kind }
            profiles.append(p)
        }
        Self.save(profiles)
        if selected == nil || !profiles.contains(where: { $0.id == selected }) { selected = list.first?.id }
        return list.count
    }

    func remove(_ p: VPNProfile) {
        if connectedID == p.id { disconnect() }
        profiles.removeAll { $0.id == p.id }
        Self.save(profiles)
        if selected == p.id { selected = profiles.first?.id }
    }

    func connect(_ p: VPNProfile) {
        guard let d = try? JSONSerialization.data(withJSONObject: p.request()) else { return }
        let dir = (Self.wantPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        FileManager.default.createFile(atPath: Self.wantPath, contents: d, attributes: [.posixPermissions: 0o600])
        connectedID = p.id
        state = .connecting
        error = nil
        if !RootBridge.shared.active { RootBridge.shared.enable() }
    }

    func disconnect() {
        try? FileManager.default.removeItem(atPath: Self.wantPath)
        connectedID = nil
        state = .off
    }

    private func poll() {
        guard let d = FileManager.default.contents(atPath: Self.statePath),
              let j = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
              let ts = j["ts"] as? Double, Date().timeIntervalSince1970 - ts < 15 else {
            if connectedID != nil, state != .connecting { state = .connecting }
            return
        }
        let s = State(rawValue: j["state"] as? String ?? "off") ?? .off
        if connectedID == nil, s == .off { state = .off } else { state = s }
        since = (j["since"] as? Double).map { Date(timeIntervalSince1970: $0) }
        error = j["error"] as? String
        if let b = j["bytes"] as? [Int], b.count == 2 { rx = b[0]; tx = b[1] }
        if let r = j["rx"] as? Int, r > 0 { rx = r }
        if let t = j["tx"] as? Int, t > 0 { tx = t }
    }

    nonisolated static func readWantID() -> String? {
        guard let d = FileManager.default.contents(atPath: wantPath),
              let j = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return nil }
        return j["id"] as? String
    }

    // MARK: Anahtar Zinciri

    nonisolated static func load() -> [VPNProfile] {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService,
                                kSecAttrAccount as String: "profiles", kSecReturnData as String: true]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return [] }
        return (try? JSONDecoder().decode([VPNProfile].self, from: d)) ?? []
    }

    nonisolated static func save(_ list: [VPNProfile]) {
        guard let d = try? JSONEncoder().encode(list) else { return }
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService,
                                   kSecAttrAccount as String: "profiles"]
        if SecItemUpdate(base as CFDictionary, [kSecValueData as String: d] as CFDictionary) == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = d
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(add as CFDictionary, nil)
        }
    }
}

// MARK: - Yıllık VPN aboneliği (kripto)

enum VPNPlan {
    static let priceUSD = 25
    /// README'deki adreslerle aynı (Bana bir kahve ısmarlar mısın?).
    struct Coin {
        let name: String
        let symbol: String
        let network: String
        let address: String
        let geckoID: String?      // nil: dolara sabit (USDT, USDC)
        let decimals: Int         // gösterilen/ödenen ondalık
        let token: String?        // ERC-20 sözleşmesi
        let tokenDecimals: Int
    }

    /// README'deki adreslerle aynı (Bana bir kahve ısmarlar mısın?).
    static let coins: [Coin] = [
        Coin(name: "USDT", symbol: "USDT", network: "Ethereum (ERC-20)", address: "0xCD9ab39db50A830e157776a97bc9Ae21811e3177",
             geckoID: nil, decimals: 2, token: "0xdAC17F958D2ee523a2206206994597C13D831ec7", tokenDecimals: 6),
        Coin(name: "USDC", symbol: "USDC", network: "Ethereum (ERC-20)", address: "0xCD9ab39db50A830e157776a97bc9Ae21811e3177",
             geckoID: nil, decimals: 2, token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", tokenDecimals: 6),
        Coin(name: "Bitcoin (BTC)", symbol: "BTC", network: "Bitcoin (SegWit)", address: "bc1qevw8l3pwfahysgmxy0vhv2srnk0dcyze7pggq8",
             geckoID: "bitcoin", decimals: 8, token: nil, tokenDecimals: 0),
        Coin(name: "Ethereum (ETH)", symbol: "ETH", network: "Ethereum", address: "0xCD9ab39db50A830e157776a97bc9Ae21811e3177",
             geckoID: "ethereum", decimals: 6, token: nil, tokenDecimals: 0),
        Coin(name: "Litecoin (LTC)", symbol: "LTC", network: "Litecoin (SegWit)", address: "ltc1qx40ryzy34vf5977aq5uk3rpqm7err5jvf7gcwl",
             geckoID: "litecoin", decimals: 8, token: nil, tokenDecimals: 0),
        Coin(name: "Solana (SOL)", symbol: "SOL", network: "Solana", address: "5uwHKnCMFbFpob2ssypd69svUFCYZQePCwZcQfELckAD",
             geckoID: "solana", decimals: 5, token: nil, tokenDecimals: 0),
        Coin(name: "Dogecoin (DOGE)", symbol: "DOGE", network: "Dogecoin", address: "DTtZ7oJELg9hs43o1g97qVM676H46XorAT",
             geckoID: "dogecoin", decimals: 2, token: nil, tokenDecimals: 0),
        Coin(name: "Monero (XMR)", symbol: "XMR", network: "Monero", address: "42tsRvBWbPujgVpQdNy6Ba6ovKNcPkxQBKWn1rYcENDpAPTuvQ2ejxCXcUc5KJQTdkHicn4agR7GnYroSUGQLzVhL93KmTt",
             geckoID: "monero", decimals: 6, token: nil, tokenDecimals: 0),
    ]

    /// 25 $ karşılığı, gösterilen ondalığa YUKARI yuvarlanmış (eksik ödeme olmasın).
    static func amount(for c: Coin, usdPrice: Decimal) -> Decimal {
        guard usdPrice > 0 else { return 0 }
        var raw = Decimal(priceUSD) / usdPrice, out = Decimal()
        NSDecimalRound(&out, &raw, c.decimals, .up)
        return out
    }

    static func format(_ d: Decimal, decimals: Int) -> String {
        let f = NumberFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.minimumFractionDigits = min(decimals, 2); f.maximumFractionDigits = decimals
        f.minimumIntegerDigits = 1; f.usesGroupingSeparator = false
        return f.string(from: d as NSDecimalNumber) ?? "\(d)"
    }

    /// En küçük birime çevirir (wei, token birimi): tam sayı metni.
    static func baseUnits(_ d: Decimal, decimals: Int) -> String {
        var v = d * pow(Decimal(10), decimals), out = Decimal()
        NSDecimalRound(&out, &v, 0, .up)
        return (out as NSDecimalNumber).stringValue
    }

    /// Cüzdanların okuduğu ödeme bağlantısı: adres + tutar (BIP-21, EIP-681, Solana Pay, Monero).
    static func paymentURI(_ c: Coin, amount: Decimal) -> String {
        let amt = format(amount, decimals: c.decimals)
        if let t = c.token { return "ethereum:\(t)@1/transfer?address=\(c.address)&uint256=\(baseUnits(amount, decimals: c.tokenDecimals))" }
        switch c.symbol {
        case "ETH": return "ethereum:\(c.address)@1?value=\(baseUnits(amount, decimals: 18))"
        case "BTC": return "bitcoin:\(c.address)?amount=\(amt)"
        case "LTC": return "litecoin:\(c.address)?amount=\(amt)"
        case "DOGE": return "dogecoin:\(c.address)?amount=\(amt)"
        case "SOL": return "solana:\(c.address)?amount=\(amt)"
        case "XMR": return "monero:\(c.address)?tx_amount=\(amt)"
        default: return c.address
        }
    }

    /// Güncel dolar kurları (yalnızca kur indirilir, hiçbir şey gönderilmez). Önce CoinGecko, olmazsa Coinbase.
    static func fetchPrices() async -> [String: Decimal]? {
        let ids = coins.compactMap(\.geckoID).joined(separator: ",")
        if let u = URL(string: "https://api.coingecko.com/api/v3/simple/price?ids=\(ids)&vs_currencies=usd"),
           let (d, r) = try? await URLSession.shared.data(from: u), (r as? HTTPURLResponse)?.statusCode == 200,
           let j = (try? JSONSerialization.jsonObject(with: d)) as? [String: [String: Any]] {
            var out: [String: Decimal] = [:]
            for (k, v) in j { if let p = v["usd"] as? NSNumber { out[k] = p.decimalValue } }
            if out.count >= 3 { return out }
        }
        // Yedek: Coinbase (1 USD = x coin); Monero yok.
        guard let u = URL(string: "https://api.coinbase.com/v2/exchange-rates?currency=USD"),
              let (d, _) = try? await URLSession.shared.data(from: u),
              let j = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
              let rates = (j["data"] as? [String: Any])?["rates"] as? [String: String] else { return nil }
        var out: [String: Decimal] = [:]
        for c in coins where c.geckoID != nil {
            if let r = rates[c.symbol], let v = Decimal(string: r, locale: Locale(identifier: "en_US_POSIX")), v > 0 { out[c.geckoID!] = 1 / v }
        }
        return out.isEmpty ? nil : out
    }

    /// Ödeme bildirimi: permwatch'ın geliştiricisine e-posta (işlem kodu + iletişim adresi). Kullanıcı gönder'e basar.
    static func notify(coin: String, network: String, tx: String, contact: String, amount: String = "", rate: String = "") {
        let ver = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let body = """
        \(L("vpn.mailIntro"))

        Coin: \(coin) (\(network))
        Amount: \(amount)
        Rate: \(rate)
        Tx: \(tx)
        Contact: \(contact)
        Plan: permwatch VPN, 1 year, \(priceUSD) USD
        App: permwatch \(ver), macOS \(ProcessInfo.processInfo.operatingSystemVersionString)
        """
        let subject = "permwatch VPN: \(coin) \(tx.prefix(12))"
        if let s = NSSharingService(named: .composeEmail), s.canPerform(withItems: [body]) {
            s.recipients = [ProblemReport.address]
            s.subject = subject
            s.perform(withItems: [body])
            return
        }
        var c = URLComponents()
        c.scheme = "mailto"
        c.path = ProblemReport.address
        c.queryItems = [URLQueryItem(name: "subject", value: subject), URLQueryItem(name: "body", value: body)]
        if let u = c.url { NSWorkspace.shared.open(u) }
    }

    /// İşlem kodu biçim denetimi (yazım hatalarını yakalamak için; zincirde doğrulamayı geliştirici yapar).
    static func validTx(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespaces)
        let hex = t.hasPrefix("0x") ? String(t.dropFirst(2)) : t
        if hex.count == 64, hex.allSatisfy(\.isHexDigit) { return true }
        // Solana imzası: base58, 80-90 karakter
        let b58 = Set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        return (80...90).contains(t.count) && t.allSatisfy { b58.contains($0) }
    }
}
