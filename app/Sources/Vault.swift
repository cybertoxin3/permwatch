import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Kasadaki bir kayıt.
struct VaultItem: Codable, Identifiable, Equatable {
    var id = UUID().uuidString
    var title: String
    var url: String
    var username: String
    var password: String
    var notes: String = ""
    var created = Date()
    var updated = Date()
}

/// Diskteki kasa dosyası. Şifreler AES-256-GCM ile şifreli; anahtar ana paroladan PBKDF2-SHA256 ile türetilir.
///
///   kasaAnahtarı  = rastgele 256 bit
///   sarmalıAnahtar = AES-GCM(PBKDF2(anaParola, tuz, 600 000), kasaAnahtarı)
///   kayıtlar      = AES-GCM(kasaAnahtarı, JSON)
///
/// Ana parola hiçbir yerde saklanmaz. Touch ID açıksa kasa anahtarı ayrıca Anahtar Zinciri'nde tutulur ve
/// yalnızca Touch ID / Mac parolası doğrulandıktan sonra okunur.
struct VaultFile: Codable {
    var version = 1
    var salt: Data
    var iterations: Int
    var wrappedKey: Data      // AES-GCM birleşik biçim (nonce|şifreli|etiket)
    var items: Data           // AES-GCM birleşik biçim
}

enum VaultCrypto {
    static let iterations = 600_000

    static func randomBytes(_ n: Int) -> Data {
        var d = Data(count: n)
        _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        return d
    }

    /// PBKDF2-HMAC-SHA256 → 256 bit anahtar.
    static func deriveKey(password: String, salt: Data, iterations: Int) -> SymmetricKey? {
        let pw = Array(password.utf8)
        var out = [UInt8](repeating: 0, count: 32)
        let status = salt.withUnsafeBytes { s in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw.map { Int8(bitPattern: $0) }, pw.count,
                                 s.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations), &out, out.count)
        }
        return status == kCCSuccess ? SymmetricKey(data: out) : nil
    }

    static func seal(_ data: Data, key: SymmetricKey) throws -> Data {
        guard let c = try AES.GCM.seal(data, using: key).combined else { throw CocoaError(.coderInvalidValue) }
        return c
    }

    static func open(_ data: Data, key: SymmetricKey) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: key)
    }

    /// Güçlü şifre: harf, rakam ve simge; karışabilen karakterler (0/O, 1/l/I) yok.
    static func generate(length: Int = 20) -> String {
        let lower = Array("abcdefghijkmnopqrstuvwxyz"), upper = Array("ABCDEFGHJKLMNPQRSTUVWXYZ")
        let digits = Array("23456789"), symbols = Array("!@#$%&*-_=+?")
        let all = lower + upper + digits + symbols
        func pick(_ s: [Character]) -> Character {
            var r: UInt32 = 0
            _ = SecRandomCopyBytes(kSecRandomDefault, 4, &r)
            return s[Int(r % UInt32(s.count))]
        }
        var chars = [pick(lower), pick(upper), pick(digits), pick(symbols)]
        while chars.count < length { chars.append(pick(all)) }
        for i in stride(from: chars.count - 1, to: 0, by: -1) {
            var r: UInt32 = 0
            _ = SecRandomCopyBytes(kSecRandomDefault, 4, &r)
            chars.swapAt(i, Int(r % UInt32(i + 1)))
        }
        return String(chars)
    }

    /// Kaba güç tahmini (bit): karakter kümesi büyüklüğü × uzunluk; tekrar ve sık kalıplar düşürür.
    static func strength(_ p: String) -> Int {
        guard !p.isEmpty else { return 0 }
        var pool = 0
        if p.contains(where: \.isLowercase) { pool += 26 }
        if p.contains(where: \.isUppercase) { pool += 26 }
        if p.contains(where: \.isNumber) { pool += 10 }
        if p.contains(where: { !$0.isLetter && !$0.isNumber }) { pool += 32 }
        let unique = Set(p).count
        var bits = Int(Double(min(p.count, unique * 2)) * log2(Double(max(pool, 2))))
        let common = ["123456", "password", "qwerty", "sifre", "parola", "111111", "abc123", "iloveyou", "admin"]
        if common.contains(where: { p.lowercased().contains($0) }) { bits = min(bits, 20) }
        return bits
    }
}

@MainActor
final class Vault: ObservableObject {
    static let shared = Vault()
    nonisolated static var path: String { NSHomeDirectory() + "/Library/Application Support/permwatch/vault.pwv" }
    static let touchIDKey = "vaultTouchID"
    nonisolated static let keychainService = "permwatch.vault"

    @Published private(set) var exists = FileManager.default.fileExists(atPath: Vault.path)
    @Published private(set) var unlocked = false
    @Published private(set) var items: [VaultItem] = []
    @Published var touchID: Bool = UserDefaults.standard.bool(forKey: Vault.touchIDKey) {
        didSet {
            UserDefaults.standard.set(touchID, forKey: Self.touchIDKey)
            if touchID, let k = key { Self.keychainStore(k) } else if !touchID { Self.keychainDelete() }
        }
    }

    private var key: SymmetricKey?
    private var file: VaultFile?
    private var idleTimer: Timer?
    private var lastUse = Date()
    static let autoLock: TimeInterval = 5 * 60

    private init() {
        let nc = DistributedNotificationCenter.default()
        nc.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { Vault.shared.lock() }
        }
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { Vault.shared.lock() }
        }
    }

    // MARK: Oluşturma, açma, kilitleme

    func create(master: String) throws {
        let salt = VaultCrypto.randomBytes(16)
        guard let kek = VaultCrypto.deriveKey(password: master, salt: salt, iterations: VaultCrypto.iterations) else { throw CocoaError(.coderInvalidValue) }
        let vk = SymmetricKey(size: .bits256)
        let wrapped = try VaultCrypto.seal(vk.withUnsafeBytes { Data($0) }, key: kek)
        let body = try VaultCrypto.seal(JSONEncoder().encode([VaultItem]()), key: vk)
        file = VaultFile(salt: salt, iterations: VaultCrypto.iterations, wrappedKey: wrapped, items: body)
        key = vk
        items = []
        try write()
        exists = true
        didUnlock()
    }

    /// Ana parolayla aç. Yanlışsa false.
    func unlock(master: String) -> Bool {
        guard let f = readFile(),
              let kek = VaultCrypto.deriveKey(password: master, salt: f.salt, iterations: f.iterations),
              let raw = try? VaultCrypto.open(f.wrappedKey, key: kek) else { return false }
        return open(f, key: SymmetricKey(data: raw))
    }

    /// Touch ID ile aç (açıksa).
    func unlockWithTouchID(completion: @escaping (Bool) -> Void) {
        guard touchID else { completion(false); return }
        let ctx = LAContext()
        ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: L("vault.authReason")) { ok, _ in
            DispatchQueue.main.async {
                guard ok, let raw = Self.keychainLoad(), let f = self.readFile() else { completion(false); return }
                completion(self.open(f, key: SymmetricKey(data: raw)))
            }
        }
    }

    private func open(_ f: VaultFile, key k: SymmetricKey) -> Bool {
        guard let d = try? VaultCrypto.open(f.items, key: k), let list = try? JSONDecoder().decode([VaultItem].self, from: d) else { return false }
        file = f; key = k; items = list
        didUnlock()
        return true
    }

    private func didUnlock() {
        unlocked = true
        touch()
        idleTimer?.invalidate()
        idleTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { _ in
            MainActor.assumeIsolated {
                if Date().timeIntervalSince(Vault.shared.lastUse) > Vault.autoLock { Vault.shared.lock() }
            }
        }
    }

    /// Kullanıcı bir şey yaptıkça otomatik kilit süresi baştan başlar.
    func touch() { lastUse = Date() }

    func lock() {
        key = nil; items = []; unlocked = false
        idleTimer?.invalidate(); idleTimer = nil
    }

    func changeMaster(old: String, new: String) -> Bool {
        guard unlock(master: old), let vk = key, var f = file else { return false }
        let salt = VaultCrypto.randomBytes(16)
        guard let kek = VaultCrypto.deriveKey(password: new, salt: salt, iterations: VaultCrypto.iterations),
              let wrapped = try? VaultCrypto.seal(vk.withUnsafeBytes { Data($0) }, key: kek) else { return false }
        f.salt = salt; f.iterations = VaultCrypto.iterations; f.wrappedKey = wrapped
        file = f
        return (try? write()) != nil
    }

    // MARK: Kayıtlar

    func save(_ item: VaultItem) {
        var it = item
        it.updated = Date()
        if let i = items.firstIndex(where: { $0.id == it.id }) { items[i] = it } else { items.insert(it, at: 0) }
        persist()
    }

    func delete(_ item: VaultItem) {
        items.removeAll { $0.id == item.id }
        persist()
    }

    private func persist() {
        touch()
        guard let k = key, var f = file, let body = try? VaultCrypto.seal(JSONEncoder().encode(items), key: k) else { return }
        f.items = body
        file = f
        try? write()
    }

    private func write() throws {
        guard let f = file else { return }
        let dir = (Self.path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let enc = JSONEncoder(); enc.outputFormatting = .prettyPrinted
        try enc.encode(f).write(to: URL(fileURLWithPath: Self.path), options: [.atomic])
        chmod(Self.path, 0o600)
        if touchID, let k = key { Self.keychainStore(k) }
    }

    private func readFile() -> VaultFile? {
        guard let d = FileManager.default.contents(atPath: Self.path) else { return nil }
        return try? JSONDecoder().decode(VaultFile.self, from: d)
    }

    /// Şifreyi panoya kopyalar; 30 saniye sonra (hâlâ oradaysa) siler. Pano geçmişi uygulamalarına "gizli" işaretlenir.
    func copy(_ text: String) {
        touch()
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.declareTypes([.string, NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")], owner: nil)
        pb.setString(text, forType: .string)
        pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let count = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            if NSPasteboard.general.changeCount == count { NSPasteboard.general.clearContents() }
        }
    }

    /// Tarayıcıdan dışa aktarılan CSV (Chrome/Safari/Firefox: name/title, url, username, password).
    func importCSV(_ text: String) -> Int {
        let rows = CSV.parse(text)
        guard let head = rows.first?.map({ $0.lowercased() }) else { return 0 }
        func col(_ names: [String]) -> Int? { head.firstIndex { names.contains($0) } }
        guard let pi = col(["password"]) else { return 0 }
        let ti = col(["name", "title"]), ui = col(["url", "login_uri"]), ni = col(["username", "login_username"])
        var n = 0
        for r in rows.dropFirst() where r.count > pi && !r[pi].isEmpty {
            func v(_ i: Int?) -> String { i.flatMap { $0 < r.count ? r[$0] : nil } ?? "" }
            let url = v(ui)
            let title = v(ti).isEmpty ? (URL(string: url)?.host ?? url) : v(ti)
            if items.contains(where: { $0.url == url && $0.username == v(ni) && $0.password == r[pi] }) { continue }
            items.append(VaultItem(title: title, url: url, username: v(ni), password: r[pi]))
            n += 1
        }
        persist()
        return n
    }

    // MARK: Anahtar Zinciri (yalnızca Touch ID açıkken)

    nonisolated static func keychainStore(_ k: SymmetricKey) {
        keychainDelete()
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService,
                                kSecAttrAccount as String: "key", kSecValueData as String: k.withUnsafeBytes { Data($0) },
                                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        SecItemAdd(q as CFDictionary, nil)
    }

    nonisolated static func keychainLoad() -> Data? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService,
                                kSecAttrAccount as String: "key", kSecReturnData as String: true]
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    nonisolated static func keychainDelete() {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService] as CFDictionary)
    }
}

/// Sızdırılmış şifre denetimi (Have I Been Pwned, k-anonimlik): şifrenin SHA-1 özetinin yalnızca ilk 5 karakteri
/// gönderilir; şifre ya da tam özeti Mac'ten çıkmaz.
enum PwnedCheck {
    static func count(_ password: String) async -> Int? {
        let hash = Insecure.SHA1.hash(data: Data(password.utf8)).map { String(format: "%02X", $0) }.joined()
        let prefix = String(hash.prefix(5)), suffix = hash.dropFirst(5)
        var req = URLRequest(url: URL(string: "https://api.pwnedpasswords.com/range/\(prefix)")!)
        req.setValue("true", forHTTPHeaderField: "Add-Padding")
        req.setValue("permwatch", forHTTPHeaderField: "User-Agent")
        guard let (d, r) = try? await URLSession.shared.data(for: req), (r as? HTTPURLResponse)?.statusCode == 200,
              let text = String(data: d, encoding: .utf8) else { return nil }
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":")
            if parts.count == 2, parts[0] == suffix { return Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0 }
        }
        return 0
    }
}

/// Basit CSV okuyucu (tırnaklı alanlar, alan içinde virgül/satır sonu).
enum CSV {
    static func parse(_ text: String) -> [[String]] {
        var rows: [[String]] = [], row: [String] = [], field = "", quoted = false
        var it = Array(text).makeIterator()
        var pending: Character? = nil
        while let c = pending ?? it.next() {
            pending = nil
            if quoted {
                if c == "\"" {
                    if let n = it.next() { if n == "\"" { field.append("\"") } else { quoted = false; pending = n } } else { quoted = false }
                } else { field.append(c) }
            } else if c == "\"" { quoted = true }
            else if c == "," { row.append(field); field = "" }
            else if c == "\n" || c == "\r\n" || c == "\r" { row.append(field); field = ""; if row.contains(where: { !$0.isEmpty }) { rows.append(row) }; row = [] }
            else { field.append(c) }
        }
        row.append(field)
        if row.contains(where: { !$0.isEmpty }) { rows.append(row) }
        return rows
    }
}
