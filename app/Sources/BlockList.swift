import Foundation

/// Engellenen sunucular: kullanıcının klasöründeki düz bir liste. Yönetici yardımcısı (root) bu dosyadan
/// yalnızca geçerli IP adreslerini alır ve macOS'un güvenlik duvarına (pf) uygular.
@MainActor
final class BlockList: ObservableObject {
    static let shared = BlockList()
    static let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/permwatch/blocklist")

    @Published private(set) var ips: [String] = []

    private init() { load() }

    func load() {
        let text = (try? String(contentsOf: Self.url, encoding: .utf8)) ?? ""
        ips = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter(Self.isIP)
    }

    nonisolated static func isIP(_ s: String) -> Bool {
        var a4 = in_addr(), a6 = in6_addr()
        return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1
    }

    /// "1.2.3.4:443" ya da "[2001:db8::1]:443" → yalnızca adres.
    nonisolated static func host(of endpoint: String) -> String {
        if endpoint.hasPrefix("["), let r = endpoint.firstIndex(of: "]") { return String(endpoint[endpoint.index(after: endpoint.startIndex)..<r]) }
        let parts = endpoint.split(separator: ":")
        return parts.count == 2 ? String(parts[0]) : endpoint
    }

    func contains(_ ip: String) -> Bool { ips.contains(ip) }

    func toggle(_ ip: String) {
        guard Self.isIP(ip) else { return }
        if let i = ips.firstIndex(of: ip) { ips.remove(at: i) } else { ips.append(ip) }
        save()
    }

    func remove(_ ip: String) { ips.removeAll { $0 == ip }; save() }

    private func save() {
        try? FileManager.default.createDirectory(at: Self.url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? (ips.joined(separator: "\n") + "\n").write(to: Self.url, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: Self.url.path)
    }
}
