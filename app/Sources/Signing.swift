import AppKit
import Security

/// Diskteki bir uygulamanın kod imzasını okur (yalnızca dosya mevcutsa).
enum Signing {
    struct Info {
        var teamID: String?
        var organization: String?
        var isApple: Bool
    }

    private static var cache: [String: Info?] = [:]

    static func info(path: String) -> Info? {
        if let c = cache[path] { return c }
        var result: Info?
        defer { cache[path] = result }
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return nil }
        var dict: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(code, flags, &dict) == errSecSuccess,
              let info = dict as? [String: Any] else { return nil }
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String
        var org: String?
        var apple = false
        if let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate], let leaf = certs.first,
           let summary = SecCertificateCopySubjectSummary(leaf) as String? {
            // "Developer ID Application: Örnek A.Ş. (ABCDE12345)" → "Örnek A.Ş."
            apple = summary.hasPrefix("Software Signing") || summary.hasPrefix("Apple ")
            var s = summary
            if let r = s.range(of: ": ") { s = String(s[r.upperBound...]) }
            if let r = s.range(of: " (", options: .backwards) { s = String(s[..<r.lowerBound]) }
            org = apple ? nil : s
        }
        result = Info(teamID: team, organization: org, isApple: apple)
        return result
    }

    /// İmzayı sınıflandırır: apple | developer | adhoc | unsigned.
    /// Yalnızca imza yapısını doğrular (tüm dosyaları hash'lemez), bu yüzden hızlıdır.
    /// Dosya okunamıyorsa (ör. yalnızca root okuyabiliyorsa) "unreadable" döner: imzasız sanmak yanlış alarm olur.
    static func classify(path: String) -> (signature: String, team: String?, identifier: String?) {
        let exe = Bundle(path: path)?.executablePath ?? path
        guard FileManager.default.isReadableFile(atPath: exe) else { return ("unreadable", nil, nil) }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return ("unreadable", nil, nil) }
        var dict: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &dict) == errSecSuccess,
              let info = dict as? [String: Any] else { return ("unreadable", nil, nil) }
        guard let ident = info[kSecCodeInfoIdentifier as String] as? String else { return ("unsigned", nil, nil) }
        let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String
        if flags & 0x2 != 0 { return ("adhoc", nil, ident) }   // CS_ADHOC
        var req: SecRequirement?
        if SecRequirementCreateWithString("anchor apple" as CFString, [], &req) == errSecSuccess, let req,
           SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSBasicValidateOnly), req) == errSecSuccess {
            return ("apple", nil, ident)
        }
        return ("developer", team, ident)
    }

    /// Bundle ID'den yüklü uygulamanın yolunu bulur.
    static func appPath(bundleID: String) -> String? {
        NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)?.path
    }
}
