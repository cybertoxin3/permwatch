import AppKit
import Foundation

/// Gerçek dünyadaki Mac tehditlerine yönelik kontroller: reklam yazılımı/tarayıcı ele geçirme,
/// araya girme (MITM), uzaktan erişim ve casus yazılım belirtileri. Her bulgunun bir düzeltmesi var.
struct Finding: Identifiable, Hashable {
    enum Category: String, CaseIterable { case browser, mitm, remote, spyware }
    enum Fix: Hashable {
        case openURL(String)
        case openInBrowser(app: String, url: String)
        case revoke(key: String, services: [String])
        case untrustCert(name: String, admin: Bool)
        case removeProfile(identifier: String)
        case deleteDefault(domain: String, key: String)
        case disableLaunchItem(plist: String)
        case trash([String])
    }

    let id: String
    let category: Category
    let verdict: Explanation.Verdict
    let title: String
    let body: String
    var iconKey: String? = nil
    var fixes: [(title: String, fix: Fix)] = []

    static func == (a: Finding, b: Finding) -> Bool { a.id == b.id }
    func hash(into h: inout Hasher) { h.combine(id) }
}

@MainActor
final class SecurityChecks: ObservableObject {
    @Published private(set) var findings: [Finding] = []
    @Published private(set) var running = false
    @Published private(set) var lastRun: Date?
    @Published var message: String?

    func run(apps: [AppSummary], rootProfiles: String?) {
        guard !running else { return }
        running = true
        let input = apps.map { ($0.key, $0.name, $0.services, $0.signatureText) }
        Task.detached(priority: .userInitiated) {
            var out: [Finding] = []
            out += Checks.browserExtensions()
            out += Checks.browserPolicies()
            out += Checks.searchAndHome()
            out += Checks.proxy()
            out += Checks.dns()
            out += Checks.trustedCerts()
            out += Checks.profiles(rootOutput: rootProfiles)
            out += Checks.vpns()
            out += Checks.sharing()
            out += Checks.remoteApps()
            out += Checks.spyware(input)
            let result = out
            await MainActor.run {
                self.findings = result
                self.running = false
                self.lastRun = Date()
            }
        }
    }

    func count(_ v: Explanation.Verdict) -> Int { findings.filter { $0.verdict == v }.count }

    /// Düzeltmeyi uygula. Kullanıcının kendi alanında doğrudan; yönetici gerektirenlerde macOS şifre sorar.
    func apply(_ fix: Finding.Fix, store: Store, then: @escaping () -> Void) {
        switch fix {
        case .openURL(let u):
            if let url = URL(string: u) { NSWorkspace.shared.open(url) }
            then()
        case .openInBrowser(let app, let u):
            Shell.run("/usr/bin/open", ["-a", app, u])
            then()
        case .revoke(let key, let services):
            let r = store.revoke(services: services, key: key)
            message = r.message
            then()
        case .untrustCert(let name, let admin):
            DispatchQueue.global().async {
                let r = Checks.untrust(name: name, admin: admin)
                DispatchQueue.main.async { self.message = r; then() }
            }
        case .removeProfile(let id):
            DispatchQueue.global().async {
                let r = Checks.admin("/usr/bin/profiles remove -identifier \(Checks.q(id))")
                DispatchQueue.main.async { self.message = r ?? L("fix.done"); then() }
            }
        case .deleteDefault(let domain, let key):
            let (code, out) = Shell.run("/usr/bin/defaults", ["delete", domain, key])
            message = code == 0 ? L("fix.done") : out
            then()
        case .disableLaunchItem(let plist):
            DispatchQueue.global().async {
                let r = Checks.disableLaunchItem(plist)
                DispatchQueue.main.async { self.message = r; then() }
            }
        case .trash(let paths):
            NSWorkspace.shared.recycle(paths.map { URL(fileURLWithPath: $0) }) { _, err in
                DispatchQueue.main.async {
                    let left = paths.filter { FileManager.default.fileExists(atPath: $0) }
                    if !left.isEmpty { _ = Uninstaller.trashWithFinder(left) }
                    self.message = err == nil || left.allSatisfy({ !FileManager.default.fileExists(atPath: $0) }) ? L("fix.done") : err?.localizedDescription
                    then()
                }
            }
        }
    }
}

// MARK: - Kontroller

enum Checks {
    static let home = NSHomeDirectory()

    static func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    /// Yönetici olarak sabit bir komut (macOS şifre penceresi). Hata yoksa nil.
    static func admin(_ cmd: String) -> String? {
        let script = "do shell script \"\(cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"
        var err: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&err)
        guard let err else { return nil }
        return (err[NSAppleScript.errorMessage] as? String) ?? "\(err[NSAppleScript.errorNumber] ?? "?")"
    }

    // MARK: Tarayıcı uzantıları

    struct Browser { let name: String; let app: String; let dir: String; let store: [String]; let page: String }
    static let chromium: [Browser] = [
        .init(name: "Chrome", app: "Google Chrome", dir: "Google/Chrome", store: ["clients2.google.com"], page: "chrome://extensions/?id="),
        .init(name: "Brave", app: "Brave Browser", dir: "BraveSoftware/Brave-Browser", store: ["clients2.google.com"], page: "brave://extensions/?id="),
        .init(name: "Edge", app: "Microsoft Edge", dir: "Microsoft Edge", store: ["edge.microsoft.com", "clients2.google.com"], page: "edge://extensions/?id="),
        .init(name: "Arc", app: "Arc", dir: "Arc/User Data", store: ["clients2.google.com"], page: "arc://extensions/?id="),
        .init(name: "Vivaldi", app: "Vivaldi", dir: "Vivaldi", store: ["clients2.google.com"], page: "vivaldi://extensions/?id="),
        .init(name: "Opera", app: "Opera", dir: "com.operasoftware.Opera", store: ["extension-updates.opera.com", "clients2.google.com"], page: "opera://extensions/?id="),
        .init(name: "Yandex", app: "Yandex", dir: "Yandex/YandexBrowser", store: ["clients2.google.com", "addons-store.yandex.net"], page: "browser://extensions/?id="),
    ]
    static let broad: Set<String> = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/"]
    /// Sayfaları denetleyen, trafiği yönlendiren, başka uzantıları yöneten ya da ekranı yakalayabilen izinler.
    static let powerful: Set<String> = ["proxy", "debugger", "management", "desktopCapture", "tabCapture"]

    static func profiles(of b: Browser) -> [String] {
        let base = home + "/Library/Application Support/" + b.dir
        return ((try? FileManager.default.contentsOfDirectory(atPath: base)) ?? [])
            .filter { $0 == "Default" || $0.hasPrefix("Profile ") }.map { base + "/" + $0 }
    }

    static func browserExtensions() -> [Finding] {
        var out: [Finding] = []
        let fm = FileManager.default
        for b in chromium {
            for prof in profiles(of: b) {
                let extDir = prof + "/Extensions"
                for id in (try? fm.contentsOfDirectory(atPath: extDir)) ?? [] where id.count == 32 {
                    guard let ver = ((try? fm.contentsOfDirectory(atPath: extDir + "/" + id)) ?? []).sorted().last else { continue }
                    let dir = extDir + "/" + id + "/" + ver
                    guard let data = fm.contents(atPath: dir + "/manifest.json"),
                          let m = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                    let name = extensionName(m, dir: dir) ?? id
                    var perms = Set((m["permissions"] as? [Any] ?? []).compactMap { $0 as? String })
                    perms.formUnion((m["host_permissions"] as? [String]) ?? [])
                    for cs in (m["content_scripts"] as? [[String: Any]]) ?? [] { perms.formUnion((cs["matches"] as? [String]) ?? []) }
                    let allSites = !perms.isDisjoint(with: broad)
                    let power = perms.intersection(powerful).sorted()
                    let update = (m["update_url"] as? String) ?? ""
                    let sideloaded = !update.isEmpty && !b.store.contains(where: update.contains)
                    guard allSites || sideloaded || !power.isEmpty else { continue }
                    let verdict: Explanation.Verdict = sideloaded || !power.isEmpty ? .caution : .info
                    var reasons: [String] = []
                    if allSites { reasons.append(L("chk.ext.allSites")) }
                    if !power.isEmpty { reasons.append(L("chk.ext.power", power.joined(separator: ", "))) }
                    if sideloaded { reasons.append(L("chk.ext.sideloaded")) }
                    let profName = (prof as NSString).lastPathComponent
                    if out.contains(where: { $0.id.hasPrefix("ext.\(b.name).\(id).") }) { continue }   // başka profilde zaten var
                    out.append(Finding(id: "ext.\(b.name).\(id).\(profName)", category: .browser, verdict: verdict,
                                       title: L("chk.ext.title", name, b.name),
                                       body: reasons.joined(separator: " ") + " " + L("chk.ext.advice"),
                                       fixes: [(L("chk.ext.open"), .openInBrowser(app: b.app, url: b.page + id))]))
                }
            }
        }
        // Firefox
        let ffBase = home + "/Library/Application Support/Firefox/Profiles"
        for prof in (try? fm.contentsOfDirectory(atPath: ffBase)) ?? [] {
            guard let data = fm.contents(atPath: ffBase + "/" + prof + "/extensions.json"),
                  let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            for a in (j["addons"] as? [[String: Any]]) ?? [] where (a["type"] as? String) == "extension" && (a["location"] as? String) == "app-profile" {
                let up = a["userPermissions"] as? [String: Any] ?? [:]
                let origins = Set((up["origins"] as? [String]) ?? [])
                let perms = Set((up["permissions"] as? [String]) ?? [])
                let allSites = !origins.isDisjoint(with: broad)
                let power = perms.intersection(powerful).sorted()
                guard allSites || !power.isEmpty else { continue }
                let name = ((a["defaultLocale"] as? [String: Any])?["name"] as? String) ?? (a["id"] as? String ?? "?")
                var reasons: [String] = []
                if allSites { reasons.append(L("chk.ext.allSites")) }
                if !power.isEmpty { reasons.append(L("chk.ext.power", power.joined(separator: ", "))) }
                let fid = "ext.Firefox.\(a["id"] as? String ?? name)"
                if out.contains(where: { $0.id == fid }) { continue }
                out.append(Finding(id: fid, category: .browser,
                                   verdict: power.isEmpty ? .info : .caution,
                                   title: L("chk.ext.title", name, "Firefox"),
                                   body: reasons.joined(separator: " ") + " " + L("chk.ext.advice"),
                                   fixes: [(L("chk.ext.open"), .openInBrowser(app: "Firefox", url: "about:addons"))]))
            }
        }
        return out
    }

    static func extensionName(_ m: [String: Any], dir: String) -> String? {
        guard var name = m["name"] as? String else { return nil }
        if name.hasPrefix("__MSG_"), name.hasSuffix("__") {
            let key = String(name.dropFirst(6).dropLast(2)).lowercased()
            let loc = (m["default_locale"] as? String) ?? "en"
            if let d = FileManager.default.contents(atPath: "\(dir)/_locales/\(loc)/messages.json"),
               let msgs = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
               let entry = msgs.first(where: { $0.key.lowercased() == key })?.value as? [String: Any],
               let msg = entry["message"] as? String { name = msg }
        }
        return name
    }

    // MARK: Zorla uygulanan tarayıcı politikaları

    static let policyDomains = ["com.google.Chrome", "com.brave.Browser", "com.microsoft.Edge", "org.mozilla.firefox",
                                "com.operasoftware.Opera", "com.vivaldi.Vivaldi", "company.thebrowser.Browser"]
    static let riskyPolicies: Set<String> = ["ExtensionInstallForcelist", "ExtensionInstallSources", "ExtensionSettings",
                                             "HomepageLocation", "RestoreOnStartupURLs", "NewTabPageLocation",
                                             "DefaultSearchProviderSearchURL", "DefaultSearchProviderEnabled", "ProxySettings",
                                             "ProxyServer", "ProxyMode", "ProxyPacUrl", "DnsOverHttpsTemplates",
                                             "ExtensionAllowedTypes", "Homepage", "SearchEngines", "Extensions", "Proxy"]

    static func browserPolicies() -> [Finding] {
        var out: [Finding] = []
        let user = NSUserName()
        for domain in policyDomains {
            // Profil ile zorlanmış (yönetilen) ayarlar
            for path in ["/Library/Managed Preferences/\(domain).plist", "/Library/Managed Preferences/\(user)/\(domain).plist"] {
                guard let d = NSDictionary(contentsOfFile: path) as? [String: Any] else { continue }
                let keys = Set(d.keys).intersection(riskyPolicies).sorted()
                guard !keys.isEmpty else { continue }
                out.append(Finding(id: "policy.managed.\(domain)", category: .browser, verdict: .danger,
                                   title: L("chk.policy.title", browserName(domain)),
                                   body: L("chk.policy.managed", keys.joined(separator: ", ")),
                                   fixes: [(L("chk.profiles.open"), .openURL("x-apple.systempreferences:com.apple.Profiles-Settings.extension"))]))
            }
            // Kullanıcı tercihlerine yazılmış politikalar (reklam yazılımlarının sık yaptığı)
            if let d = UserDefaults(suiteName: domain)?.persistentDomain(forName: domain) {
                let keys = Set(d.keys).intersection(riskyPolicies).sorted()
                for k in keys {
                    out.append(Finding(id: "policy.user.\(domain).\(k)", category: .browser, verdict: .caution,
                                       title: L("chk.policy.title", browserName(domain)),
                                       body: L("chk.policy.user", k, String(describing: d[k]!).prefix(160).description),
                                       fixes: [(L("chk.policy.remove"), .deleteDefault(domain: domain, key: k))]))
                }
            }
        }
        return out
    }

    static func browserName(_ domain: String) -> String {
        ["com.google.Chrome": "Chrome", "com.brave.Browser": "Brave", "com.microsoft.Edge": "Edge", "org.mozilla.firefox": "Firefox",
         "com.operasoftware.Opera": "Opera", "com.vivaldi.Vivaldi": "Vivaldi", "company.thebrowser.Browser": "Arc"][domain] ?? domain
    }

    // MARK: Arama motoru ve ana sayfa

    static let knownSearch = ["google.", "bing.com", "duckduckgo.com", "yahoo.com", "yandex.", "ecosia.org", "search.brave.com",
                              "startpage.com", "qwant.com", "baidu.com", "naver.com", "kagi.com", "perplexity.ai", "chatgpt.com"]
    static let hijackWords = ["search", "find", "query", "safe", "browse", "seek", "look", "smart", "quick"]

    static func searchAndHome() -> [Finding] {
        var out: [Finding] = []
        for b in chromium {
            for prof in profiles(of: b) {
                guard let data = FileManager.default.contents(atPath: prof + "/Preferences"),
                      let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                let profName = (prof as NSString).lastPathComponent
                if let url = ((j["default_search_provider_data"] as? [String: Any])?["template_url_data"] as? [String: Any])?["url"] as? String,
                   let host = URL(string: url.replacingOccurrences(of: "{searchTerms}", with: "x"))?.host,
                   !knownSearch.contains(where: host.contains) {
                    out.append(Finding(id: "search.\(b.name).\(profName)", category: .browser, verdict: .caution,
                                       title: L("chk.search.title", b.name), body: L("chk.search.body", host),
                                       fixes: [(L("chk.search.fix"), .openInBrowser(app: b.app, url: b.page.replacingOccurrences(of: "extensions/?id=", with: "settings/search")))]))
                }
                var urls: [String] = []
                if let h = j["homepage"] as? String, (j["homepage_is_newtabpage"] as? Bool) == false { urls.append(h) }
                if let s = j["session"] as? [String: Any], (s["restore_on_startup"] as? Int) == 4 {
                    urls += (s["startup_urls"] as? [String]) ?? []
                }
                for u in urls {
                    guard let host = URL(string: u)?.host?.lowercased(),
                          hijackWords.contains(where: host.contains), !knownSearch.contains(where: host.contains) else { continue }
                    out.append(Finding(id: "home.\(b.name).\(profName).\(host)", category: .browser, verdict: .caution,
                                       title: L("chk.home.title", b.name), body: L("chk.home.body", host),
                                       fixes: [(L("chk.search.fix"), .openInBrowser(app: b.app, url: b.page.replacingOccurrences(of: "extensions/?id=", with: "settings/onStartup")))]))
                }
            }
        }
        return out
    }

    // MARK: Proxy ve DNS

    static func scutilDict(_ args: [String]) -> [String: String] {
        var d: [String: String] = [:]
        for line in Shell.run("/usr/sbin/scutil", args).1.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 { d[parts[0]] = parts[1] }
        }
        return d
    }

    static func proxy() -> [Finding] {
        let p = scutilDict(["--proxy"])
        var items: [String] = []
        for (kind, en, host, port) in [("HTTP", "HTTPEnable", "HTTPProxy", "HTTPPort"), ("HTTPS", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
                                       ("SOCKS", "SOCKSEnable", "SOCKSProxy", "SOCKSPort")] where p[en] == "1" {
            items.append("\(kind) \(p[host] ?? "?"):\(p[port] ?? "?")")
        }
        if p["ProxyAutoConfigEnable"] == "1" { items.append("PAC \(p["ProxyAutoConfigURLString"] ?? "?")") }
        guard !items.isEmpty else { return [] }
        let local = items.allSatisfy { $0.contains("127.0.0.1") || $0.contains("localhost") || $0.contains("::1") }
        return [Finding(id: "proxy", category: .mitm, verdict: local ? .info : .caution,
                        title: L("chk.proxy.title"), body: L(local ? "chk.proxy.local" : "chk.proxy.body", items.joined(separator: ", ")),
                        fixes: [(L("chk.network.open"), .openURL("x-apple.systempreferences:com.apple.Network-Settings.extension"))])]
    }

    static let knownDNS: Set<String> = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222",
                                        "208.67.220.220", "94.140.14.14", "94.140.15.15", "77.88.8.8", "77.88.8.1", "76.76.2.0",
                                        "76.76.10.0", "185.228.168.9", "2606:4700:4700::1111", "2001:4860:4860::8888"]

    static func dns() -> [Finding] {
        var servers: [String] = []
        for line in Shell.run("/usr/sbin/scutil", ["--dns"]).1.split(separator: "\n") where line.contains("nameserver[") {
            if let v = line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces), !servers.contains(v) { servers.append(v) }
        }
        let unknown = servers.filter { !knownDNS.contains($0) && !Conversation.isLocal($0) }
        guard !unknown.isEmpty else { return [] }
        return [Finding(id: "dns.\(unknown.joined(separator: ","))", category: .mitm, verdict: .caution,
                        title: L("chk.dns.title"), body: L("chk.dns.body", unknown.joined(separator: ", ")),
                        fixes: [(L("chk.network.open"), .openURL("x-apple.systempreferences:com.apple.Network-Settings.extension"))])]
    }

    // MARK: Güvenilen kök sertifikalar

    static func trustedCerts() -> [Finding] {
        var out: [Finding] = []
        for admin in [false, true] {
            let text = Shell.run("/usr/bin/security", admin ? ["dump-trust-settings", "-d"] : ["dump-trust-settings"]).1
            var certs: [(name: String, policies: [String], roots: Int)] = []
            for line in text.split(separator: "\n").map(String.init) {
                let t = line.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("Cert "), let r = t.range(of: ": ") {
                    certs.append((String(t[r.upperBound...]), [], 0))
                } else if t.hasPrefix("Number of trust settings"), t.hasSuffix(": 0"), !certs.isEmpty {
                    certs[certs.count - 1].policies.append("*")   // kısıtsız: her amaç için güvenilir
                } else if t.hasPrefix("Policy OID"), let v = t.split(separator: ":", maxSplits: 1).last, !certs.isEmpty {
                    certs[certs.count - 1].policies.append(v.trimmingCharacters(in: .whitespaces))
                }
            }
            for (name, group) in Dictionary(grouping: certs, by: { $0.name }) {
                let pol = Set(group.flatMap(\.policies))
                let ssl = pol.contains("*") || pol.contains { $0.contains("SSL") || $0.contains("Basic") }
                let verdict: Explanation.Verdict = pol.contains("*") || pol.contains(where: { $0.contains("SSL") }) ? .danger : (ssl ? .caution : .info)
                out.append(Finding(id: "cert.\(admin).\(name)", category: .mitm, verdict: verdict,
                                   title: L("chk.cert.title", name),
                                   body: L(ssl ? "chk.cert.ssl" : "chk.cert.limited", group.count.formatted(), pol.sorted().joined(separator: ", ")),
                                   fixes: [(L("chk.cert.fix"), .untrustCert(name: name, admin: admin))]))
            }
        }
        return out
    }

    /// Adı verilen sertifika(lar)ın güven ayarını kaldırır (sertifika silinmez).
    static func untrust(name: String, admin: Bool) -> String {
        let pem = Shell.run("/usr/bin/security", ["find-certificate", "-a", "-c", name, "-p"]).1
        let blocks = pem.components(separatedBy: "-----END CERTIFICATE-----").filter { $0.contains("BEGIN CERTIFICATE") }
        guard !blocks.isEmpty else { return L("fix.notFound") }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("permwatch-certs-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        var errors: [String] = []
        for (i, b) in blocks.enumerated() {
            let f = dir.appendingPathComponent("\(i).pem")
            try? (b + "-----END CERTIFICATE-----\n").write(to: f, atomically: true, encoding: .utf8)
            if admin {
                if let e = Checks.admin("/usr/bin/security remove-trusted-cert -d \(q(f.path))"), !e.contains("not found") { errors.append(e) }
            } else {
                let (c, o) = Shell.run("/usr/bin/security", ["remove-trusted-cert", f.path])
                if c != 0, !o.contains("not found"), !o.contains("could not be found") { errors.append(o) }
            }
        }
        return errors.isEmpty ? L("fix.done") : errors.joined(separator: "; ")
    }

    // MARK: Yapılandırma profilleri ve VPN

    static func profiles(rootOutput: String?) -> [Finding] {
        var text = Shell.run("/usr/bin/profiles", ["show", "-type", "configuration", "-user", NSUserName()]).1
        if let r = rootOutput { text += "\n" + r }
        var out: [Finding] = []
        var seen = Set<String>()
        // "attribute: name: X" ve "attribute: profileIdentifier: Y" satırları; yük türleri de bölümde geçer
        let sections = text.components(separatedBy: "_computerlevel[").count > 1
            ? text.components(separatedBy: "_computerlevel[") : text.components(separatedBy: "\n\n")
        for sec in sections {
            func attr(_ k: String) -> String? {
                sec.split(separator: "\n").first { $0.contains("attribute: \(k): ") }
                    .flatMap { $0.components(separatedBy: "attribute: \(k): ").last?.trimmingCharacters(in: .whitespaces) }
            }
            guard let id = attr("profileIdentifier"), seen.insert(id).inserted else { continue }
            let name = attr("name") ?? id
            let risky = ["com.apple.security.root", "com.apple.security.pkcs1", "com.apple.proxy", "com.apple.dnsSettings",
                         "com.google.Chrome", "com.apple.vpn", "com.apple.webcontent-filter"].filter { sec.contains($0) }
            out.append(Finding(id: "profile.\(id)", category: .mitm, verdict: risky.isEmpty ? .info : .danger,
                               title: L("chk.profile.title", name),
                               body: risky.isEmpty ? L("chk.profile.body") : L("chk.profile.risky", risky.joined(separator: ", ")),
                               fixes: [(L("chk.profiles.open"), .openURL("x-apple.systempreferences:com.apple.Profiles-Settings.extension")),
                                       (L("chk.profile.remove"), .removeProfile(identifier: id))]))
        }
        return out
    }

    static func vpns() -> [Finding] {
        let lines = Shell.run("/usr/sbin/scutil", ["--nc", "list"]).1.split(separator: "\n").filter { $0.contains("VPN") || $0.contains("PPP") || $0.contains("IPSec") }
        let names = lines.compactMap { l -> String? in
            guard let a = l.firstIndex(of: "\""), let b = l.lastIndex(of: "\""), a < b else { return nil }
            return String(l[l.index(after: a)..<b])
        }
        guard !names.isEmpty else { return [] }
        return [Finding(id: "vpn.\(names.joined(separator: ","))", category: .mitm, verdict: names.count > 2 ? .caution : .info,
                        title: L("chk.vpn.title", names.count.formatted()), body: L("chk.vpn.body", names.joined(separator: ", ")),
                        fixes: [(L("chk.vpn.open"), .openURL("x-apple.systempreferences:com.apple.NetworkExtensionSettingsUI.NESettingsUIExtension"))])]
    }

    // MARK: Uzaktan erişim

    static func sharing() -> [Finding] {
        let listening = Set(Shell.run("/usr/sbin/netstat", ["-an", "-p", "tcp"]).1.split(separator: "\n")
            .filter { $0.contains("LISTEN") }.compactMap { $0.split(separator: " ", omittingEmptySubsequences: true).dropFirst(3).first }
            .compactMap { a -> Int? in
                let s = String(a)
                guard !s.hasPrefix("127.") && !s.hasPrefix("::1") else { return nil }
                return Int(s.split(separator: ".").last ?? "")
            })
        let services: [(Int, String, Explanation.Verdict)] = [(22, "chk.share.ssh", .caution), (5900, "chk.share.screen", .caution),
                                                              (3283, "chk.share.ard", .caution), (445, "chk.share.files", .info),
                                                              (548, "chk.share.files", .info), (3389, "chk.share.rdp", .caution)]
        var out: [Finding] = []
        var done = Set<String>()
        for (port, key, v) in services where listening.contains(port) && done.insert(key).inserted {
            out.append(Finding(id: "share.\(key)", category: .remote, verdict: v, title: L(key), body: L("chk.share.body", String(port)),
                               fixes: [(L("chk.share.open"), .openURL("x-apple.systempreferences:com.apple.Sharing-Settings.extension"))]))
        }
        return out
    }

    static let remoteTools: [(match: String, name: String)] = [
        ("teamviewer", "TeamViewer"), ("anydesk", "AnyDesk"), ("rustdesk", "RustDesk"), ("splashtop", "Splashtop"),
        ("screenconnect", "ScreenConnect"), ("connectwise", "ConnectWise Control"), ("logmein", "LogMeIn"), ("gotoassist", "GoTo Resolve"),
        ("zohoassist", "Zoho Assist"), ("remotepc", "RemotePC"), ("nomachine", "NoMachine"), ("realvnc", "RealVNC"), ("vnc server", "VNC Server"),
        ("tightvnc", "TightVNC"), ("parsec", "Parsec"), ("jump desktop", "Jump Desktop"), ("chrome remote desktop", "Chrome Remote Desktop"),
        ("remoting_host", "Chrome Remote Desktop"), ("supremo", "Supremo"), ("aeroadmin", "AeroAdmin"), ("ammyy", "Ammyy Admin"),
        ("todesk", "ToDesk"), ("sunlogin", "Sunlogin"), ("anyviewer", "AnyViewer"), ("dwservice", "DWService"), ("meshagent", "MeshCentral"),
        ("atera", "Atera"), ("ninjarmm", "NinjaOne"), ("kaseya", "Kaseya"), ("action1", "Action1"), ("level.io", "Level"),
    ]

    static func remoteApps() -> [Finding] {
        let fm = FileManager.default
        var places: [String: String] = [:]   // ad → bulunduğu yer
        for dir in ["/Applications", home + "/Applications", "/Library/LaunchDaemons", "/Library/LaunchAgents", home + "/Library/LaunchAgents",
                    "/Library/Application Support", "/opt"] {
            for f in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] {
                let low = f.lowercased()
                if let t = remoteTools.first(where: { low.contains($0.match) }) { places[t.name, default: dir + "/" + f] = places[t.name] ?? dir + "/" + f }
            }
        }
        let running = Set(Advisor.runningPaths().map { $0.lowercased() })
        return places.map { name, path in
            let active = running.contains { r in remoteTools.contains { $0.name == name && r.contains($0.match) } }
            let isLaunch = path.contains("/Launch")
            return Finding(id: "remote.\(name)", category: .remote, verdict: active || isLaunch ? .caution : .info,
                           title: L("chk.remote.title", name),
                           body: L(active ? "chk.remote.running" : "chk.remote.installed", PathUtil.abbreviate(path)),
                           iconKey: path.hasSuffix(".app") ? path : nil,
                           fixes: isLaunch ? [(L("chk.launch.disable"), .disableLaunchItem(plist: path))]
                                           : (path.hasSuffix(".app") ? [(L("action.showInFinder"), .openURL(URL(fileURLWithPath: path).deletingLastPathComponent().absoluteString))] : []))
        }
    }

    static func disableLaunchItem(_ plist: String) -> String {
        let label = (NSDictionary(contentsOfFile: plist)?["Label"] as? String) ?? ((plist as NSString).lastPathComponent as NSString).deletingPathExtension
        if plist.hasPrefix(home) {
            Shell.run("/bin/launchctl", ["bootout", "gui/\(getuid())/\(label)"])
            var res: NSURL?
            do { try FileManager.default.trashItem(at: URL(fileURLWithPath: plist), resultingItemURL: &res); return L("fix.done") }
            catch { return error.localizedDescription }
        }
        let dom = plist.contains("LaunchDaemons") ? "system" : "gui/\(getuid())"
        let user = NSUserName()
        let cmd = "/bin/launchctl bootout \(dom)/\(q(label)) ; /bin/mkdir -p \(q("/Users/\(user)/.Trash")) ; /bin/mv \(q(plist)) \(q("/Users/\(user)/.Trash/"))"
        return admin(cmd) ?? L("fix.done")
    }

    // MARK: Casus yazılım belirtileri (izin kombinasyonları)

    static func spyware(_ apps: [(key: String, name: String, services: [String], signature: String?)]) -> [Finding] {
        var out: [Finding] = []
        for a in apps {
            let s = Set(a.services)
            let screen = s.contains("kTCCServiceScreenCapture")
            let keys = s.contains("kTCCServiceListenEvent")
            let control = s.contains("kTCCServiceAccessibility") || s.contains("kTCCServicePostEvent")
            let mic = s.contains("kTCCServiceMicrophone")
            let score = [screen, keys, control, mic].filter { $0 }.count
            guard score >= 3 || (keys && screen) else { continue }
            let sig = a.key.hasPrefix("/") ? Signing.classify(path: a.key).signature : nil
            if sig == "apple" { continue }
            var caps: [String] = []
            if screen { caps.append(L("chk.spy.screen")) }
            if keys { caps.append(L("chk.spy.keys")) }
            if control { caps.append(L("chk.spy.control")) }
            if mic { caps.append(L("chk.spy.mic")) }
            let unsigned = sig == "unsigned" || sig == "adhoc"
            out.append(Finding(id: "spy.\(a.key)", category: .spyware, verdict: unsigned || score >= 4 ? .danger : .caution,
                               title: L("chk.spy.title", a.name), body: L("chk.spy.body", caps.joined(separator: ", ")),
                               iconKey: a.key.hasPrefix("/") ? a.key : nil,
                               fixes: [(L("adv.revoke"), .revoke(key: a.key, services: a.services.filter {
                                   ["kTCCServiceScreenCapture", "kTCCServiceListenEvent", "kTCCServiceAccessibility",
                                    "kTCCServicePostEvent", "kTCCServiceMicrophone"].contains($0) }))]))
        }
        return out
    }
}
