// Bütünleşik testler: kontrollerin ayrıştırıcıları ve düzeltme eylemleri gerçek sistemde, zararsız
// deneme öğeleriyle. Çalıştır: make test-integration (önce make app).
import AppKit
import Foundation

var failures = 0
func check(_ cond: Bool, _ name: String) { if cond { print("✓ \(name)") } else { failures += 1; print("✗ \(name)") } }

@main struct Integration { @MainActor static func main() {
    // Sertifika güven ayarları
    let trust = """
    Number of trusted certs = 3
    Cert 0: wifi.example.edu
       Number of trust settings : 1
       Trust Setting 0:
          Policy OID            : EAP
          Result Type           : kSecTrustSettingsResultTrustAsRoot
    Cert 1: Evil Proxy CA
       Number of trust settings : 0
    Cert 2: Corp SSL
       Number of trust settings : 1
       Trust Setting 0:
          Policy OID            : Apple SSL
    """
    let t = Checks.parseTrust(trust, admin: false)
    check(t.count == 3, "sertifika: 3 bulgu")
    check(t.first { $0.id.hasSuffix("Evil Proxy CA") }?.verdict == .danger, "kısıtsız güvenilen kök sertifika tehlike")
    check(t.first { $0.id.hasSuffix("Corp SSL") }?.verdict == .danger, "SSL için güvenilen sertifika tehlike")
    check(t.first { $0.id.hasSuffix("wifi.example.edu") }?.verdict == .info, "yalnızca EAP için güvenilen sertifika bilgi")

    // Yapılandırma profilleri
    let prof = """
    _computerlevel[1] attribute: name: Ad Helper
    _computerlevel[1] attribute: profileIdentifier: com.adhelper.profile
    _computerlevel[1] PayloadType = com.google.Chrome
    _computerlevel[2] attribute: name: Company Wi-Fi
    _computerlevel[2] attribute: profileIdentifier: com.corp.wifi
    _computerlevel[2] PayloadType = com.apple.wifi.managed
    """
    let p = Checks.parseProfiles(prof)
    check(p.count == 2, "profil: 2 bulgu (bulunan: \(p.map(\.id)))")
    check(p.first { $0.id == "profile.com.adhelper.profile" }?.verdict == .danger, "tarayıcı politikası kuran profil tehlike")
    check(p.first { $0.id == "profile.com.corp.wifi" }?.verdict == .info, "Wi-Fi profili bilgi")

    // VPN listesi
    let vpn = """
    Available network connection services in the current set (*=enabled):
    * (Disconnected)   DA5E3874 VPN (com.urban-vpn.mac) "Urban VPN Desktop"   [VPN:com.urban-vpn.mac]
    * (Connected)      F1C32D64 VPN (com.example) "Work VPN"                 [VPN:com.example]
    """
    let v = Checks.parseVPNs(vpn)
    check(v.count == 1 && v[0].id == "vpn.Urban VPN Desktop,Work VPN", "VPN adları okunur")

    // Dinleyen portlar
    let ns = """
    tcp4       0      0  *.22                   *.*                    LISTEN
    tcp4       0      0  127.0.0.1.5900         *.*                    LISTEN
    tcp46      0      0  *.7000                 *.*                    LISTEN
    """
    let s = Checks.parseSharing(ns)
    check(s.contains { $0.id == "share.chk.share.ssh" }, "SSH (22) açık bulunur")
    check(!s.contains { $0.id == "share.chk.share.screen" }, "yalnızca 127.0.0.1'de dinleyen ekran paylaşımı sayılmaz")

    // Casus yazılım izin kombinasyonu
    let spy = Checks.spyware([("bundle:com.example.spy", "SpyApp", ["kTCCServiceScreenCapture", "kTCCServiceListenEvent"], nil),
                              ("bundle:com.example.ok", "Recorder", ["kTCCServiceScreenCapture"], nil)])
    check(spy.count == 1 && spy[0].id == "spy.bundle:com.example.spy", "ekran + klavye izleme birlikte uyarı, tek izin değil")

    // Safari uzantıları: uygulamaya göre gruplanır, sistem uzantıları sayılmaz
    let saf = """
         com.example.Ext.One(1.0)
    	            Path = /Applications/NoSuchApp.app/Contents/PlugIns/One.appex
    	   Parent Bundle = /Applications/NoSuchApp.app
    	     Parent Name = NoSuchApp

         com.example.Ext.Two(1.0)
    	            Path = /Applications/NoSuchApp.app/Contents/PlugIns/Two.appex
    	   Parent Bundle = /Applications/NoSuchApp.app
    	     Parent Name = NoSuchApp

         com.apple.Safari.Something(1.0)
    	   Parent Bundle = /System/Applications/Something.app
    """
    let sf = Checks.parseSafari(saf)
    check(sf.count == 1 && sf[0].id == "safari./Applications/NoSuchApp.app" && sf[0].verdict == .caution,
          "Safari: imzasız/olmayan uygulamanın uzantısı uyarı, sistem uzantısı yok sayılır")

    let sum = Checks.summarizeExtensions([Finding(id: "ext.summary.Safari", category: .browser, verdict: .info, title: "s", body: "")])
    check(sum.count == 1 && sum[0].id == "ext.summary.Safari", "hazır özet kartı ikinci kez özetlenmez")

    check(UpdateChecker.isNewer("v0.10.0", than: "0.9.3") && !UpdateChecker.isNewer("0.2.0", than: "0.2.0") && !UpdateChecker.isNewer("v0.1.9", than: "0.2"),
          "sürüm karşılaştırma")

    // Engelleme: yalnızca geçerli IP adresleri
    check(BlockList.host(of: "93.184.216.34:443") == "93.184.216.34" && BlockList.host(of: "[2001:db8::1]:443") == "2001:db8::1",
          "uç noktadan adres ayrılır")
    check(BlockList.isIP("203.0.113.5") && BlockList.isIP("2001:db8::1") && !BlockList.isIP("example.com")
          && !BlockList.isIP("1.2.3.4; rm -rf /") && !BlockList.isIP("1.2.3.4 } pass all"), "kural enjeksiyonu reddedilir")

    // VPN sızıntısı (sentetik: tünel utun4, fiziksel en0 = 192.0.2.10)
    func conn(_ name: String, _ local: String, _ remote: String) -> ConnRow {
        ConnRow(id: name + remote, pid: 1, name: name, path: nil, proto: "TCP", local: local, remote: remote, state: "ESTABLISHED",
                signature: "developer", rules: [], ruleArgs: [], risk: .normal)
    }
    let route = Checks.RouteState(tunnel: "utun4", physical: "en0", physicalIP: "192.0.2.10")
    let leak = Checks.vpnLeak([conn("Safari", "192.0.2.10:50000", "93.184.216.34:443"),        // sızıntı
                               conn("amneziawg-go", "192.0.2.10:51000", "185.193.125.59:40301"), // tünelin kendisi
                               conn("Mail", "100.101.145.127:50001", "17.1.2.3:993"),             // tünel içinden
                               conn("AirPlay", "192.0.2.10:7000", "192.168.1.20:7000")],          // yerel ağ
                              route: route)
    check(leak.contains { $0.id == "vpnleak.Safari" }, "tünel dışından bağlanan program sızıntı sayılır, VPN ve yerel ağ sayılmaz")
    check(Checks.vpnLeak([conn("Safari", "192.0.2.10:1", "93.184.216.34:443")], route: nil).isEmpty, "VPN kapalıyken sızıntı yok")

    // Tarayıcı politikası (deneme alanı) tespiti ve silinmesi
    let dom = "com.permwatch.selftest"
    Shell.run("/usr/bin/defaults", ["write", dom, "HomepageLocation", "http://search-redirect.invalid"])
    let pol = Checks.browserPolicies(domains: [dom])
    check(pol.contains { $0.id == "policy.user.\(dom).HomepageLocation" }, "zorla yazılmış ana sayfa politikası bulunur")
    Shell.run("/usr/bin/defaults", ["delete", dom, "HomepageLocation"])
    check(Checks.browserPolicies(domains: [dom]).isEmpty, "politika silinince bulgu kalkar")
    Shell.run("/usr/bin/defaults", ["delete", dom])

    // Başlangıç öğesini durdurup kaldırma (kullanıcı alanında zararsız deneme öğesi: /usr/bin/true)
    let label = "com.permwatch.selftest"
    let agents = NSHomeDirectory() + "/Library/LaunchAgents"
    let plist = agents + "/\(label).plist"
    let item: NSDictionary = ["Label": label, "ProgramArguments": ["/usr/bin/true"], "RunAtLoad": false]
    item.write(toFile: plist, atomically: true)
    _ = Shell.run("/bin/launchctl", ["bootstrap", "gui/\(getuid())", plist])
    if Shell.run("/bin/launchctl", ["print", "gui/\(getuid())/\(label)"]).0 == 0 {
        let r = Checks.disableLaunchItem(plist)
        check(r == L("fix.done"), "başlangıç öğesi kaldırma tamamlandı")
        check(!FileManager.default.fileExists(atPath: plist), "plist LaunchAgents'tan çıktı")
        check(Shell.run("/bin/launchctl", ["print", "gui/\(getuid())/\(label)"]).0 != 0, "öğe launchd'den kaldırıldı")
        let trashed = NSHomeDirectory() + "/.Trash/\(label).plist"
        check(FileManager.default.fileExists(atPath: trashed), "plist Çöp Sepeti'nde (geri alınabilir)")
        try? FileManager.default.removeItem(atPath: trashed)
    } else {
        print("– başlangıç öğesi testi atlandı (grafik oturum yok)")
        try? FileManager.default.removeItem(atPath: plist)
    }

    // Çöp Sepeti'ne taşıma
    try? FileManager.default.createDirectory(atPath: NSHomeDirectory() + "/Library/Application Support/permwatch", withIntermediateDirectories: true)
    let tmp = NSHomeDirectory() + "/Library/Application Support/permwatch/selftest-\(UUID().uuidString).txt"
    FileManager.default.createFile(atPath: tmp, contents: Data("x".utf8))
    var moved: NSURL?
    try? FileManager.default.trashItem(at: URL(fileURLWithPath: tmp), resultingItemURL: &moved)
    check(!FileManager.default.fileExists(atPath: tmp), "dosya Çöp Sepeti'ne taşındı")
    if let m = moved as URL? { try? FileManager.default.removeItem(at: m) }

    // YARA motoru + Apple imzaları: EICAR
    let eicar = FileManager.default.temporaryDirectory.appendingPathComponent("permwatch-eicar-\(UUID().uuidString).com")
    // Ters yazılı: test programının kendisi EICAR kuralına takılıp koruma servisince engellenmesin.
    try? Data(String("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X".reversed()).utf8).write(to: eicar)
    if FileManager.default.fileExists(atPath: YaraEngine.rulesDir + "/XProtect.yara") {
        check(YaraEngine.shared.load() == nil, "Apple XProtect kuralları derlendi (\(YaraEngine.shared.ruleCount))")
        check(YaraEngine.shared.scan(eicar.path)?.contains { $0.rule == "EICAR" } == true, "EICAR test dosyası yakalandı")
        check(Targets.isScannable(eicar.path), "EICAR ön elemeden geçer")
    } else {
        print("– XProtect kuralları yok, YARA testi atlandı")
    }
    try? FileManager.default.removeItem(at: eicar)

    // Elastic imzaları: hepsi derlenir; zararsız bir deneme dosyası Xmrig kuralına takılır.
    check(YaraEngine.shared.load(force: true) == nil && YaraEngine.shared.extraCount > 100,
          "Elastic macOS kuralları derlendi (\(YaraEngine.shared.extraCount))")
    let minerDir = NSHomeDirectory() + "/Library/Application Support/permwatch"
    try? FileManager.default.createDirectory(atPath: minerDir, withIntermediateDirectories: true)   // temiz makinede (CI) yok
    let miner = minerDir + "/selftest-miner-\(UUID().uuidString)"
    var body = Data([0xcf, 0xfa, 0xed, 0xfe])   // Mach-O başlığı (çalıştırılabilir değil)
    // Metinler ters yazılı: test programının kendisi kurala takılıp koruma servisince engellenmesin.
    let parts = ["tegrat_tes.gninim", "EMANTSOH_GIRMX", "]SNOITPO[ girmx :egasU", "NOISREV_GIRMX"].map { String($0.reversed()) }
    body.append(Data(("\0" + parts.joined(separator: "\0") + "\0").utf8))
    FileManager.default.createFile(atPath: miner, contents: body, attributes: [.posixPermissions: 0o755])
    let hit = YaraEngine.shared.scan(miner)?.first { $0.name == "MacOS.Cryptominer.Xmrig" }
    check(hit != nil, "Elastic kuralı deneme dosyasını yakaladı")

    // Karantina: taşınır, çalıştırılamaz, geri yüklenince izinleri geri gelir
    let qs = QuarantineStore.shared
    let failedQ = qs.quarantine(paths: [miner], launchItems: [], name: "MacOS.Cryptominer.Xmrig", rule: "test")
    let qi = qs.items.first { $0.files[miner] != nil }
    check(failedQ.isEmpty && qi != nil && !FileManager.default.fileExists(atPath: miner), "dosya karantinaya taşındı")
    if let qi, let stored = qi.files[miner] {
        check(!FileManager.default.isExecutableFile(atPath: stored), "karantinadaki dosya çalıştırılamaz")
        check(qs.restore(qi) == nil && FileManager.default.isExecutableFile(atPath: miner), "geri yüklendi, izinler geri geldi")
    }
    try? FileManager.default.removeItem(atPath: miner)

    // Zararlı sunucu listesi eşleştirmesi (üst alan adları dahil)
    ThreatIntel.store.set(domains: ["evil.example"], ips: ["203.0.113.66"])
    check(ThreatIntel.store.match(ip: "198.51.100.1", host: "cdn.a.evil.example")?.0 == "evil.example", "alt alan adı listedeki alan adına eşleşir")
    check(ThreatIntel.store.match(ip: "203.0.113.66", host: nil)?.1 == "Feodo Tracker", "listedeki IP eşleşir")
    check(ThreatIntel.store.match(ip: "198.51.100.1", host: "notevil.example") == nil, "benzer ama farklı alan adı eşleşmez")
    check(ThreatIntel.parseHosts("# yorum\n0.0.0.0 bad.example\n0.0.0.0 0.0.0.0\n") == ["bad.example"], "hosts listesi ayrıştırılır")
    check(ThreatIntel.parseIPs("# DstIP\r\n50.16.16.211\r\n# END\r\n") == ["50.16.16.211"], "Windows satır sonlu IP listesi ayrıştırılır")
    check(PathUtil.abbreviate("/Users/Shared/x") == "/Users/Shared/x", "paylaşılan klasör ~ olarak gösterilmez")
    ThreatIntel.store.set(domains: [], ips: [])

    // Fidye yazılımı belirtileri
    let rdir = FileManager.default.temporaryDirectory.appendingPathComponent("permwatch-ransom-\(UUID().uuidString)").path
    try? FileManager.default.createDirectory(atPath: rdir, withIntermediateDirectories: true)
    var rnd = Data(count: 4096); _ = rnd.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 4096, $0.baseAddress!) }
    FileManager.default.createFile(atPath: rdir + "/rapor.pdf", contents: rnd)
    FileManager.default.createFile(atPath: rdir + "/gercek.pdf", contents: Data(("%PDF-1.7\n" + String(repeating: "metin ", count: 400)).utf8))
    FileManager.default.createFile(atPath: rdir + "/notlar.txt", contents: rnd)
    FileManager.default.createFile(atPath: rdir + "/tez.docx.locked", contents: rnd)
    FileManager.default.createFile(atPath: rdir + "/film.mp4.part", contents: rnd)
    check(RansomDetector.suspicious(path: rdir + "/rapor.pdf", renamed: false), "rastgele baytlı .pdf şüpheli")
    check(!RansomDetector.suspicious(path: rdir + "/gercek.pdf", renamed: false), "gerçek .pdf şüpheli değil")
    check(RansomDetector.suspicious(path: rdir + "/notlar.txt", renamed: false), "rastgele baytlı .txt şüpheli")
    check(RansomDetector.suspicious(path: rdir + "/tez.docx.locked", renamed: true), "rapor.docx → .locked şüpheli")
    check(!RansomDetector.suspicious(path: rdir + "/film.mp4.part", renamed: true), "yarım indirme (.part) şüpheli değil")
    try? FileManager.default.removeItem(atPath: rdir)

    // "Bize bildir": gerekli bilgiler var, kişisel bilgiler yok
    let report = ProblemReport.diagnostics(hw: ProblemReport.hardware(), posture: SecurityPosture.evaluate())
    print(report.split(separator: "\n").map { "    | " + $0 }.joined(separator: "\n"))
    check(["Version:", "Model:", "Chip:", "macOS:", "Memory:", "Full Disk Access:", "Real-time:", "Signatures:"].allSatisfy(report.contains),
          "rapor sürüm, model, çip, macOS ve koruma durumunu içeriyor")
    let host = ProcessInfo.processInfo.hostName.components(separatedBy: ".").first ?? "-"
    check(!report.contains(NSUserName()) && !report.contains(NSHomeDirectory()) && !report.localizedCaseInsensitiveContains(host)
          && !report.contains("Serial"), "raporda kullanıcı adı, ev klasörü, bilgisayar adı ve seri numarası yok")

    // Çökme raporları: yalnızca permwatch'ın kendi raporları; özet kişisel bilgi içermez
    check(CrashReports.isOurs("permwatch-2026-11-09-101500.ips") && !CrashReports.isOurs("permwatch-crashtest-2026-11-09-101500.ips")
          && !CrashReports.isOurs("permwatch-root-2026-11-09-101500.ips") && !CrashReports.isOurs("Safari-2026-11-09-101500.ips"),
          "çökme raporu adları doğru seçiliyor")
    let crashDir = NSHomeDirectory() + "/Library/Logs/DiagnosticReports"
    if let f = ((try? FileManager.default.contentsOfDirectory(atPath: crashDir)) ?? []).filter({ $0.hasPrefix("permwatch-crashtest-") && $0.hasSuffix(".ips") }).sorted().last,
       let sum = CrashReports.summary(URL(fileURLWithPath: crashDir + "/" + f)) {
        print(sum.split(separator: "\n").prefix(8).map { "    | " + $0 }.joined(separator: "\n"))
        check(sum.contains("Exception:") && sum.contains("Crashed thread"), "çökme özeti hata türünü ve çöken çağrıları içeriyor")
        check(!sum.contains(NSUserName()) && !sum.contains(NSHomeDirectory()), "çökme özetinde kullanıcı adı ve ev klasörü yok")
    } else {
        print("– gerçek çökme raporu yok, özet testi atlandı")
    }

    // Dolandırıcılık Kalkanı: oturum tespiti
    do {
        var det = SessionDetector()
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        func at(_ s: Double) -> Date { t0.addingTimeInterval(s) }
        func any(_ bytes: Int64) -> [RemoteObservation] { [RemoteObservation(pid: 4242, name: "AnyDesk", path: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk", kind: .tool, bytes: bytes)] }
        // Boşta: 3 sn'de ~600 bayt (sunucuya bağlı bekleme)
        var b: Int64 = 10_000
        var idleSessions = 0
        for i in 0..<6 { b += 600; idleSessions += det.update(any(b), now: at(Double(i) * 3)).count }
        check(idleSessions == 0, "boşta bekleyen AnyDesk uyarı vermez")
        // Ekran akışı: 3 sn'de 450 KB (150 KB/sn)
        b += 450_000; let first = det.update(any(b), now: at(18)).count
        b += 450_000; let second = det.update(any(b), now: at(21))
        check(first == 0 && second.count == 1 && second[0].name == "AnyDesk", "ekran akışı iki yoklamada oturum sayılır")
        // Akış durur: 20 sn'den uzun sessizlik → oturum biter
        var after = second
        for i in 1...9 { b += 300; after = det.update(any(b), now: at(21 + Double(i) * 3)) }
        check(after.isEmpty, "uzun sessizlikten sonra oturum biter")
        // Süreç kapanınca hemen biter
        b += 450_000; _ = det.update(any(b), now: at(60)); b += 450_000; _ = det.update(any(b), now: at(63))
        check(det.update([], now: at(66)).isEmpty, "program kapanınca oturum biter")
        // Ekran Paylaşımı ve SSH
        var d2 = SessionDetector()
        _ = d2.update([RemoteObservation(pid: 7, name: "Screen Sharing", path: nil, kind: .screenSharing, bytes: 0)], now: at(0))
        let ss = d2.update([RemoteObservation(pid: 7, name: "Screen Sharing", path: nil, kind: .screenSharing, bytes: 200_000)], now: at(3))
        check(ss.count == 1, "Ekran Paylaşımı trafiği oturum sayılır")
        var d3 = SessionDetector()
        check(d3.update([RemoteObservation(pid: 9, name: "SSH", path: nil, kind: .ssh, bytes: -1)], now: at(0)).count == 1, "SSH oturumu hemen sayılır")
    }
    check(ShareGuard.classify(path: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk", name: "AnyDesk")?.name == "AnyDesk"
          && ShareGuard.classify(path: "/Applications/ToDesk.app/Contents/MacOS/ToDesk_Service", name: "ToDesk_Service")?.name == "ToDesk"
          && ShareGuard.classify(path: "/Applications/Autodesk Fusion.app/Contents/MacOS/Autodesk Fusion", name: "Autodesk Fusion") == nil
          && ShareGuard.classify(path: nil, name: "screensharingd")?.kind == .screenSharing
          && ShareGuard.classify(path: "/usr/bin/ssh", name: "ssh") == nil,
          "uzaktan erişim süreçleri doğru tanınır (Autodesk karışmaz)")
    check(SensitiveSites.match("online.isbank.com.tr") == "isbank.com.tr" && SensitiveSites.match("www.garantibbva.com.tr") == "garantibbva.com.tr"
          && SensitiveSites.match("notisbank.com.tr") == nil && SensitiveSites.match("www.google.com") == nil
          && SensitiveSites.match("online.sberbank.ru") == "online.sberbank.ru",
          "banka alan adları (alt alan adlarıyla) eşleşir, benzerleri eşleşmez")

    do {
        // Gerçek replayd satırları (macOS 26, screencapture -V ile)
        var p = CaptureLogParser()
        p.feed("-[RPConnectionManager processNewConnection:]:197 accepted client connection PID: 439")
        p.feed("-[RPClient initWithConnection:clientProxy:bundleIdentifier:]:125 0x97ec99040")
        check(p.activePIDs.isEmpty, "bağlanmak paylaşım sayılmaz")
        p.feed("-[RPClient captureSessionDidChange:withScreenAspectRatio:]:2024 client=0x97ec99040 captureSession=0x97e784000 aspectRatio=1.600000")
        check(p.activePIDs == [439] && p.startedAt[439] != nil, "paylaşım başlayınca süreç bulunur")
        p.feed("-[RPConnectionManager stop:transactionID:streamData:withCompletionHandler:]:1012")
        check(p.activePIDs == [439], "yöneticinin stop satırı paylaşımı bitirmez")
        p.feed("-[RPClient stop:transactionID:streamData:withCompletionHandler:]:1432 stream=0x97e784000 streamID=<private>")
        check(p.activePIDs.isEmpty && p.startedAt.isEmpty, "stop ile paylaşım biter")
        // İstemci ayrılınca bütün paylaşımları biter; ölü süreç unutulur
        p.feed("accepted client connection PID: 500")
        p.feed("-[RPClient initWithConnection:clientProxy:bundleIdentifier:]:125 0xabc1")
        p.feed("-[RPClient captureSessionDidChange:withScreenAspectRatio:]:2024 client=0xabc1 captureSession=0xdef1 aspectRatio=1.6")
        p.feed("-[RPClient invalidate]:167 0xabc1")
        check(p.activePIDs.isEmpty, "istemci ayrılınca paylaşım biter")
        p.feed("accepted client connection PID: 501")
        p.feed("-[RPClient initWithConnection:clientProxy:bundleIdentifier:]:125 0xabc2")
        p.feed("-[RPClient captureSessionDidChange:withScreenAspectRatio:]:2024 client=0xabc2 captureSession=0xdef2 aspectRatio=1.6")
        p.forget { $0 == 501 }
        check(p.activePIDs.isEmpty, "kapanan süreç unutulur")
        check(ShareGuard.outermostApp("/Applications/Google Chrome.app/Contents/Frameworks/x.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper") == "/Applications/Google Chrome.app",
              "yardımcı süreç ana uygulamaya bağlanır")
    }

    do {
        let none: (String) -> String? = { _ in nil }
        let fakes = ["garantibbva-giris.com", "akbankgiris.com", "isbank.com.tr.hesap-onay.xyz", "paypa1.com", "garantibbvva.com",
                     "yapikerdi.com.tr", "applesupport-id.com", "edevlet-odeme.net", "ziraatbankasi-musteri.online", "binance-wallet.top",
                     "secure-paypal.info", "netfIix.com", "rnicrosoft.com"]
        let real = ["online.isbank.com.tr", "www.garantibbva.com.tr", "appleid.apple.com", "www.google.com", "accounts.google.com",
                    "amazon.co.uk", "www.amazon.de", "login.microsoftonline.com", "www.paypal.com", "github.com", "www.appleinsider.com",
                    "pineapple.com", "revolt.chat", "finance.com", "www.reddit.com", "eksisozluk.com", "www.hurriyet.com.tr",
                    "zoom.us", "discord.com", "www.akbanksanat.com", "giris.turkiye.gov.tr", "signin.aws.amazon.com", "amazonaws.com",
                    "www.ing.com.tr", "notion.so", "www.figma.com", "slack.com", "medium.com", "web.whatsapp.com", "www.n11.com"]
        let missed = fakes.filter { Phish.verdict($0, listed: none) == nil }
        let wrong = real.filter { Phish.verdict($0, listed: none) != nil }
        check(missed.isEmpty, "sahte siteler yakalanır \(missed)")
        check(wrong.isEmpty, "gerçek siteler uyarı vermez \(wrong)")
        check(Phish.verdict("tamamen-baska.xyz", listed: { _ in "OpenPhish" }) == .listed("OpenPhish"), "listedeki site yakalanır")
        // İsteğe bağlı ölçüm: PERMWATCH_PHISH_EVAL=<klasör> (top10k.txt ve phish3k.txt)
        if let dir = ProcessInfo.processInfo.environment["PERMWATCH_PHISH_EVAL"] {
            let top = ((try? String(contentsOfFile: dir + "/top10k.txt", encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
            let ph = ((try? String(contentsOfFile: dir + "/phish3k.txt", encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
            let fp = top.filter { Phish.verdict($0, listed: none) != nil }
            let caught = ph.filter { Phish.verdict($0, listed: none) != nil }
            print("ÖLÇÜM yanlış alarm: \(fp.count)/\(top.count) → \(fp.map { "\($0)=\(Phish.verdict($0, listed: none)!)" })")
            print("ÖLÇÜM liste olmadan yakalanan sahte: \(caught.count)/\(ph.count)")
        }
    }

    do {
        let arpText = """
        ? (192.168.1.1) at 0:11:22:33:44:5 on en0 ifscope [ethernet]
        ? (192.168.1.23) at 0:11:22:33:44:5 on en0 ifscope [ethernet]
        ? (192.168.1.40) at a2:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        ? (192.168.1.50) at 46:1c:14:4c:d4:c on en0 ifscope permanent [ethernet]
        ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
        ? (10.0.0.1) at 0:aa:bb:cc:dd:ee on en5 ifscope [ethernet]
        """
        let arp = NetCheck.parseARP(arpText, iface: "en0")
        check(arp.count == 3 && arp[0].mac == "00:11:22:33:44:05", "ARP tablosu okunur (kendi adresi, çok noktaya yayın ve başka arayüz hariç)")
        check(NetCheck.gatewayIssues(gateway: "192.168.1.1", arp: arp) == [.arpSpoof("192.168.1.23")], "yönlendiriciyi taklit eden cihaz bulunur")
        check(NetCheck.gatewayIssues(gateway: "192.168.1.1", arp: Array(arp.dropFirst(1).dropFirst(1)) + [arp[0]]).isEmpty, "taklit yoksa sorun yok")
        check(LanDevice(ip: "1", mac: "a2:bb:cc:dd:ee:ff", isGateway: false, isNew: false).privateMAC
              && !LanDevice(ip: "1", mac: "00:11:22:33:44:05", isGateway: false, isNew: false).privateMAC, "gizli donanım adresi tanınır")
    }

    print(failures == 0 ? "\nTüm bütünleşik testler geçti." : "\n\(failures) bütünleşik test başarısız.")
    exit(failures == 0 ? 0 : 1)
} }
