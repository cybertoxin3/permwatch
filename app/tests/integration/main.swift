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
    let tmp = NSHomeDirectory() + "/Library/Application Support/permwatch/selftest-\(UUID().uuidString).txt"
    FileManager.default.createFile(atPath: tmp, contents: Data("x".utf8))
    var moved: NSURL?
    try? FileManager.default.trashItem(at: URL(fileURLWithPath: tmp), resultingItemURL: &moved)
    check(!FileManager.default.fileExists(atPath: tmp), "dosya Çöp Sepeti'ne taşındı")
    if let m = moved as URL? { try? FileManager.default.removeItem(at: m) }

    // YARA motoru + Apple imzaları: EICAR
    let eicar = FileManager.default.temporaryDirectory.appendingPathComponent("permwatch-eicar-\(UUID().uuidString).com")
    try? Data("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".utf8).write(to: eicar)
    if FileManager.default.fileExists(atPath: YaraEngine.rulesDir + "/XProtect.yara") {
        check(YaraEngine.shared.load() == nil, "Apple XProtect kuralları derlendi (\(YaraEngine.shared.ruleCount))")
        check(YaraEngine.shared.scan(eicar.path)?.contains { $0.rule == "EICAR" } == true, "EICAR test dosyası yakalandı")
        check(Targets.isScannable(eicar.path), "EICAR ön elemeden geçer")
    } else {
        print("– XProtect kuralları yok, YARA testi atlandı")
    }
    try? FileManager.default.removeItem(at: eicar)

    print(failures == 0 ? "\nTüm bütünleşik testler geçti." : "\n\(failures) bütünleşik test başarısız.")
    exit(failures == 0 ? 0 : 1)
} }
