import Foundation

/// Elle güvenilen kök sertifikalar ve yapılandırma profilleri değiştiği anda uyarır. Bunlar sessizce
/// eklenirse şifreli trafik okunabilir ya da Mac uzaktan yönetilebilir; bu yüzden "Mac'imi Kontrol Et"i
/// beklemeden dakikada bir bakılır. İlk çalıştırmada mevcut olanlar sessizce "bilinen" sayılır.
@MainActor
final class TrustWatch {
    static let shared = TrustWatch()
    private let key = "trustWatchBaseline"
    private var timer: Timer?
    private var busy = false

    private init() {
        guard Snapshot.section == nil else { return }
        check()
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in
            MainActor.assumeIsolated { TrustWatch.shared.check() }
        }
    }

    func check() {
        guard !busy else { return }
        busy = true
        let root = RootBridge.shared.active ? RootBridge.shared.data?.profiles : nil
        Task.detached(priority: .utility) {
            let found = Checks.trustedCerts() + Checks.profiles(rootOutput: root)
            await MainActor.run { self.busy = false; self.compare(found) }
        }
    }

    private func compare(_ found: [Finding]) {
        let ids = Set(found.map(\.id))
        guard let old = UserDefaults.standard.stringArray(forKey: key).map(Set.init) else {
            UserDefaults.standard.set(Array(ids), forKey: key)   // ilk çalıştırma: temel durum
            return
        }
        for f in found where !old.contains(f.id) {
            var t = Threat(id: "trustwatch.\(f.id)", risk: f.verdict == .danger ? .high : .caution,
                           title: f.category == .mitm ? L("tw.newCert") : L("tw.newProfile"),
                           detail: f.title, iconKey: nil, section: .security, focus: .none)
            if let fix = f.fixes.first {
                switch fix.1 {
                case .untrustCert(let name, let admin):
                    t.actions = [ThreatAction(title: fix.0, prominent: true) {
                        DispatchQueue.global().async { _ = Checks.untrust(name: name, admin: admin) }
                    }]
                case .removeProfile(let id):
                    t.actions = [ThreatAction(title: fix.0, prominent: true) {
                        DispatchQueue.global().async { _ = Checks.admin("/usr/bin/profiles remove -identifier \(Checks.q(id))") }
                    }]
                default: break
                }
            }
            ThreatCenter.shared.report(t)
        }
        if ids != old { UserDefaults.standard.set(Array(ids), forKey: key) }
    }
}
