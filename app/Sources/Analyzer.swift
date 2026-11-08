import Foundation
import SwiftUI

enum Risk: Int, Comparable {
    case normal, caution, high
    static func < (a: Risk, b: Risk) -> Bool { a.rawValue < b.rawValue }

    var label: String {
        switch self {
        case .normal: return L("risk.normal")
        case .caution: return L("risk.caution")
        case .high: return L("risk.high")
        }
    }

    var color: Color {
        switch self {
        case .normal: return .green
        case .caution: return .orange
        case .high: return .red
        }
    }
}

enum Kind { case exec, btmAdd, btmRemove, quarantine, gatekeeper, tcc }

enum Rule: String {
    case unsignedPersistence, unsignedStartupBinary, startupWeakSignature, rapidGrants,
         shellSuspicious, cronJob, authPlugin, loginHook, profileInstalled, hiddenTarget, nightHidden, tccUnsigned, tccAdhoc,
         quarantine, unsignedDownload, dyld, gatekeeper, lolbinFromUnsigned

    var risk: Risk {
        switch self {
        case .unsignedPersistence, .unsignedStartupBinary, .rapidGrants, .shellSuspicious, .hiddenTarget, .nightHidden, .tccUnsigned, .dyld: return .high
        case .tccAdhoc, .startupWeakSignature, .cronJob, .authPlugin, .loginHook, .profileInstalled, .quarantine, .unsignedDownload, .gatekeeper, .lolbinFromUnsigned: return .caution
        }
    }

    var text: String { L("rule.\(rawValue)") }
}

struct Field: Identifiable {
    let id = UUID()
    let label: String
    let value: String
    var mono = false
    var warn = false
}

enum Category: Hashable {
    case micCamera, screen, accessibility, fullDisk
    var services: Set<String> {
        switch self {
        case .micCamera: return ["kTCCServiceMicrophone", "kTCCServiceCamera"]
        case .screen: return ["kTCCServiceScreenCapture"]
        case .accessibility: return ["kTCCServiceAccessibility"]
        case .fullDisk: return ["kTCCServiceSystemPolicyAllFiles"]
        }
    }
}

struct Item: Identifiable, Hashable {
    let id: Int
    let date: Date
    let kind: Kind
    let appKey: String
    let appName: String
    let title: String
    let subtitle: String
    let rules: [Rule]
    let risk: Risk
    let trusted: Bool
    let rawType: String
    let fields: [Field]
    let tccService: String?
    let revealPath: String?
    let removablePlist: String?

    static func == (a: Item, b: Item) -> Bool { a.id == b.id && a.risk == b.risk && a.trusted == b.trusted }
    func hash(into h: inout Hasher) { h.combine(id) }

    var alertHeader: String {
        switch kind {
        case .btmAdd, .btmRemove: return L("alert.persistence")
        case .tcc: return L("alert.permission")
        case .exec: return L("alert.execution")
        case .quarantine, .gatekeeper: return L("alert.evasion")
        }
    }
}

struct AppSummary: Identifiable {
    var id: String { key }
    let key: String
    let name: String
    let signatureText: String?
    let location: String?
    let firstSeen: Date
    let lastSeen: Date
    let risk: Risk
    let trusted: Bool
    let services: [String]       // şu an izinli olan TCC servisleri
    let loginItem: String?       // varsa öğe türü etiketi
    let quarantineRemoved: Bool
    let grantedVia: String?
    let buckets: [(level: Double, high: Bool)]
}

// MARK: - Yardımcılar

enum PathUtil {
    /// Homebrew ile kurulmuş bir paketin programıysa paket adı. Homebrew programları çoğunlukla
    /// geçici (ad-hoc) imzalıdır; bu yüzden imzasız sayılıp yanlış alarm üretmesinler. Kurulum kaydı
    /// (INSTALL_RECEIPT.json) aranır; risk tamamen kaldırılmaz, yalnızca düşürülür.
    static func homebrewFormula(_ path: String?) -> String? {
        guard let path else { return nil }
        let real = (path as NSString).resolvingSymlinksInPath
        for cellar in ["/opt/homebrew/Cellar/", "/usr/local/Cellar/", "/home/linuxbrew/.linuxbrew/Cellar/"] where real.hasPrefix(cellar) {
            let parts = real.dropFirst(cellar.count).split(separator: "/")
            guard parts.count >= 2 else { return nil }
            let receipt = cellar + parts[0] + "/" + parts[1] + "/INSTALL_RECEIPT.json"
            return FileManager.default.fileExists(atPath: receipt) ? String(parts[0]) : nil
        }
        return nil
    }

    /// /Users/<ad>/x → ~/x
    static func abbreviate(_ p: String) -> String {
        var s = p
        if s.hasPrefix("file://"), let u = URL(string: s) { s = u.path }
        if s.hasPrefix("/Users/") {
            let rest = s.dropFirst("/Users/".count)
            if let slash = rest.firstIndex(of: "/") { return "~" + rest[slash...] }
            return "~"
        }
        return s
    }

    static func fromURL(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        if s.hasPrefix("file://"), let u = URL(string: s) { return u.path }
        return s
    }

    /// .../Foo.app/Contents/MacOS/Foo → .../Foo.app
    static func appBundle(_ p: String) -> String? {
        if let r = p.range(of: ".app/") { return String(p[..<r.lowerBound]) + ".app" }
        if p.hasSuffix(".app") { return p }
        if p.hasSuffix(".app/") { return String(p.dropLast()) }
        return nil
    }

    static func displayName(_ p: String) -> String {
        let last = (p as NSString).lastPathComponent
        return last.hasSuffix(".app") ? String(last.dropLast(4)) : last
    }

    static func isHidden(_ p: String) -> Bool {
        p.split(separator: "/").contains { $0.hasPrefix(".") && $0 != "." && $0 != ".." }
    }

    static func parentDir(_ p: String) -> String { (p as NSString).deletingLastPathComponent }
}

enum Text10n {
    static func service(_ s: String) -> String {
        let map = [
            "kTCCServiceMicrophone": "svc.microphone", "kTCCServiceCamera": "svc.camera",
            "kTCCServiceScreenCapture": "svc.screen", "kTCCServiceAccessibility": "svc.accessibility",
            "kTCCServiceSystemPolicyAllFiles": "svc.fullDisk", "kTCCServiceSystemPolicyDocumentsFolder": "svc.documents",
            "kTCCServiceSystemPolicyDesktopFolder": "svc.desktop", "kTCCServiceSystemPolicyDownloadsFolder": "svc.downloads",
            "kTCCServiceAppleEvents": "svc.automation", "kTCCServiceListenEvent": "svc.inputMonitoring",
            "kTCCServicePostEvent": "svc.accessibility", "kTCCServiceAddressBook": "svc.contacts",
            "kTCCServicePhotos": "svc.photos", "kTCCServicePhotosAdd": "svc.photos",
            "kTCCServiceBluetoothAlways": "svc.bluetooth", "kTCCServiceDeveloperTool": "svc.developerTools",
            "kTCCServiceFileProviderDomain": "svc.fileProvider", "kTCCServiceFocusStatus": "svc.focus",
            "kTCCServiceMediaLibrary": "svc.mediaLibrary", "kTCCServiceReminders": "svc.reminders",
            "kTCCServiceCalendar": "svc.calendar", "kTCCServiceSpeechRecognition": "svc.speech",
            "kTCCServiceSystemPolicyAppBundles": "svc.appManagement", "kTCCServiceSystemPolicyAppData": "svc.appData",
            "kTCCServiceSystemPolicyNetworkVolumes": "svc.networkVolumes",
            "kTCCServiceSystemPolicyRemovableVolumes": "svc.removableVolumes",
            "kTCCServiceUbiquity": "svc.icloud", "kTCCServiceLiverpool": "svc.icloud",
            "kTCCServiceWebBrowserPublicKeyCredential": "svc.passkeys",
        ]
        if let k = map[s] { return L(k) }
        return s.replacingOccurrences(of: "kTCCService", with: "")
    }

    static func reason(_ r: String?) -> String {
        switch r {
        case "user_consent": return L("reason.userConsent")
        case "user_set": return L("reason.userSet")
        case "system_set": return L("reason.systemSet")
        case "mdm_policy": return L("reason.mdm")
        case "service_policy", "service_override_policy", "app_type_policy": return L("reason.servicePolicy")
        case "entitled": return L("reason.entitled")
        case let x?: return x
        case nil: return "—"
        }
    }

    static func btmType(_ t: String) -> String {
        switch t {
        case "agent": return L("btm.agent")
        case "daemon": return L("btm.daemon")
        case "cron", "shell", "browserExt", "sysExt", "authPlugin", "kext", "loginHook", "btmItem", "profile":
            return L("btm.\(t)")
        default: return L("btm.loginItem")
        }
    }

    static func signature(_ sig: String?, team: String?, org: String? = nil) -> String? {
        switch sig {
        case "unsigned": return L("sig.unsigned")
        case "adhoc": return L("sig.adhoc")
        case "unreadable": return L("sig.unreadable")
        case "apple": return L("sig.apple")
        case "developer":
            if let org, let team { return "\(org) (\(team))" }
            return L("sig.developer", team ?? "?")
        default: return nil
        }
    }

    static func settingsURL(service: String) -> URL? {
        let pane: String
        switch service {
        case "kTCCServiceScreenCapture": pane = "Privacy_ScreenCapture"
        case "kTCCServiceAccessibility", "kTCCServicePostEvent": pane = "Privacy_Accessibility"
        case "kTCCServiceMicrophone": pane = "Privacy_Microphone"
        case "kTCCServiceCamera": pane = "Privacy_Camera"
        case "kTCCServiceSystemPolicyAllFiles": pane = "Privacy_AllFiles"
        case "kTCCServiceListenEvent": pane = "Privacy_ListenEvent"
        case "kTCCServiceAppleEvents": pane = "Privacy_Automation"
        default: pane = "Privacy"
        }
        return URL(string: "x-apple.systempreferences:com.apple.preference.security?\(pane)")
    }
}

// MARK: - Analiz

struct Analysis {
    var items: [Item] = []
    var apps: [AppSummary] = []
}

enum Analyzer {
    private struct AppState {
        var name: String
        var sig: String?
        var team: String?
        var org: String?
        var location: String?
        var first: Date
        var last: Date
        var itemIDs: [Int] = []
        var grants: [String: Date] = [:]     // servis → izin zamanı
        var allowed: [String: Bool] = [:]
        var grantedVia: String?
        var loginItem: String?
        var quarantineRemoved = false
        var hasTCCorBTM = false
    }

    static func run(_ events: [RawEvent], trusted: Set<String>) -> Analysis {
        let sorted = events.enumerated().sorted { $0.element.ts < $1.element.ts }
        var apps: [String: AppState] = [:]
        var helperOwner: [String: String] = [:]   // BTM executable → uygulama anahtarı
        var bundleKey: [String: String] = [:]     // signing_id → uygulama anahtarı
        var seenExec = Set<String>()
        let extraTypes: Set<String> = ["cron", "shell", "browserExt", "sysExt", "authPlugin", "kext", "loginHook",
                                       "btmItem", "profile"]
        var usedIDs = Set<Int>()
        var quarantined: [String] = []           // karantinası silinen yollar
        var items: [Item] = []
        let cal = Calendar.current

        func touch(_ key: String, name: String, date: Date) {
            if apps[key] == nil { apps[key] = AppState(name: name, first: date, last: date) }
            apps[key]!.last = max(apps[key]!.last, date)
        }

        func keyFor(path: String) -> String {
            if let owner = helperOwner[path] { return owner }
            return PathUtil.appBundle(path) ?? path
        }

        func setSig(_ key: String, _ p: ProcInfo?) {
            guard let p, let s = p.signature else { return }
            apps[key]?.sig = s
            if let t = p.team_id { apps[key]?.team = t }
            if apps[key]?.location == nil, let path = p.path {
                apps[key]?.location = PathUtil.appBundle(path) ?? path
            }
            if s == "developer", let path = p.path, let info = Signing.info(path: PathUtil.appBundle(path) ?? path) {
                apps[key]?.org = info.organization
            }
        }

        func sigText(_ key: String) -> String? {
            guard let a = apps[key] else { return nil }
            return Text10n.signature(a.sig, team: a.team, org: a.org)
        }

        func procName(_ p: ProcInfo?) -> String {
            guard let path = p?.path else { return p?.pid.map { "pid \($0)" } ?? "—" }
            return PathUtil.displayName(PathUtil.appBundle(path) ?? path)
        }

        for (idx, e) in sorted {
            let d = e.date
            var kind: Kind
            var key: String
            var name: String
            var title: String
            var sub: [String] = []
            var rules: [Rule] = []
            var fields: [Field] = []
            var tccService: String?
            var reveal: String?
            var plist: String?

            switch e.event {
            case "exec":
                kind = .exec
                let t = e.target?.process
                let path = t?.path ?? "?"
                let parentSig = e.process?.signature
                let tool = t?.signature == "apple" && parentSig != nil && parentSig != "apple"
                // Apple aracı, Apple olmayan bir uygulama tarafından çalıştırıldıysa olayı o uygulamaya bağla.
                if tool, let pp = e.process?.path {
                    key = keyFor(path: pp)
                    touch(key, name: PathUtil.displayName(key), date: d)
                    setSig(key, e.process)
                } else {
                    key = keyFor(path: path)
                    touch(key, name: PathUtil.displayName(key), date: d)
                    setSig(key, t)
                    if let sid = t?.signing_id { bundleKey[sid] = key }
                }
                name = apps[key]!.name
                let first = !seenExec.contains(path)
                seenExec.insert(path)
                let exeName = PathUtil.displayName(PathUtil.appBundle(path) ?? path)
                title = (first && t?.signature != "apple") ? L("ev.exec.first", exeName) : L("ev.exec", exeName)

                let unsigned = t?.signature == "unsigned" || t?.signature == "adhoc"
                if !(e.dyld_env ?? []).isEmpty { rules.append(.dyld) }
                if unsigned && first && path.contains("/Downloads/") { rules.append(.unsignedDownload) }
                if PathUtil.isHidden(path) && cal.component(.hour, from: d) < 5 { rules.append(.nightHidden) }
                if e.lolbin == true && (parentSig == "unsigned" || parentSig == "adhoc") { rules.append(.lolbinFromUnsigned) }

                sub.append(PathUtil.abbreviate(PathUtil.appBundle(path) ?? path))
                if !tool, let s = Text10n.signature(t?.signature, team: t?.team_id) { sub.append(s) }
                if first, quarantined.contains(where: { path.hasPrefix($0) }) { sub.append(L("sub.quarantineRemoved")) }
                if tool || e.process?.ppid == 1 || e.process?.pid == 1 {
                    sub.append(L("sub.launchedBy", e.process?.pid == 1 ? "launchd" : procName(e.process)))
                }

                fields.append(Field(label: L("field.path"), value: PathUtil.abbreviate(path), mono: true))
                if let argv = e.argv, argv.count > 1 {
                    fields.append(Field(label: L("field.arguments"), value: argv.dropFirst().joined(separator: " "), mono: true))
                }
                fields.append(Field(label: L("field.parent"), value: "\(procName(e.process)) (pid \(e.process?.pid ?? 0))", mono: true))
                fields.append(Field(label: L("field.signature"), value: Text10n.signature(t?.signature, team: t?.team_id) ?? "—", mono: true, warn: unsigned))
                if let env = e.dyld_env, !env.isEmpty {
                    fields.append(Field(label: "DYLD", value: env.joined(separator: "\n"), mono: true, warn: true))
                }
                if let c = t?.cdhash { fields.append(Field(label: "cdhash", value: c, mono: true)) }
                reveal = path

            case "btm_launch_item_add" where extraTypes.contains(e.item?.type ?? ""),
                 "btm_launch_item_remove" where extraTypes.contains(e.item?.type ?? ""):
                // Genişletilmiş kalıcılık: cron, kabuk dosyası, tarayıcı/sistem/kernel uzantısı, eklenti, login hook
                let add = e.event == "btm_launch_item_add"
                kind = add ? .btmAdd : .btmRemove
                let type = e.item?.type ?? ""
                let loc = PathUtil.fromURL(e.item?.url)
                key = loc ?? e.executable_path ?? (e.label ?? type)
                let label = e.label ?? PathUtil.displayName(key)
                touch(key, name: label, date: d)
                name = label
                let typeText = Text10n.btmType(type)
                title = add ? L("ev.persist", typeText, label) : "\(L("ev.btm.remove")) · \(label)"
                rules = (e.note ?? "").split(separator: ",").compactMap { Rule(rawValue: String($0)) }
                let owner = e.instigator
                if add, let sig = owner?.signature {
                    let brew = PathUtil.homebrewFormula(owner?.path ?? e.executable_path) != nil
                    if sig == "unsigned" && owner?.script != true { rules.append(brew ? .startupWeakSignature : .unsignedStartupBinary) }
                    else if (sig == "adhoc" && !brew) || owner?.script == true { rules.append(.startupWeakSignature) }
                    // Apple'a ait yetkilendirme eklentisi şüpheli değildir.
                    if sig == "apple" { rules.removeAll { $0 == .authPlugin } }
                }
                if let l = loc { sub.append(PathUtil.abbreviate(l)) }
                if let x = e.executable_path, x != loc { sub.append(PathUtil.abbreviate(x)) }
                fields.append(Field(label: L("field.itemType"), value: typeText))
                if let l = loc { fields.append(Field(label: L("field.path"), value: PathUtil.abbreviate(l), mono: true)) }
                if let x = e.executable_path {
                    fields.append(Field(label: L("field.executes"), value: x, mono: true,
                                        warn: rules.contains(.shellSuspicious)))
                }
                if let o = owner {
                    fields.append(Field(label: L("field.signature"),
                                        value: o.script == true ? L("sig.script") : (Text10n.signature(o.signature, team: o.team_id) ?? "—"),
                                        mono: true, warn: o.signature == "unsigned"))
                }
                reveal = loc

            case "btm_launch_item_add", "btm_launch_item_remove":
                let add = e.event == "btm_launch_item_add"
                kind = add ? .btmAdd : .btmRemove
                let it = e.item
                let owner = e.instigator ?? e.app
                let appPath = PathUtil.fromURL(it?.app_url) ?? owner?.path
                key = appPath.map { keyFor(path: $0) } ?? (PathUtil.fromURL(it?.url) ?? "?")
                touch(key, name: PathUtil.displayName(key), date: d)
                setSig(key, owner)
                apps[key]!.hasTCCorBTM = true
                name = apps[key]!.name
                let typeText = Text10n.btmType(it?.type ?? "")
                if add {
                    apps[key]!.loginItem = (it?.type == "agent" || it?.type == "daemon") ? typeText : L("btm.loginItem")
                    if let exe = e.executable_path { helperOwner[exe] = key }
                    switch it?.type {
                    case "agent": title = L("ev.btm.agent")
                    case "daemon": title = L("ev.btm.daemon")
                    default: title = L("ev.btm.login", name)
                    }
                } else {
                    apps[key]!.loginItem = nil
                    title = L("ev.btm.remove")
                }
                let ownerSig = owner?.signature
                let ownerUnsigned = ownerSig == "unsigned" || ownerSig == "adhoc"
                let scanned = e.origin == "scan"
                if add {
                    if scanned {
                        // Tarama öğeyi kimin eklediğini bilemez; yalnızca neyi çalıştırdığını bilir.
                        if ownerSig == "unsigned" && owner?.script != true { rules.append(.unsignedStartupBinary) }
                        else if ownerUnsigned { rules.append(.startupWeakSignature) }
                    } else if ownerUnsigned {
                        rules.append(.unsignedPersistence)
                    }
                    let g = apps[key]!.grants
                    if let a = g["kTCCServiceAccessibility"], let s = g["kTCCServiceScreenCapture"], abs(a.timeIntervalSince(s)) <= 120 {
                        rules.append(.rapidGrants)
                    }
                    if let exe = e.executable_path, PathUtil.isHidden(exe) { rules.append(.hiddenTarget) }
                }
                let plistPath = PathUtil.fromURL(it?.url)
                if let p = plistPath { sub.append(PathUtil.abbreviate(p).components(separatedBy: "/").last ?? p) }
                let sigDesc = owner?.script == true ? L("sig.script") : Text10n.signature(ownerSig, team: owner?.team_id)
                let who = procName(owner) + (sigDesc.map { " (\($0))" } ?? "")
                sub.append(scanned ? L("sub.runs", who) : L("sub.addedBy", who))

                fields.append(Field(label: L("field.itemType"), value: typeText, mono: true))
                if let p = plistPath { fields.append(Field(label: "Plist", value: PathUtil.abbreviate(p), mono: true)) }
                if let exe = e.executable_path { fields.append(Field(label: L("field.executes"), value: PathUtil.abbreviate(exe), mono: true)) }
                if !scanned {
                    fields.append(Field(label: L("field.addedBy"), value: "\(procName(owner)) (pid \(owner?.pid ?? 0))", mono: true))
                }
                fields.append(Field(label: L("field.signature"), value: sigDesc ?? "—", mono: true, warn: ownerUnsigned))
                if let src = owner?.path, !scanned || PathUtil.appBundle(src) != nil {
                    fields.append(Field(label: L("field.source"), value: PathUtil.abbreviate(PathUtil.appBundle(src) ?? src), mono: true))
                }
                if add, let p = plistPath, p.contains("/Library/LaunchAgents/"), p.hasPrefix(NSHomeDirectory()) { plist = p }
                reveal = plistPath

            case "quarantine_removed":
                kind = .quarantine
                let path = e.target?.path ?? "?"
                key = keyFor(path: path)
                touch(key, name: PathUtil.displayName(key), date: d)
                apps[key]!.quarantineRemoved = true
                quarantined.append(path)
                name = apps[key]!.name
                title = L("ev.quarantine")
                rules.append(.quarantine)
                sub = [PathUtil.abbreviate(path), procName(e.process)]
                fields.append(Field(label: L("field.target"), value: PathUtil.abbreviate(path), mono: true))
                fields.append(Field(label: L("field.process"), value: "\(procName(e.process)) (pid \(e.process?.pid ?? 0))", mono: true))
                reveal = path

            case "gatekeeper_user_override":
                kind = .gatekeeper
                let path = e.target?.path ?? "?"
                key = keyFor(path: path)
                touch(key, name: PathUtil.displayName(key), date: d)
                name = apps[key]!.name
                title = L("ev.gatekeeper", name)
                rules.append(.gatekeeper)
                sub = [PathUtil.abbreviate(path)]
                fields.append(Field(label: L("field.target"), value: PathUtil.abbreviate(path), mono: true))
                if let h = e.sha256 { fields.append(Field(label: "SHA-256", value: h, mono: true)) }
                fields.append(Field(label: L("field.signature"),
                                    value: e.target_signing.flatMap { $0.team_id.map { L("sig.developer", $0) } } ?? L("sig.unsigned"),
                                    mono: true, warn: e.target_signing == nil))
                reveal = path

            case "tcc_modify":
                kind = .tcc
                let svc = e.service ?? "?"
                tccService = svc
                let ident = e.identity ?? "?"
                let resp = e.responsible
                if e.identity_type == "bundle_id" {
                    if let k = bundleKey[ident] {
                        key = k
                    } else if let rp = resp?.path, resp?.signing_id == ident {
                        key = keyFor(path: rp)
                    } else if let p = Signing.appPath(bundleID: ident) {
                        key = p
                    } else {
                        key = "bundle:" + ident
                    }
                } else {
                    key = keyFor(path: ident)
                }
                let display = key.hasPrefix("bundle:") ? ident : PathUtil.displayName(key)
                touch(key, name: display, date: d)
                apps[key]!.hasTCCorBTM = true
                if resp?.signing_id == ident || e.identity_type == "executable_path" { setSig(key, resp) }
                if apps[key]!.sig == nil, !key.hasPrefix("bundle:"), let info = Signing.info(path: key) {
                    apps[key]!.sig = info.isApple ? "apple" : (info.teamID == nil ? "adhoc" : "developer")
                    apps[key]!.team = info.teamID
                    apps[key]!.org = info.organization
                    apps[key]!.location = key
                }
                name = apps[key]!.name
                let svcName = Text10n.service(svc)
                let granted = e.right == "allowed" || e.right == "limited"
                if e.update == "delete" {
                    title = L("ev.tcc.revoked", name, svcName)
                } else if e.right == "denied" {
                    title = L("ev.tcc.denied", name, svcName)
                } else if e.right == "limited" {
                    title = L("ev.tcc.limited", name, svcName)
                } else {
                    title = L("ev.tcc.granted", name, svcName)
                }
                let allowedNow = granted && e.update != "delete"
                apps[key]!.allowed[svc] = allowedNow
                if allowedNow {
                    apps[key]!.grants[svc] = d
                    apps[key]!.grantedVia = Text10n.reason(e.reason)
                    let s = apps[key]!.sig
                    if s == "unsigned" { rules.append(.tccUnsigned) }
                    if s == "adhoc" { rules.append(.tccAdhoc) }
                    let other = svc == "kTCCServiceAccessibility" ? "kTCCServiceScreenCapture"
                              : svc == "kTCCServiceScreenCapture" ? "kTCCServiceAccessibility" : nil
                    if let o = other, let t = apps[key]!.grants[o], abs(t.timeIntervalSince(d)) <= 120 { rules.append(.rapidGrants) }
                }
                sub.append(Text10n.reason(e.reason))
                if let s = sigText(key) { sub.append(s) }
                fields.append(Field(label: L("field.service"), value: svcName))
                fields.append(Field(label: L("field.identity"), value: PathUtil.abbreviate(ident), mono: true))
                if let target = e.argv?.first {
                    fields.append(Field(label: L("field.target"), value: PathUtil.abbreviate(target), mono: true))
                }
                fields.append(Field(label: L("field.reason"), value: Text10n.reason(e.reason)))
                fields.append(Field(label: L("field.signature"), value: sigText(key) ?? "—", mono: true,
                                    warn: apps[key]!.sig == "unsigned" || apps[key]!.sig == "adhoc"))
                if !key.hasPrefix("bundle:") { reveal = key }

            default:
                continue
            }

            // Taramalar arasında değişmeyen kimlik: olay türü + zaman + konu.
            var h = Hasher()
            h.combine(e.event); h.combine(e.ts); h.combine(e.identity); h.combine(e.service)
            h.combine(e.item?.url); h.combine(e.target?.path); h.combine(e.target?.process?.path); h.combine(e.update)
            var sid = h.finalize()
            while usedIDs.contains(sid) { sid &+= 1 }
            usedIDs.insert(sid)
            _ = idx
            apps[key]!.itemIDs.append(sid)
            let isTrusted = trusted.contains(key)
            let risk = isTrusted ? .normal : (rules.map(\.risk).max() ?? .normal)
            items.append(Item(id: sid, date: d, kind: kind, appKey: key, appName: name, title: title,
                              subtitle: sub.joined(separator: " · "), rules: rules, risk: risk, trusted: isTrusted,
                              rawType: e.event.uppercased(), fields: fields, tccService: tccService,
                              revealPath: reveal, removablePlist: plist))
        }

        let byID = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
        var summaries: [AppSummary] = []
        for (key, a) in apps where a.hasTCCorBTM || (a.sig != nil && a.sig != "apple") {
            let its = a.itemIDs.compactMap { byID[$0] }
            let isTrusted = trusted.contains(key)
            let risk = isTrusted ? .normal : (its.map(\.risk).max() ?? .normal)
            // 8 kovalık etkinlik çubuğu
            let span = max(a.last.timeIntervalSince(a.first), 1)
            var counts = Array(repeating: 0, count: 8)
            var high = Array(repeating: false, count: 8)
            for it in its {
                let b = min(7, Int(it.date.timeIntervalSince(a.first) / span * 8))
                counts[b] += 1
                if it.risk == .high { high[b] = true }
            }
            let mx = Double(counts.max() ?? 1)
            let buckets = (0..<8).map { (level: max(0.12, Double(counts[$0]) / max(mx, 1)), high: high[$0]) }
            let services = a.allowed.filter(\.value).map(\.key).sorted()
            summaries.append(AppSummary(key: key, name: a.name,
                                        signatureText: Text10n.signature(a.sig, team: a.team, org: a.org),
                                        location: a.location.map { PathUtil.abbreviate(PathUtil.parentDir($0)) },
                                        firstSeen: a.first, lastSeen: a.last, risk: risk, trusted: isTrusted,
                                        services: services, loginItem: a.loginItem,
                                        quarantineRemoved: a.quarantineRemoved, grantedVia: a.grantedVia,
                                        buckets: buckets))
        }
        return Analysis(items: items, apps: summaries)
    }
}
