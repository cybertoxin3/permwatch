import AppKit
import Foundation
import Security
import SQLite3

/// Bu Mac'in gerçek durumunu okur: TCC izin veritabanları ve launchd başlangıç öğeleri.
/// Endpoint Security gerektirmez; TCC.db için uygulamaya Tam Disk Erişimi verilmiş olmalı.
/// Sonuçları CLI'ın olay formatına (RawEvent) çevirir, böylece aynı kural motoru kullanılır.
enum SystemScanner {
    static let userTCC = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
    static let systemTCC = "/Library/Application Support/com.apple.TCC/TCC.db"
    static let launchDirs = [
        NSHomeDirectory() + "/Library/LaunchAgents",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ]

    /// Kullanıcı TCC.db okunabiliyorsa Tam Disk Erişimi var demektir.
    static var hasFullDiskAccess: Bool {
        var db: OpaquePointer?
        defer { sqlite3_close(db) }
        guard sqlite3_open_v2("file:\(userTCC)?immutable=1", &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nil) == SQLITE_OK
        else { return false }
        return sqlite3_exec(db, "select 1 from access limit 1", nil, nil, nil) == SQLITE_OK
    }

    struct Snapshot: Codable, Equatable {
        var tcc: [String: Int] = [:]        // "servis|istemci" → auth_value
        var plists: [String: String] = [:]  // plist yolu → çalıştırılan dosya
    }

    struct Result {
        var events: [RawEvent]
        var snapshot: Snapshot
        var tccReadable: Bool
    }

    /// Mevcut durumu okur; önceki anlık görüntüyle karşılaştırıp silinen izin ve
    /// başlangıç öğeleri için "kaldırıldı" olayları üretir.
    static func scan(previous: Snapshot?, removedLog: [RawEvent]) -> Result {
        var events: [RawEvent] = []
        var snap = Snapshot()
        let now = Date().timeIntervalSince1970

        // MARK: TCC
        var readable = false
        for path in [userTCC, systemTCC] {
            guard let rows = readTCC(path) else { continue }
            readable = true
            for r in rows {
                let key = "\(r.service)|\(r.client)"
                snap.tcc[key] = r.auth
                let right: String
                switch r.auth {
                case 0: right = "denied"
                case 2: right = "allowed"
                case 3, 4, 5: right = "limited"
                default: continue
                }
                var e = RawEvent(ts: r.modified > 0 ? r.modified : now, event: "tcc_modify")
                e.origin = "scan"
                e.service = r.service
                e.identity = r.client
                e.identity_type = r.clientType == 1 ? "executable_path" : "bundle_id"
                e.update = (previous?.tcc[key]).map { $0 == r.auth ? "create" : "modify" } ?? "create"
                e.right = right
                e.reason = reasonName(r.reason)
                e.responsible = processInfo(forClient: r.client, type: r.clientType)
                if let target = r.indirect { e.argv = [target] }
                events.append(e)
            }
        }

        // MARK: launchd başlangıç öğeleri
        for dir in launchDirs {
            let daemon = dir.hasSuffix("LaunchDaemons")
            let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
            for name in names where name.hasSuffix(".plist") {
                let plist = dir + "/" + name
                guard let exe = executable(ofPlist: plist) else { continue }
                snap.plists[plist] = exe
                let attrs = try? FileManager.default.attributesOfItem(atPath: plist)
                let created = (attrs?[.creationDate] as? Date)?.timeIntervalSince1970 ?? now
                var e = RawEvent(ts: created, event: "btm_launch_item_add")
                e.origin = "scan"
                e.item = BTMItem(type: daemon ? "daemon" : "agent", legacy: true, managed: false, uid: nil,
                                 url: URL(fileURLWithPath: plist).absoluteString,
                                 app_url: PathUtil.appBundle(exe).map { URL(fileURLWithPath: $0).absoluteString })
                e.executable_path = exe
                e.instigator = processInfo(forPath: exe)
                events.append(e)
            }
        }

        // MARK: Kaybolanlar (önceki taramada vardı, şimdi yok)
        var removed = removedLog
        if let prev = previous {
            for (key, auth) in prev.tcc where snap.tcc[key] == nil && readable {
                let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
                guard parts.count == 2 else { continue }
                var e = RawEvent(ts: now, event: "tcc_modify")
                e.origin = "scan"
                e.service = parts[0]
                e.identity = parts[1]
                e.identity_type = parts[1].hasPrefix("/") ? "executable_path" : "bundle_id"
                e.update = "delete"
                e.right = auth == 2 ? "allowed" : "denied"
                e.reason = "user_set"
                e.responsible = processInfo(forClient: parts[1], type: parts[1].hasPrefix("/") ? 1 : 0)
                removed.append(e)
            }
            for (plist, exe) in prev.plists where snap.plists[plist] == nil {
                var e = RawEvent(ts: now, event: "btm_launch_item_remove")
                e.origin = "scan"
                e.item = BTMItem(type: plist.contains("LaunchDaemons") ? "daemon" : "agent", legacy: true,
                                 managed: false, uid: nil, url: URL(fileURLWithPath: plist).absoluteString, app_url: nil)
                e.instigator = processInfo(forPath: exe)
                removed.append(e)
            }
        }
        return Result(events: events + removed, snapshot: snap, tccReadable: readable)
    }

    // MARK: - TCC okuma

    private struct Row {
        var service: String
        var client: String
        var clientType: Int
        var auth: Int
        var reason: Int
        var modified: Double
        var indirect: String?
    }

    private static func readTCC(_ path: String) -> [Row]? {
        var db: OpaquePointer?
        defer { sqlite3_close(db) }
        guard sqlite3_open_v2("file:\(path)?immutable=1", &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nil) == SQLITE_OK
        else { return nil }
        let sql = """
            select service, client, client_type, auth_value, auth_reason, last_modified, indirect_object_identifier
            from access
            """
        var st: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(st) }
        func text(_ i: Int32) -> String? { sqlite3_column_text(st, i).map { String(cString: $0) } }
        var rows: [Row] = []
        while sqlite3_step(st) == SQLITE_ROW {
            guard let svc = text(0), let client = text(1) else { continue }
            let ind = text(6).flatMap { $0 == "UNUSED" || $0.isEmpty ? nil : $0 }
            rows.append(Row(service: svc, client: client, clientType: Int(sqlite3_column_int(st, 2)),
                            auth: Int(sqlite3_column_int(st, 3)), reason: Int(sqlite3_column_int(st, 4)),
                            modified: sqlite3_column_double(st, 5), indirect: ind))
        }
        return rows
    }

    /// TCC auth_reason sayısal değerleri (es_tcc_authorization_reason_t ile aynı sıra).
    private static func reasonName(_ r: Int) -> String {
        switch r {
        case 2: return "user_consent"
        case 3: return "user_set"
        case 4: return "system_set"
        case 5: return "service_policy"
        case 6: return "mdm_policy"
        case 7: return "service_override_policy"
        case 11: return "entitled"
        case 12: return "app_type_policy"
        default: return "other"
        }
    }

    // MARK: - launchd plist

    private static func executable(ofPlist path: String) -> String? {
        guard let d = NSDictionary(contentsOfFile: path) as? [String: Any] else { return nil }
        if let p = d["Program"] as? String { return p }
        if let a = d["ProgramArguments"] as? [String], let p = a.first { return p }
        if let b = d["BundleProgram"] as? String {
            // SMAppService: yol, plist'i içeren uygulamaya göre görelidir.
            if let r = path.range(of: ".app/") { return String(path[..<r.lowerBound]) + ".app/" + b }
            return b
        }
        return nil
    }

    // MARK: - İmza

    private static var cache: [String: ProcInfo] = [:]

    static func processInfo(forClient client: String, type: Int) -> ProcInfo? {
        if type == 1 { return processInfo(forPath: client) }
        guard let app = Signing.appPath(bundleID: client) else {
            return ProcInfo(path: nil, signing_id: client)
        }
        var p = processInfo(forPath: app) ?? ProcInfo(path: app)
        p.signing_id = client
        return p
    }

    static func processInfo(forPath path: String) -> ProcInfo? {
        if let c = cache[path] { return c }
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let target = PathUtil.appBundle(path) ?? path
        var p = ProcInfo(path: path)
        let c = Signing.classify(path: target)
        p.signature = c.signature
        p.team_id = c.team
        p.signing_id = c.identifier
        if c.signature == "unsigned", let h = FileHandle(forReadingAtPath: path) {
            p.script = h.readData(ofLength: 2) == Data("#!".utf8)
            try? h.close()
        }
        cache[path] = p
        return p
    }
}

extension RawEvent {
    init(ts: Double, event: String) {
        self.ts = ts
        self.event = event
    }
}

extension ProcInfo {
    init(path: String?, signing_id: String? = nil) {
        self.path = path
        self.signing_id = signing_id
    }
}
