// permwatch-guard: Endpoint Security ile her program çalıştırılmadan ÖNCE izin ister (AUTH_EXEC).
// Apple'ın kendi (platform) programlarına hemen izin verir; diğerlerini Apple XProtect ve Elastic
// imzalarıyla tarar ve bilinen bir zararlıysa çalışmasını engeller. Kullanıcının "tanıyorum" dediği
// yollar her zaman çalışır. Engellenen her olay kullanıcının okuyabildiği bir dosyaya yazılır.
//
// Girdi yok, komut almaz. Root olarak launchd (SMAppService) tarafından çalıştırılır.
import Foundation

let dataDir = "/Library/Application Support/permwatch"
let statusPath = dataDir + "/guard.json"
let eventsPath = dataDir + "/guard-events.jsonl"

// MARK: Konsol kullanıcısı (olay dosyasının sahibi, izin listesi ve güncel imzaların yeri)

struct ConsoleUser { let uid: uid_t; let gid: gid_t; let home: String }

func consoleUser() -> ConsoleUser? {
    var st = stat()
    guard stat("/dev/console", &st) == 0, st.st_uid != 0, let pw = getpwuid(st.st_uid) else { return nil }
    return ConsoleUser(uid: st.st_uid, gid: pw.pointee.pw_gid, home: String(cString: pw.pointee.pw_dir))
}

/// Yalnızca kullanıcıya (ya da root'a) ait ve başkalarının yazamadığı dosyalar okunur.
func trustedFile(_ path: String, owner: uid_t) -> Bool {
    var st = stat()
    guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG || (st.st_mode & S_IFMT) == S_IFDIR else { return false }
    return (st.st_uid == owner || st.st_uid == 0) && (st.st_mode & 0o022) == 0
}

// MARK: YARA

final class Rules: @unchecked Sendable {
    // Taramalar eşzamanlı (okuyucu), yeniden yükleme tek başına (yazıcı).
    private var rw = pthread_rwlock_t()
    private var rules: UnsafeMutablePointer<YR_RULES>?
    private var stamp = ""
    private(set) var count = 0

    init() { yr_initialize(); pthread_rwlock_init(&rw, nil) }

    static let xprotect = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources"

    /// Güncel Elastic kuralları (kullanıcının indirdikleri, güvenilirse) ya da uygulamayla gelenler.
    static func extraDir(user: ConsoleUser?) -> String? {
        if let u = user {
            let d = u.home + "/Library/Application Support/permwatch/intel/rules"
            if trustedFile(d, owner: u.uid), !((try? FileManager.default.contentsOfDirectory(atPath: d)) ?? []).filter({ $0.hasSuffix(".yar") }).isEmpty { return d }
        }
        // permwatch.app/Contents/Library/Guard/permwatch-guard.app → permwatch.app/Contents/Resources
        let contents = ((Bundle.main.bundlePath as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent
        let d = (contents as NSString).deletingLastPathComponent + "/Resources/rules/elastic"
        return FileManager.default.fileExists(atPath: d) ? d : nil
    }

    func reload(user: ConsoleUser?) {
        var files = ["XProtect.yara", "XPScripts.yr"].map { Self.xprotect + "/" + $0 }.filter { FileManager.default.fileExists(atPath: $0) }
        let apple = files.count
        if let d = Self.extraDir(user: user) {
            files += ((try? FileManager.default.contentsOfDirectory(atPath: d)) ?? []).filter { $0.hasSuffix(".yar") }.sorted().map { d + "/" + $0 }
        }
        let key = files.map { f in "\(f):\((try? FileManager.default.attributesOfItem(atPath: f))?[.modificationDate] as? Date ?? .distantPast)" }.joined()
        pthread_rwlock_rdlock(&rw); let same = key == stamp && rules != nil; pthread_rwlock_unlock(&rw)
        if same { return }
        func compiles(_ path: String) -> Bool {
            var c: UnsafeMutablePointer<YR_COMPILER>?
            guard yr_compiler_create(&c) == ERROR_SUCCESS, let c else { return false }
            defer { yr_compiler_destroy(c) }
            guard let fp = fopen(path, "r") else { return false }
            defer { fclose(fp) }
            return yr_compiler_add_file(c, fp, "t", path) == 0
        }
        var comp: UnsafeMutablePointer<YR_COMPILER>?
        guard yr_compiler_create(&comp) == ERROR_SUCCESS, let comp else { return }
        defer { yr_compiler_destroy(comp) }
        for (i, f) in files.enumerated() where i < apple || compiles(f) {
            guard let fp = fopen(f, "r") else { continue }
            let ns = i == 0 ? "xprotect" : (i == 1 && apple == 2 ? "scripts" : "elastic." + ((f as NSString).lastPathComponent as NSString).deletingPathExtension)
            _ = yr_compiler_add_file(comp, fp, ns, f)
            fclose(fp)
        }
        var compiled: UnsafeMutablePointer<YR_RULES>?
        guard yr_compiler_get_rules(comp, &compiled) == ERROR_SUCCESS, let compiled else { return }
        var n = 0
        var r = compiled.pointee.rules_table
        while let cur = r, (cur.pointee.flags & Int32(RULE_FLAGS_NULL)) == 0 { n += 1; r = cur + 1 }
        pthread_rwlock_wrlock(&rw)
        if let old = rules { yr_rules_destroy(old) }
        rules = compiled; stamp = key; count = n
        pthread_rwlock_unlock(&rw)
    }

    private final class Box { var hit: (String, String)? }

    /// İlk eşleşme: (kural, ad). Taranamazsa ya da süre biterse nil. timeout: kilit alındıktan sonra
    /// kalan süre (saniye); 1'den azsa taranmaz.
    func scan(_ path: String, timeout: () -> Double) -> (rule: String, name: String)? {
        pthread_rwlock_rdlock(&rw); defer { pthread_rwlock_unlock(&rw) }
        guard let rules else { return nil }
        let t = timeout()
        guard t >= 1 else { return nil }
        let box = Box()
        let ctx = Unmanaged.passRetained(box)
        defer { ctx.release() }
        _ = yr_rules_scan_file(rules, path, SCAN_FLAGS_REPORT_RULES_MATCHING | SCAN_FLAGS_FAST_MODE, { _, message, data, user in
            guard message == CALLBACK_MSG_RULE_MATCHING, let data, let user else { return CALLBACK_CONTINUE }
            let rule = data.assumingMemoryBound(to: YR_RULE.self)
            let id = String(cString: rule.pointee.identifier)
            var name = id
            if var m = rule.pointee.metas {
                while true {
                    let k = String(cString: m.pointee.identifier)
                    if k == "description" || k == "threat_name", let s = m.pointee.string { name = String(cString: s) }
                    if (m.pointee.flags & Int32(META_FLAGS_LAST_IN_RULE)) != 0 { break }
                    m += 1
                }
            }
            Unmanaged<Box>.fromOpaque(user).takeUnretainedValue().hit = (id, name)
            return CALLBACK_ABORT
        }, ctx.toOpaque(), Int32(min(t, 10)))
        return box.hit
    }
}

// MARK: Durum ve olaylar

let rules = Rules()
var user = consoleUser()
let stateLock = NSLock()
var allowed = Set<String>()
var blocked = 0
var scanned = 0
var lastError: String?

func readAllowList() {
    guard let u = user else { allowed = []; return }
    let p = u.home + "/Library/Application Support/permwatch/guard-allow.txt"
    guard trustedFile(p, owner: u.uid), let t = try? String(contentsOfFile: p, encoding: .utf8) else { allowed = []; return }
    let set = Set(t.components(separatedBy: .newlines).filter { $0.hasPrefix("/") })
    stateLock.lock(); allowed = set; stateLock.unlock()
}

func writeOwned(_ data: Data, to path: String, append: Bool) {
    try? FileManager.default.createDirectory(atPath: dataDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
    let fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | (append ? O_APPEND : O_TRUNC), 0o600)
    guard fd >= 0 else { return }
    _ = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
    if let u = user { fchown(fd, u.uid, u.gid) }
    fchmod(fd, 0o600)
    close(fd)
}

func writeStatus(active: Bool) {
    stateLock.lock()
    var doc: [String: Any] = ["ts": Date().timeIntervalSince1970, "active": active, "rules": rules.count,
                              "blocked": blocked, "scanned": scanned]
    if let e = lastError { doc["error"] = e }
    stateLock.unlock()
    if let d = try? JSONSerialization.data(withJSONObject: doc) { writeOwned(d, to: statusPath, append: false) }
}

func logBlock(path: String, rule: String, name: String, pid: Int32, parent: String) {
    let ev: [String: Any] = ["ts": Date().timeIntervalSince1970, "action": "deny", "path": path, "rule": rule,
                             "name": name, "pid": pid, "parent": parent]
    guard var d = try? JSONSerialization.data(withJSONObject: ev) else { return }
    d.append(0x0a)
    // Dosya 1 MB'ı geçerse baştan başla (uygulama olayları zaten okuyup saklıyor).
    if let a = try? FileManager.default.attributesOfItem(atPath: eventsPath), (a[.size] as? Int ?? 0) > 1 << 20 {
        writeOwned(d, to: eventsPath, append: false)
    } else {
        writeOwned(d, to: eventsPath, append: true)
    }
}

// MARK: Endpoint Security

func str(_ t: es_string_token_t) -> String {
    guard t.length > 0, let p = t.data else { return "" }
    return String(decoding: UnsafeRawBufferPointer(start: p, count: t.length), as: UTF8.self)
}

var timebase = mach_timebase_info_data_t()
mach_timebase_info(&timebase)

/// Kararın verilmesi gereken son ana kalan saniye.
func secondsLeft(_ m: UnsafePointer<es_message_t>) -> Double {
    let now = mach_absolute_time()
    let dl = m.pointee.deadline
    guard dl > now else { return 0 }
    return Double(dl - now) * Double(timebase.numer) / Double(timebase.denom) / 1e9
}

let work = DispatchQueue(label: "permwatch.guard", qos: .userInitiated, attributes: .concurrent)
/// Engellenen dosyalar (yol|boyut|değişiklik) → kural; aynı dosya her çalıştırmada yeniden taranmasın.
var denyCache: [String: (String, String)] = [:]

func fileKey(_ f: UnsafeMutablePointer<es_file_t>) -> String {
    let st = f.pointee.stat
    return "\(str(f.pointee.path))|\(st.st_size)|\(st.st_mtimespec.tv_sec)|\(st.st_ino)"
}

func decide(_ client: OpaquePointer, _ m: UnsafePointer<es_message_t>) {
    let exec = m.pointee.event.exec
    let target = exec.target.pointee
    var files: [UnsafeMutablePointer<es_file_t>] = [target.executable]
    // #! betiği: yorumlayıcı Apple'ın olsa bile betiğin kendisi taranır.
    if m.pointee.version >= 2, let s = exec.script { files.append(s) }
    let parent = str(m.pointee.process.pointee.executable.pointee.path)
    let pid = audit_token_to_pid(target.audit_token)

    stateLock.lock(); let allow = allowed; stateLock.unlock()
    var verdict: (String, String, String)?   // yol, kural, ad
    for f in files {
        let path = str(f.pointee.path)
        if allow.contains(path) { continue }
        if target.is_platform_binary && f == target.executable { continue }
        let key = fileKey(f)
        stateLock.lock(); let cached = denyCache[key]; stateLock.unlock()
        if let c = cached { verdict = (path, c.0, c.1); break }
        guard f.pointee.stat.st_size <= 100 << 20 else { continue }
        stateLock.lock(); scanned += 1; stateLock.unlock()
        // Süre kilitten sonra hesaplanır; yanıt için en az 1 saniye pay bırakılır.
        if let hit = rules.scan(path, timeout: { secondsLeft(m) - 1.0 }) {
            stateLock.lock(); denyCache[key] = hit; stateLock.unlock()
            verdict = (path, hit.rule, hit.name)
            break
        }
    }
    if let v = verdict {
        es_respond_auth_result(client, m, ES_AUTH_RESULT_DENY, false)
        stateLock.lock(); blocked += 1; stateLock.unlock()
        logBlock(path: v.0, rule: v.1, name: v.2, pid: pid, parent: parent)
    } else {
        // İzin verilenler çekirdek önbelleğinde tutulur (dosya değişene kadar yeniden sorulmaz).
        es_respond_auth_result(client, m, ES_AUTH_RESULT_ALLOW, true)
    }
}

readAllowList()
rules.reload(user: user)

var client: OpaquePointer?
let res = es_new_client(&client) { c, m in
    guard m.pointee.event_type == ES_EVENT_TYPE_AUTH_EXEC else { return }
    let exec = m.pointee.event.exec
    // Apple'ın programı ve betik değil: beklemeden izin ver.
    if exec.target.pointee.is_platform_binary && !(m.pointee.version >= 2 && exec.script != nil) {
        es_respond_auth_result(c, m, ES_AUTH_RESULT_ALLOW, true)
        return
    }
    es_retain_message(m)
    work.async {
        decide(c, m)
        es_release_message(m)
    }
}

guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
    switch res {
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: lastError = "fda"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: lastError = "entitlement"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: lastError = "root"
    default: lastError = "es_new_client \(res.rawValue)"
    }
    writeStatus(active: false)
    // launchd yeniden başlatır; Tam Disk Erişimi verilene kadar sık deneme yapma.
    sleep(30)
    exit(1)
}

es_mute_path(client, CommandLine.arguments[0], ES_MUTE_PATH_TYPE_LITERAL)
es_clear_cache(client)
var events = [ES_EVENT_TYPE_AUTH_EXEC]
guard es_subscribe(client, &events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
    lastError = "es_subscribe"; writeStatus(active: false); exit(1)
}
writeStatus(active: true)

// Durumu güncel tut; kullanıcı, izin listesi ve imzalar değişirse yeniden oku.
var tick = 0
while true {
    sleep(5)
    tick += 1
    let u = consoleUser()
    if u?.uid != user?.uid { user = u; rules.reload(user: user) }
    readAllowList()
    if tick % 120 == 0 { rules.reload(user: user) }
    writeStatus(active: true)
}
