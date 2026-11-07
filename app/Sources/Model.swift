import Foundation

// permwatch CLI'ının JSON Lines çıktısının şeması (src/main.c ile birebir).

struct ProcInfo: Decodable, Hashable {
    var pid: Int32?
    var ppid: Int32?
    var uid: Int32?
    var responsible_pid: Int32?
    var path: String?
    var signing_id: String?
    var team_id: String?
    var signature: String?   // apple | developer | adhoc | unsigned
    var cs_flags: String?
    var cdhash: String?
}

struct BTMItem: Decodable, Hashable {
    var type: String
    var legacy: Bool?
    var managed: Bool?
    var uid: Int32?
    var url: String?
    var app_url: String?
}

struct TargetSigning: Decodable, Hashable {
    var signing_id: String?
    var team_id: String?
    var cdhash: String?
}

/// `target` exec olayında süreç nesnesi, quarantine/gatekeeper olaylarında dosya yolu.
enum TargetField: Decodable, Hashable {
    case process(ProcInfo)
    case path(String)

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self) {
            self = .path(s)
        } else {
            self = .process(try c.decode(ProcInfo.self))
        }
    }

    var process: ProcInfo? { if case .process(let p) = self { return p }; return nil }
    var path: String? { if case .path(let s) = self { return s }; return nil }
}

struct RawEvent: Decodable {
    var ts: Double
    var event: String
    var process: ProcInfo?
    // exec
    var target: TargetField?
    var argv: [String]?
    var dyld_env: [String]?
    var lolbin: Bool?
    // btm
    var item: BTMItem?
    var executable_path: String?
    var instigator: ProcInfo?
    var app: ProcInfo?
    // tcc
    var service: String?
    var identity: String?
    var identity_type: String?
    var update: String?
    var right: String?
    var reason: String?
    var responsible: ProcInfo?
    // gatekeeper
    var sha256: String?
    var target_signing: TargetSigning?

    var date: Date { Date(timeIntervalSince1970: ts) }
}

enum JSONL {
    /// Satır satır çözer; bozuk satırları atlar ve sayısını döndürür.
    static func decode(_ data: Data) -> (events: [RawEvent], bad: Int) {
        let dec = JSONDecoder()
        var out: [RawEvent] = []
        var bad = 0
        for line in data.split(separator: UInt8(ascii: "\n")) where !line.isEmpty {
            if let e = try? dec.decode(RawEvent.self, from: Data(line)) {
                out.append(e)
            } else {
                bad += 1
            }
        }
        return (out, bad)
    }
}
