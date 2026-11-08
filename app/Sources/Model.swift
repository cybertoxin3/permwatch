import Foundation

// permwatch CLI'ının JSON Lines çıktısının şeması (src/main.c ile birebir).

struct ProcInfo: Codable, Hashable {
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
    var script: Bool?        // imzasız ama "#!" ile başlayan betik (yalnızca tarama)
}

struct BTMItem: Codable, Hashable {
    var type: String
    var legacy: Bool?
    var managed: Bool?
    var uid: Int32?
    var url: String?
    var app_url: String?
}

struct TargetSigning: Codable, Hashable {
    var signing_id: String?
    var team_id: String?
    var cdhash: String?
}

/// `target` exec olayında süreç nesnesi, quarantine/gatekeeper olaylarında dosya yolu.
enum TargetField: Codable, Hashable {
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

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .process(let p): try c.encode(p)
        case .path(let s): try c.encode(s)
        }
    }

    var process: ProcInfo? { if case .process(let p) = self { return p }; return nil }
    var path: String? { if case .path(let s) = self { return s }; return nil }
}

struct RawEvent: Codable {
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
    // "scan": CLI olayı değil, SystemScanner'ın bu Mac'in mevcut durumundan ürettiği kayıt
    var origin: String?
    var label: String?       // tarama: genişletilmiş kalıcılık öğesinin görünen adı
    var note: String?        // tarama: virgülle ayrılmış kural adları (ör. "shellSuspicious")

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
