// permwatch uygulama testleri: paket ayrıştırıcı, gizleme, izleyiciler, açıklamalar.
// Çalıştır: make test-app
import Foundation

var failures = 0
func check(_ cond: Bool, _ name: String, file: String = #file, line: Int = #line) {
    if cond { print("✓ \(name)") } else { failures += 1; print("✗ \(name)  (\(line). satır)") }
}

func le(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xff), UInt8(v >> 8 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 24)] }
func be16(_ v: Int) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }

/// PKTAP başlığı + DLT_NULL + IPv4 + L4 + veri.
func frame(proto: UInt8, l4: [UInt8], payload: [UInt8], pid: UInt32 = 4242, comm: String = "curl", dirOut: Bool = true,
           src: [UInt8] = [10, 8, 1, 2], dst: [UInt8] = [34, 223, 124, 45]) -> [UInt8] {
    var h = [UInt8](repeating: 0, count: 156)
    h.replaceSubrange(0..<4, with: le(156)); h.replaceSubrange(8..<12, with: le(0))
    h.replaceSubrange(12..<17, with: Array("utun4".utf8)); h.replaceSubrange(36..<40, with: le(dirOut ? 2 : 1))
    h.replaceSubrange(52..<56, with: le(pid)); h.replaceSubrange(56..<(56 + comm.utf8.count), with: Array(comm.utf8))
    var ip: [UInt8] = [0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0] + src + dst
    let total = 20 + l4.count + payload.count
    ip[2] = UInt8(total >> 8); ip[3] = UInt8(total & 0xff)
    return h + le(2) + ip + l4 + payload
}
let tcpHdr: [UInt8] = [0xf0, 0x30, 0, 80, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]
func udpHdr(_ sp: Int, _ dp: Int, _ n: Int) -> [UInt8] { be16(sp) + be16(dp) + be16(8 + n) + [0, 0] }

func parse(_ f: [UInt8], payload: Bool = false) -> Packet? {
    f.withUnsafeBytes { PacketParser.parse(link: 149, $0, wire: f.count, ts: 0, seq: 1, payload: payload) }
}

// HTTP + Basic yetkilendirme
let http = Array("GET /x?user=a&password=hunter2 HTTP/1.1\r\nHost: neverssl.com\r\nAuthorization: Basic dGVzdA==\r\n\r\n".utf8)
let f1 = frame(proto: 6, l4: tcpHdr, payload: http)
if let p = parse(f1) {
    check(p.proc == "curl" && p.pid == 4242 && p.dir == "out" && p.iface == "utun4", "PKTAP: süreç, yön, arayüz")
    check(p.proto == "HTTP" && p.host == "neverssl.com", "HTTP isteği ve Host")
    check(p.flags == ["pkt.flag.cleartextCreds"], "şifresiz parola tespiti")
    check(p.info.contains("password=hunter2"), "hiçbir değer gizlenmez")
    check(p.payloadStart == 156 + 4 + 20 + 20, "uygulama verisinin başlangıcı")
    check((p.hex?.count ?? 0) == (4 + 20 + 20) * 2, "içerik kapalıyken hex yalnızca başlıklar")
    check(!(p.hex ?? "").contains("68756e74657232"), "parola hex dökümünde yok")
} else { check(false, "HTTP paketi ayrıştırılamadı") }
if let p = parse(f1, payload: true) {
    check((p.hex?.count ?? 0) == (f1.count - 156) * 2, "içerik açıkken çerçevenin tamamı")
    check((p.hex ?? "").contains("68756e74657232"), "içerik açıkken parola dökümde")
}

// DNS yanıtı (sıkıştırmalı ad)
var dns: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]
let q1: [UInt8] = [7]; dns += q1; dns += Array("example".utf8)
let q2: [UInt8] = [3]; dns += q2; dns += Array("com".utf8)
let q3: [UInt8] = [0, 0, 1, 0, 1]; dns += q3
let a1: [UInt8] = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]; dns += a1
let a2: [UInt8] = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]; dns += a2
if let p = parse(frame(proto: 17, l4: udpHdr(53, 51000, dns.count), payload: dns, dirOut: false)) {
    check(p.proto == "DNS" && p.host == "example.com", "DNS sorgu adı")
    check(p.dns == ["93.184.216.34", "1.2.3.4"], "DNS yanıt adresleri")
} else { check(false, "DNS ayrıştırılamadı") }

// TLS ClientHello + SNI
let name = Array("api.example.org".utf8)
var sniExt: [UInt8] = be16(0)
sniExt += be16(name.count + 5); sniExt += be16(name.count + 3)
let zero: [UInt8] = [0]; sniExt += zero; sniExt += be16(name.count); sniExt += name
var body: [UInt8] = [3, 3]
body += [UInt8](repeating: 0, count: 32)
let b2: [UInt8] = [0, 0, 2, 0x13, 0x01, 1, 0]; body += b2
body += be16(sniExt.count); body += sniExt
var hs: [UInt8] = [1, 0]; hs += be16(body.count); hs += body
var rec: [UInt8] = [0x16, 3, 1]; rec += be16(hs.count); rec += hs
var tcp443 = tcpHdr; tcp443[2] = 0x01; tcp443[3] = 0xbb
if let p = parse(frame(proto: 6, l4: tcp443, payload: rec)) {
    check(p.proto == "TLS" && p.host == "api.example.org", "TLS SNI")
} else { check(false, "TLS ayrıştırılamadı") }

// Bozuk/kısa paketler çökmemeli
for n in [0, 10, 100, 156, 160, 170, 180] {
    let cut = Array(f1.prefix(n))
    _ = parse(cut)
}
check(true, "kısa ve bozuk paketlerde çökme yok")
var rng = SystemRandomNumberGenerator()
for _ in 0..<2000 {
    var junk = f1; for i in 156..<junk.count where Int.random(in: 0..<8, using: &rng) == 0 { junk[i] = UInt8.random(in: 0...255, using: &rng) }
    _ = parse(junk)
}
check(true, "rastgele bozulmuş 2000 pakette çökme yok")

// Motor varsayılanı: paketler eksiksiz kaydedilir
check(CaptureEngine(device: "x").storePayload, "yakalama varsayılan olarak tam içerik kaydeder")

// İzleyiciler
check(Trackers.match("www.google-analytics.com")?.company == "Google", "izleyici: alt alan adı")
check(Trackers.match("example.com") == nil, "izleyici: sıradan site değil")
check(Trackers.match("notdoubleclick.net") == nil, "izleyici: benzer ad eşleşmez")

// Açıklamalar
let tls = Packet(seq: 1, ts: 0, l3: "IPv4", proto: "TLS", src: "10.0.0.2", dst: "1.1.1.1", sport: 5000, dport: 443,
                 len: 100, info: "Application Data")
check(Explainer.packet(tls, host: "x.com", app: "Safari", signature: "apple").verdict == .ok, "imzalı uygulamanın şifreli trafiği olağan")
check(Explainer.packet(tls, host: "x.com", app: "agent", signature: "unsigned").verdict == .caution, "imzasız programın şifreli trafiği uyarı")
check(Explainer.packet(tls, host: "x.com", app: "wget", signature: "homebrew").verdict == .ok, "Homebrew programı imzasız sayılmaz")
var cred = tls; cred.flags = ["pkt.flag.cleartextCreds"]
check(Explainer.packet(cred, host: nil, app: "a").verdict == .danger, "şifresiz parola tehlike")
check(Conversation.isLocal("192.168.1.5") && Conversation.isLocal("100.100.1.1") && !Conversation.isLocal("8.8.8.8"), "yerel adres tespiti")

// .pcap düzeltme: yarım paket atılır, PKTAP bağlantı türü 258 olur
var pc = Data([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 149, 0, 0, 0])
func rec(_ n: Int) -> Data { var r = Data(count: 8); r.append(contentsOf: le(UInt32(n))); r.append(contentsOf: le(UInt32(n))); r.append(Data(count: n)); return r }
pc.append(rec(10)); pc.append(rec(20)); pc.append(rec(30).prefix(25))
let fixed = PcapFile.sanitize(pc)
check(fixed.packets == 2 && fixed.data.count == 24 + 26 + 36, "yarım kalan son paket atılır")
check(fixed.data[20] == 2 && fixed.data[21] == 1, "PKTAP bağlantı türü 258 yazılır")

print(failures == 0 ? "\nTüm testler geçti." : "\n\(failures) test başarısız.")
exit(failures == 0 ? 0 : 1)
