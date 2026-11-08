// permwatch-root: yönetici modu yardımcısı (root olarak çalışır).
//
// Güvenlik tasarımı:
//  - Hiçbir girdi almaz (soket, dosya, argümanla komut yok); yalnızca sabit, salt-okunur
//    bir komut listesini çalıştırır ve sonucu tek bir JSON dosyasına yazar.
//  - Başlatan permwatch süreci kapanınca kendiliğinden çıkar.
//
// Kullanım: permwatch-root <üst-pid>
import Darwin
import Foundation

let outDir = "/Library/Application Support/permwatch"
let outPath = outDir + "/root.json"

guard CommandLine.arguments.count >= 2, let parent = Int32(CommandLine.arguments[1]) else {
    FileHandle.standardError.write(Data("kullanım: permwatch-root <üst-pid>\n".utf8))
    exit(64)
}
guard getuid() == 0 else {
    FileHandle.standardError.write(Data("root olarak çalışmalı\n".utf8))
    exit(77)
}

func run(_ tool: String, _ args: [String]) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: tool)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()   // önce oku (64 KB tamponu)
    p.waitUntilExit()
    return String(decoding: data, as: UTF8.self)
}

/// KERN_PROCARGS2: argümanlar ve DYLD_* ortam değişkenleri (root olarak her süreç için).
func procArgs(_ pid: Int32) -> (args: [String], dyld: [String])? {
    var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
    var argmax: Int32 = 0
    var size = MemoryLayout<Int32>.size
    guard sysctl(&mib, 2, &argmax, &size, nil, 0) == 0 else { return nil }
    var buf = [UInt8](repeating: 0, count: Int(argmax))
    size = buf.count
    mib = [CTL_KERN, KERN_PROCARGS2, pid]
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return nil }
    let argc = Int(buf.withUnsafeBytes { $0.load(as: Int32.self) })
    var i = 4
    while i < size && buf[i] != 0 { i += 1 }
    while i < size && buf[i] == 0 { i += 1 }
    var strings: [String] = []
    var start = i
    while i < size {
        if buf[i] == 0 {
            if i == start { break }
            strings.append(String(decoding: buf[start..<i], as: UTF8.self))
            start = i + 1
        }
        i += 1
    }
    let args = Array(strings.prefix(argc).prefix(24))
    let dyld = strings.dropFirst(argc).filter { $0.hasPrefix("DYLD_") }
    return (args, Array(dyld))
}

try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true,
                                         attributes: [.posixPermissions: 0o755])

var slow: [String: String] = [:]
var tick = 0
while true {
    // Başlatan uygulama kapandıysa çık.
    if kill(parent, 0) != 0 && errno == ESRCH { exit(0) }

    // Yavaş değişenler dakikada bir.
    if tick % 12 == 0 {
        slow["btm"] = run("/usr/bin/sfltool", ["dumpbtm"])
        slow["cron"] = run("/usr/bin/crontab", ["-l", "-u", "root"])
        slow["profiles"] = run("/usr/bin/profiles", ["show", "-type", "configuration"])
    }
    var procs: [String: [String: [String]]] = [:]
    let n = proc_listallpids(nil, 0)
    var pids = [Int32](repeating: 0, count: Int(max(n, 0)) + 64)
    let got = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size)))
    for pid in pids.prefix(max(0, got)) where pid > 0 {
        if let a = procArgs(pid) { procs[String(pid)] = ["args": a.args, "dyld": a.dyld] }
    }
    let doc: [String: Any] = [
        "ts": Date().timeIntervalSince1970,
        "lsof": run("/usr/sbin/lsof", ["-nP", "-i", "-F", "pcfPnT"]),
        "btm": slow["btm"] ?? "", "cron": slow["cron"] ?? "", "profiles": slow["profiles"] ?? "",
        "procs": procs,
    ]
    if let data = try? JSONSerialization.data(withJSONObject: doc) {
        let tmp = outPath + ".tmp"
        FileManager.default.createFile(atPath: tmp, contents: data, attributes: [.posixPermissions: 0o644])
        rename(tmp, outPath)
    }
    tick += 1
    sleep(5)
}
