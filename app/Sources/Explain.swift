import Foundation
import SwiftUI

// MARK: - Konuşma (uygulama ↔ sunucu)

struct Conversation: Identifiable {
    let id: String
    let proc: String
    let pid: Int32?
    let remote: String
    var host: String?
    let port: Int?
    var first: Double
    var last: Double
    var packets = 0
    var bytes = 0
    var bytesIn = 0
    var bytesOut = 0
    var protos: Set<String> = []
    var creds = false

    /// Çok veri gönderip az alan bağlantı (yükleme/sızdırma belirtisi olabilir).
    var uploadHeavy: Bool { bytesOut > 20 << 20 && bytesOut > bytesIn * 5 }

    static func isLocal(_ ip: String) -> Bool {
        if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("127.") || ip.hasPrefix("169.254.")
            || ip.hasPrefix("fe80") || ip.hasPrefix("fd") || ip == "::1" { return true }
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        if parts.count == 4 {
            if parts[0] == 172 && (16...31).contains(parts[1]) { return true }
            if parts[0] == 100 && (64...127).contains(parts[1]) { return true }
        }
        return false
    }
}

// MARK: - İzleyiciler (reklam, analiz, telemetri)

struct Tracker {
    enum Kind: String { case ads, analytics, telemetry, social }
    let company: String
    let kind: Kind

    var kindText: String { L("tracker.kind." + kind.rawValue) }
}

enum Trackers {
    /// Alan adı soneki → şirket ve tür. Bilinen, yaygın izleme/reklam/analiz uç noktaları.
    private static let list: [String: (String, Tracker.Kind)] = [
        "doubleclick.net": ("Google", .ads), "googlesyndication.com": ("Google", .ads), "googleadservices.com": ("Google", .ads),
        "google-analytics.com": ("Google", .analytics), "googletagmanager.com": ("Google", .analytics),
        "app-measurement.com": ("Google Firebase", .analytics), "firebase-settings.crashlytics.com": ("Google Firebase", .telemetry),
        "crashlytics.com": ("Google Firebase", .telemetry), "adservice.google.com": ("Google", .ads),
        "connect.facebook.net": ("Meta", .social), "graph.facebook.com": ("Meta", .social), "an.facebook.com": ("Meta", .ads),
        "pixel.facebook.com": ("Meta", .ads), "ads.linkedin.com": ("LinkedIn", .ads), "px.ads.linkedin.com": ("LinkedIn", .ads),
        "analytics.tiktok.com": ("TikTok", .analytics), "ads.tiktok.com": ("TikTok", .ads),
        "analytics.twitter.com": ("X", .analytics), "ads-api.twitter.com": ("X", .ads),
        "bat.bing.com": ("Microsoft", .ads), "clarity.ms": ("Microsoft Clarity", .analytics),
        "vortex.data.microsoft.com": ("Microsoft", .telemetry), "events.data.microsoft.com": ("Microsoft", .telemetry),
        "mc.yandex.ru": ("Yandex", .analytics), "appmetrica.yandex.net": ("Yandex", .analytics),
        "adnxs.com": ("Xandr", .ads), "criteo.com": ("Criteo", .ads), "criteo.net": ("Criteo", .ads),
        "taboola.com": ("Taboola", .ads), "outbrain.com": ("Outbrain", .ads), "scorecardresearch.com": ("comScore", .analytics),
        "quantserve.com": ("Quantcast", .ads), "rubiconproject.com": ("Magnite", .ads), "pubmatic.com": ("PubMatic", .ads),
        "casalemedia.com": ("Index Exchange", .ads), "openx.net": ("OpenX", .ads), "adsrvr.org": ("The Trade Desk", .ads),
        "amazon-adsystem.com": ("Amazon", .ads), "moatads.com": ("Oracle Moat", .ads),
        "appsflyer.com": ("AppsFlyer", .analytics), "adjust.com": ("Adjust", .analytics), "branch.io": ("Branch", .analytics),
        "app.link": ("Branch", .analytics), "kochava.com": ("Kochava", .analytics), "singular.net": ("Singular", .analytics),
        "mixpanel.com": ("Mixpanel", .analytics), "amplitude.com": ("Amplitude", .analytics), "segment.io": ("Segment", .analytics),
        "segment.com": ("Segment", .analytics), "hotjar.com": ("Hotjar", .analytics), "fullstory.com": ("FullStory", .analytics),
        "heap.io": ("Heap", .analytics), "heapanalytics.com": ("Heap", .analytics), "braze.com": ("Braze", .analytics),
        "onesignal.com": ("OneSignal", .analytics), "statsig.com": ("Statsig", .analytics), "posthog.com": ("PostHog", .analytics),
        "launchdarkly.com": ("LaunchDarkly", .telemetry), "newrelic.com": ("New Relic", .telemetry), "nr-data.net": ("New Relic", .telemetry),
        "sentry.io": ("Sentry", .telemetry), "bugsnag.com": ("Bugsnag", .telemetry), "datadoghq.com": ("Datadog", .telemetry),
        "browser-intake-datadoghq.com": ("Datadog", .telemetry), "instabug.com": ("Instabug", .telemetry),
        "applovin.com": ("AppLovin", .ads), "unityads.unity3d.com": ("Unity Ads", .ads), "chartboost.com": ("Chartboost", .ads),
        "ads.yahoo.com": ("Yahoo", .ads), "analytics.yahoo.com": ("Yahoo", .analytics), "sp.analytics.yahoo.com": ("Yahoo", .analytics),
        "ads.pinterest.com": ("Pinterest", .ads), "ct.pinterest.com": ("Pinterest", .ads), "tr.snapchat.com": ("Snap", .ads),
        "sc-static.net": ("Snap", .ads), "analytics.snapchat.com": ("Snap", .analytics), "ads.reddit.com": ("Reddit", .ads),
        "events.redditmedia.com": ("Reddit", .analytics), "static.ads-twitter.com": ("X", .ads),
        "ads.yandex.ru": ("Yandex", .ads), "an.yandex.ru": ("Yandex", .ads), "top-fwz1.mail.ru": ("VK", .analytics),
        "ad.mail.ru": ("VK", .ads), "mc.webvisor.org": ("Yandex", .analytics),
        "googleoptimize.com": ("Google", .analytics), "stats.g.doubleclick.net": ("Google", .analytics),
        "firebaselogging-pa.googleapis.com": ("Google Firebase", .telemetry), "firebaseinstallations.googleapis.com": ("Google Firebase", .analytics),
        "imasdk.googleapis.com": ("Google", .ads), "pagead2.googlesyndication.com": ("Google", .ads),
        "adsafeprotected.com": ("Integral Ad Science", .ads), "doubleverify.com": ("DoubleVerify", .ads),
        "smartadserver.com": ("Equativ", .ads), "33across.com": ("33Across", .ads), "sharethrough.com": ("Sharethrough", .ads),
        "teads.tv": ("Teads", .ads), "yieldmo.com": ("Yieldmo", .ads), "media.net": ("Media.net", .ads),
        "bidswitch.net": ("BidSwitch", .ads), "contextweb.com": ("PulsePoint", .ads), "lijit.com": ("Sovrn", .ads),
        "demdex.net": ("Adobe", .ads), "omtrdc.net": ("Adobe", .analytics), "2o7.net": ("Adobe", .analytics),
        "everesttech.net": ("Adobe", .ads), "adobedtm.com": ("Adobe", .analytics), "krxd.net": ("Salesforce", .ads),
        "exelator.com": ("Nielsen", .ads), "imrworldwide.com": ("Nielsen", .analytics), "bluekai.com": ("Oracle", .ads),
        "addthis.com": ("Oracle", .social), "rlcdn.com": ("LiveRamp", .ads), "agkn.com": ("Neustar", .ads),
        "tapad.com": ("Tapad", .ads), "mathtag.com": ("MediaMath", .ads), "turn.com": ("Amobee", .ads),
        "zemanta.com": ("Outbrain", .ads), "revcontent.com": ("Revcontent", .ads), "mgid.com": ("MGID", .ads),
        "matomo.cloud": ("Matomo", .analytics), "plausible.io": ("Plausible", .analytics), "kissmetrics.com": ("Kissmetrics", .analytics),
        "crazyegg.com": ("Crazy Egg", .analytics), "mouseflow.com": ("Mouseflow", .analytics), "luckyorange.com": ("Lucky Orange", .analytics),
        "smartlook.com": ("Smartlook", .analytics), "logrocket.io": ("LogRocket", .analytics), "lr-ingest.io": ("LogRocket", .analytics),
        "pendo.io": ("Pendo", .analytics), "intercom.io": ("Intercom", .analytics), "customer.io": ("Customer.io", .analytics),
        "clevertap-prod.com": ("CleverTap", .analytics), "leanplum.com": ("Leanplum", .analytics), "airship.com": ("Airship", .analytics),
        "urbanairship.com": ("Airship", .analytics), "iterable.com": ("Iterable", .analytics), "rudderstack.com": ("RudderStack", .analytics),
        "split.io": ("Split", .telemetry), "optimizely.com": ("Optimizely", .analytics), "vwo.com": ("VWO", .analytics),
        "appcenter.ms": ("Microsoft", .telemetry), "in.appcenter.ms": ("Microsoft", .telemetry), "dc.services.visualstudio.com": ("Microsoft", .telemetry),
        "mobile.events.data.microsoft.com": ("Microsoft", .telemetry), "self.events.data.microsoft.com": ("Microsoft", .telemetry),
        "telemetry.mozilla.org": ("Mozilla", .telemetry), "incoming.telemetry.mozilla.org": ("Mozilla", .telemetry),
        "rollbar.com": ("Rollbar", .telemetry), "raygun.io": ("Raygun", .telemetry), "honeybadger.io": ("Honeybadger", .telemetry),
        "embrace.io": ("Embrace", .telemetry), "dynatrace.com": ("Dynatrace", .telemetry), "appdynamics.com": ("AppDynamics", .telemetry),
        "mopub.com": ("MoPub", .ads), "startappservice.com": ("Start.io", .ads), "tapjoy.com": ("Tapjoy", .ads),
        "fyber.com": ("Fyber", .ads), "mintegral.com": ("Mintegral", .ads), "pangle.io": ("Pangle", .ads), "bytedance.com": ("ByteDance", .analytics),
        "umeng.com": ("Umeng", .analytics), "umengcloud.com": ("Umeng", .analytics), "doubleclick.com": ("Google", .ads),
        "inmobi.com": ("InMobi", .ads), "vungle.com": ("Vungle", .ads), "ironsrc.mobi": ("ironSource", .ads),
    ]

    static func match(_ host: String?) -> Tracker? {
        guard var h = host?.lowercased(), !h.isEmpty else { return nil }
        while true {
            if let t = list[h] { return Tracker(company: t.0, kind: t.1) }
            guard let dot = h.firstIndex(of: ".") else { return nil }
            h = String(h[h.index(after: dot)...])
            if !h.contains(".") { return nil }
        }
    }
}

// MARK: - Sade dille açıklama

/// "Bu ne, normal mi, ne yapmalıyım?" — her paket ve konuşma için.
struct Explanation {
    enum Verdict { case ok, info, caution, danger
        var color: Color { [.ok: Color.green, .info: Color.blue, .caution: Color.orange, .danger: Color.red][self]! }
        var icon: String {
            [.ok: "checkmark.shield.fill", .info: "info.circle.fill", .caution: "exclamationmark.triangle.fill",
             .danger: "xmark.octagon.fill"][self]!
        }
        var label: String { L("verdict." + ["ok", "info", "caution", "danger"][[.ok, .info, .caution, .danger].firstIndex(of: self)!]) }
    }
    let verdict: Verdict
    let what: String
    let advice: String?
}

enum Explainer {
    static let badPorts: Set<Int> = [4444, 1337, 31337, 6667, 6666, 5555, 12345, 27374, 9001, 1080]

    /// İmzasız / geçici imzalı programlar: şifreli trafikleri "normal" sayılmaz.
    static func untrusted(_ sig: String?) -> Bool { sig == "unsigned" || sig == "adhoc" }

    static func packet(_ p: Packet, host: String?, app: String, signature: String? = nil) -> Explanation {
        let flags = p.flags ?? []
        let peer = host ?? p.dst
        if flags.contains("pkt.flag.cleartextCreds") {
            return .init(verdict: .danger, what: L("x.creds.what", app, peer), advice: L("x.creds.advice"))
        }
        if let t = Trackers.match(p.host ?? host) {
            return .init(verdict: .caution, what: L("x.tracker.what", app, t.company, t.kindText), advice: L("x.tracker.advice"))
        }
        if flags.contains("pkt.flag.cleartextHTTP") {
            return .init(verdict: .caution, what: L("x.http.what", app, peer), advice: L("x.http.advice"))
        }
        if flags.contains("pkt.flag.cleartextProto") {
            return .init(verdict: .caution, what: L("x.plain.what", p.proto), advice: L("x.plain.advice"))
        }
        let ports = [p.sport, p.dport].compactMap { $0 }
        if let bp = ports.first(where: badPorts.contains) {
            return .init(verdict: .caution, what: L("x.badport.what", String(bp)), advice: L("x.badport.advice"))
        }
        if p.dir == "in", p.tcp == "SYN" {
            return .init(verdict: .caution, what: L("x.inbound.what", p.src, String(p.dport ?? 0)), advice: L("x.inbound.advice"))
        }
        if untrusted(signature), ["TLS", "QUIC", "SSH"].contains(p.proto) || p.sport != nil {
            return .init(verdict: .caution, what: L("x.unsigned.what", app, peer), advice: L("x.unsigned.advice"))
        }
        switch p.proto {
        case "TLS":
            if p.info.hasPrefix("Client Hello") { return .init(verdict: .ok, what: L("x.tls.hello", app, peer), advice: nil) }
            return .init(verdict: .ok, what: L("x.encrypted", app, peer), advice: nil)
        case "QUIC":
            return .init(verdict: .ok, what: L("x.encrypted", app, peer), advice: nil)
        case "SSH":
            return .init(verdict: .info, what: L("x.ssh"), advice: L("x.ssh.advice"))
        case "DNS":
            if p.info.contains("NXDOMAIN") { return .init(verdict: .info, what: L("x.dns.nx", p.host ?? "?"), advice: L("x.dns.nx.advice")) }
            if p.dns != nil { return .init(verdict: .ok, what: L("x.dns.answer", p.host ?? "?"), advice: nil) }
            return .init(verdict: .ok, what: L("x.dns.query", app, p.host ?? "?"), advice: nil)
        case "mDNS", "SSDP", "LLMNR", "NetBIOS":
            return .init(verdict: .ok, what: L("x.local"), advice: nil)
        case "ARP":
            return .init(verdict: .ok, what: L("x.arp"), advice: nil)
        case "ICMP", "ICMPv6":
            return .init(verdict: .ok, what: L("x.icmp"), advice: nil)
        case "DHCP":
            return .init(verdict: .ok, what: L("x.dhcp"), advice: nil)
        case "NTP":
            return .init(verdict: .ok, what: L("x.ntp"), advice: nil)
        default:
            break
        }
        if p.tcp?.contains("RST") == true { return .init(verdict: .info, what: L("x.rst"), advice: nil) }
        if p.tcp == "SYN" { return .init(verdict: .ok, what: L("x.syn", app, peer, String(p.dport ?? 0)), advice: nil) }
        return .init(verdict: .info, what: L("x.generic", app, peer), advice: nil)
    }

    static func conversation(_ c: Conversation, signature: String? = nil) -> Explanation {
        let peer = c.host ?? c.remote
        if c.creds { return .init(verdict: .danger, what: L("x.creds.what", c.proc, peer), advice: L("x.creds.advice")) }
        if untrusted(signature) {
            return .init(verdict: .caution, what: L("x.unsigned.what", c.proc, peer), advice: L("x.unsigned.advice"))
        }
        if let t = Trackers.match(c.host) {
            return .init(verdict: .caution, what: L("x.tracker.what", c.proc, t.company, t.kindText), advice: L("x.tracker.advice"))
        }
        if c.uploadHeavy {
            return .init(verdict: .caution,
                         what: L("x.upload.what", c.proc, ByteCountFormatter.string(fromByteCount: Int64(c.bytesOut), countStyle: .file),
                                 peer, ByteCountFormatter.string(fromByteCount: Int64(c.bytesIn), countStyle: .file)),
                         advice: L("x.upload.advice"))
        }
        if !c.protos.isDisjoint(with: ["HTTP", "FTP", "Telnet", "POP3", "IMAP", "SMTP"]) {
            return .init(verdict: .caution, what: L("x.http.what", c.proc, peer), advice: L("x.http.advice"))
        }
        if !c.protos.isDisjoint(with: ["TLS", "QUIC", "SSH"]) {
            return .init(verdict: .ok, what: L("x.encrypted", c.proc, peer), advice: nil)
        }
        return .init(verdict: .info, what: L("x.generic", c.proc, peer), advice: nil)
    }
}

/// Açıklama kartı (paket ve konuşma ayrıntısında).
struct ExplanationCard: View {
    let e: Explanation

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: e.verdict.icon).foregroundStyle(e.verdict.color)
                Text(L("x.title")).font(.system(size: 12, weight: .bold))
                Spacer()
                Text(e.verdict.label).font(.system(size: 11, weight: .semibold)).foregroundStyle(e.verdict.color)
            }
            Text(e.what).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
            if let a = e.advice {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "lightbulb.fill").foregroundStyle(.yellow).font(.system(size: 11))
                    Text(a).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(12)
        .background(e.verdict.color.opacity(0.09), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(e.verdict.color.opacity(0.3)))
    }
}


/// Bir adın metinde ayrı bir kelime olarak geçip geçmediği ("todesk", "Autodesk" içinde eşleşmez).
enum WordMatch {
    static func matches(_ text: String, _ key: String) -> Bool {
        let t = text.lowercased(), k = key.lowercased()
        // Hızlı yol: alt dize hiç geçmiyorsa düzenli ifadeye gerek yok (çoğu durum).
        guard t.contains(k) else { return false }
        let pattern = "(?<![a-z0-9])" + NSRegularExpression.escapedPattern(for: k) + "(?![a-z0-9])"
        return t.range(of: pattern, options: .regularExpression) != nil
    }
}
