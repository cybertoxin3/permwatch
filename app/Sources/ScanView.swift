import SwiftUI

/// Zararlı taraması: Apple'ın XProtect imzalarıyla hızlı/tam tarama, sonuçlar ve temizleme.
struct ScanView: View {
    @EnvironmentObject var scanner: MalwareScanner
    @ObservedObject private var quarantine = QuarantineStore.shared
    @ObservedObject private var realtime = RealtimeGuard.shared
    @State private var confirm: Detection?
    @State private var confirmDelete: QuarantineItem?
    @State private var qMessage: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                realtimeStatus
                ForEach(realtime.ransomAlerts) { ransomCard($0) }
                if scanner.running { progress }
                if let e = scanner.error {
                    Label(L("scan.error", e), systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                }
                if let m = scanner.message {
                    Label(m, systemImage: "checkmark.circle").foregroundStyle(.secondary)
                }
                if !scanner.detections.isEmpty {
                    ForEach(scanner.detections) { detectionCard($0) }
                } else if scanner.lastScan != nil && !scanner.running {
                    clean
                }
                quarantineSection
                xprotectSection
                about
            }
            .padding(24)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(L("nav.scan"))
        .onAppear { if Snapshot.section == "scanrun", !scanner.running { scanner.start(.quick) } }
        .confirmationDialog(confirm.map { L("scan.qTitle", $0.name) } ?? "",
                            isPresented: Binding(get: { confirm != nil }, set: { if !$0 { confirm = nil } })) {
            Button(L("scan.quarantine"), role: .destructive) { if let d = confirm { scanner.remove(d) }; confirm = nil }
            Button(L("confirm.cancel"), role: .cancel) { confirm = nil }
        } message: {
            Text(L("scan.qBody"))
        }
        .confirmationDialog(confirmDelete.map { L("q.deleteTitle", $0.name) } ?? "",
                            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })) {
            Button(L("q.delete"), role: .destructive) { if let q = confirmDelete { quarantine.delete(q) }; confirmDelete = nil }
            Button(L("confirm.cancel"), role: .cancel) { confirmDelete = nil }
        } message: {
            Text(L("q.deleteBody"))
        }
    }

    private var verdictColor: Color {
        if !scanner.detections.isEmpty { return .red }
        return scanner.lastScan == nil ? .secondary : .green
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 18) {
            Image(systemName: scanner.detections.isEmpty ? (scanner.lastScan == nil ? "shield" : "checkmark.shield.fill") : "xmark.shield.fill")
                .font(.system(size: 46)).foregroundStyle(verdictColor).frame(width: 60)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 20, weight: .bold))
                Text(subtitle).font(.system(size: 12.5)).foregroundStyle(.secondary)
            }
            Spacer()
            if scanner.running {
                Button(L("scan.cancel")) { scanner.cancel() }
            } else {
                VStack(alignment: .trailing, spacing: 6) {
                    Button { scanner.start(.quick) } label: { Label(L("scan.quick"), systemImage: "bolt.shield") }
                        .buttonStyle(.borderedProminent).controlSize(.large)
                    Button(L("scan.full")) { scanner.start(.full) }.controlSize(.small)
                }
            }
        }
    }

    private var title: String {
        if scanner.running { return L("scan.running") }
        if !scanner.detections.isEmpty { return L("scan.found", scanner.detections.count.formatted()) }
        return scanner.lastScan == nil ? L("scan.never") : L("scan.clean")
    }

    private var subtitle: String {
        var parts: [String] = []
        if let d = scanner.lastScan {
            parts.append(L("scan.last", Fmt.relative(d), scanner.lastScanned.formatted(),
                           scanner.lastKind == .full ? L("scan.fullShort") : L("scan.quickShort")))
        }
        if let v = scanner.signatureVersion { parts.append(L("scan.signatures", v)) }
        if YaraEngine.shared.extraCount > 0 { parts.append(L("scan.elastic", YaraEngine.shared.extraCount.formatted())) }
        return parts.joined(separator: " · ")
    }

    private var progress: some View {
        VStack(alignment: .leading, spacing: 6) {
            if scanner.progress < 0 { ProgressView().progressViewStyle(.linear) } else { ProgressView(value: scanner.progress) }
            HStack {
                Text(scanner.examined > 0 ? L("scan.progressFull", scanner.examined.formatted(), scanner.scanned.formatted())
                                          : L("scan.progress", scanner.scanned.formatted())).monospacedDigit()
                Spacer()
                Text(scanner.current).lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
            }
            .font(.system(size: 11.5))
        }
    }

    private var clean: some View {
        HStack(spacing: 12) {
            Image(systemName: "checkmark.seal.fill").foregroundStyle(.green).font(.system(size: 22))
            VStack(alignment: .leading, spacing: 3) {
                Text(L("scan.cleanTitle")).font(.system(size: 13, weight: .semibold))
                Text(L("scan.cleanBody", scanner.lastScanned.formatted())).font(.system(size: 12)).foregroundStyle(.secondary)
                if scanner.unreadable > 0 {
                    Text(L("scan.unreadable", scanner.unreadable.formatted())).font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }

    private func detectionCard(_ d: Detection) -> some View {
        HStack(alignment: .top, spacing: 14) {
            AppIcon(name: d.name, risk: .high, key: PathUtil.appBundle(d.path) ?? d.path, size: 40)
            VStack(alignment: .leading, spacing: 5) {
                Text(d.name).font(.system(size: 15, weight: .bold)).foregroundStyle(.red)
                Text(PathUtil.abbreviate(d.path)).font(.system(size: 11.5, design: .monospaced)).textSelection(.enabled)
                    .lineLimit(2).truncationMode(.middle)
                Text(L("scan.detectionBody")).font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !d.launchItems.isEmpty {
                    Text(L("scan.launchItems", d.launchItems.map(PathUtil.abbreviate).joined(separator: ", ")))
                        .font(.system(size: 11.5)).foregroundStyle(.orange)
                }
                HStack(spacing: 8) {
                    Button(L("scan.quarantine")) { confirm = d }.buttonStyle(.borderedProminent).tint(.red)
                    Button(L("action.showInFinder")) { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: d.path)]) }
                    Button(L("action.virustotal")) { Lookup.virusTotal(path: d.path) }
                }
                .controlSize(.small)
                .padding(.top, 2)
                Text("\(L("scan.rule")): \(d.rule)").font(.system(size: 10.5)).foregroundStyle(.tertiary)
            }
        }
        .padding(16)
        .background(Color.red.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.red.opacity(0.35)))
    }

    private var realtimeStatus: some View {
        HStack(spacing: 8) {
            Circle().fill(realtime.watching.isEmpty ? Color.secondary : Color.green).frame(width: 8, height: 8)
            Text(realtime.watching.isEmpty ? L("rt.off")
                 : L("rt.on", realtime.watching.count.formatted(), realtime.scannedCount.formatted()))
                .font(.system(size: 12))
            Spacer()
            if !FullDisk.granted && !realtime.watching.isEmpty {
                Button(L("rt.needsFDA")) { FullDisk.openSettings() }.controlSize(.small)
            }
        }
        .padding(10)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
    }

    private func ransomCard(_ a: RansomAlert) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(L("ransom.title"), systemImage: "lock.trianglebadge.exclamationmark.fill")
                .font(.system(size: 15, weight: .bold)).foregroundStyle(.red)
            Text(a.suspended ? L("ransom.detailSuspended", a.name, a.files.formatted()) : L("ransom.detail", a.name, a.files.formatted()))
                .font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
            Text(L("ransom.explain")).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ForEach(a.examples, id: \.self) { Text(PathUtil.abbreviate($0)).font(.system(size: 11, design: .monospaced)).lineLimit(1) }
            HStack(spacing: 8) {
                Button(L("ransom.terminate")) { realtime.terminate(a) }.buttonStyle(.borderedProminent).tint(.red)
                if a.suspended { Button(L("ransom.resume")) { realtime.resume(a) } }
                if let p = a.path { Button(L("action.showInFinder")) { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: p)]) } }
                Button(L("threat.dismiss")) { realtime.dismiss(a) }
            }
            .controlSize(.small)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.red.opacity(0.35)))
    }

    @ViewBuilder private var quarantineSection: some View {
        if !quarantine.items.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Text(L("q.title", quarantine.items.count.formatted())).font(.system(size: 12, weight: .semibold))
                Text(L("q.explain")).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if let m = qMessage { Text(m).font(.system(size: 11.5)).foregroundStyle(.orange) }
                ForEach(quarantine.items) { q in
                    HStack(spacing: 10) {
                        Image(systemName: "lock.doc.fill").foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(q.name).font(.system(size: 12.5, weight: .semibold))
                            Text(q.files.keys.sorted().map(PathUtil.abbreviate).joined(separator: ", "))
                                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
                            Text(Fmt.relative(q.date)).font(.system(size: 10.5)).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        Button(L("q.restore")) { qMessage = quarantine.restore(q) }
                        Button(L("q.delete")) { confirmDelete = q }
                    }
                    .controlSize(.small)
                    .padding(10)
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                }
            }
        }
    }

    /// Apple'ın kendi arka plan taramalarının (XProtect Remediator) kayıtları; yalnızca yönetici modunda okunabilir.
    private var xprotectSection: some View {
        let lines = (RootBridge.shared.data?.xprotectLog ?? "").split(separator: "\n").map(String.init)
        return VStack(alignment: .leading, spacing: 6) {
            Text(L("scan.xpTitle")).font(.system(size: 12, weight: .semibold))
            if !RootBridge.shared.active {
                Text(L("scan.xpNeedsRoot")).font(.system(size: 11.5)).foregroundStyle(.secondary)
            } else if lines.isEmpty {
                Text(L("scan.xpNone")).font(.system(size: 11.5)).foregroundStyle(.secondary)
            } else {
                Text(L("scan.xpFound", lines.count.formatted())).font(.system(size: 11.5)).foregroundStyle(.orange)
                ScrollView(.horizontal) {
                    Text(lines.suffix(30).joined(separator: "\n")).font(.system(size: 10.5, design: .monospaced)).textSelection(.enabled)
                }
                .frame(maxHeight: 180)
            }
        }
        .padding(.top, 6)
    }

    private var about: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(L("scan.aboutTitle")).font(.system(size: 12, weight: .semibold))
            Text(L("scan.about")).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(.top, 8)
    }
}
