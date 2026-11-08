import SwiftUI

/// Genel Bakış'ın en üstündeki güncelleme kartı: yeni sürümün notları, "Güncelle", yüzdeli indirme,
/// kurulum. İndirme Sparkle'da sürdüğü için kullanıcı başka bölüme geçse de devam eder.
struct UpdateCard: View {
    @EnvironmentObject var updates: UpdateChecker

    var body: some View {
        Group {
            switch updates.phase {
            case .available: available
            case .downloading, .extracting: downloading
            case .ready: ready
            case .installing: simple(icon: "gearshape.arrow.triangle.2.circlepath", text: L("upd.installing"), progress: true)
            case .failed(let msg):
                VStack(alignment: .leading, spacing: 8) {
                    Label(L("upd.failed", msg), systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                        .font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
                    Button(L("upd.retry")) { updates.checkNow() }.controlSize(.small)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
            default: EmptyView()
            }
        }
        .animation(.default, value: updates.phase)
    }

    private var meta: String {
        var parts = [L("upd.current", UpdateChecker.current)]
        if updates.size > 0 { parts.append(ByteCountFormatter.string(fromByteCount: updates.size, countStyle: .file)) }
        if let d = updates.releaseDate { parts.append(d.formatted(date: .abbreviated, time: .omitted)) }
        return parts.joined(separator: " · ")
    }

    private var available: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "arrow.down.app.fill").font(.system(size: 34)).foregroundStyle(Color.accentColor)
                VStack(alignment: .leading, spacing: 3) {
                    Text(L("upd.cardTitle", updates.latest ?? "")).font(.system(size: 17, weight: .bold))
                    Text(meta).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
            }
            if let n = updates.notes, !n.isEmpty {
                Text(L("upd.notesTitle")).font(.system(size: 12, weight: .semibold))
                ScrollView {
                    Text(Self.markdown(n)).font(.system(size: 12.5)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 180)
            }
            HStack(spacing: 10) {
                Button { updates.install() } label: { Label(L("upd.update"), systemImage: "arrow.down.circle") }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                if updates.usesSparkle {
                    Button(L("upd.later")) { updates.later() }
                    Button(L("upd.skip")) { updates.skip() }.buttonStyle(.link).font(.system(size: 12))
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.accentColor.opacity(0.3)))
    }

    private var downloading: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(L("upd.cardTitle", updates.latest ?? "")).font(.system(size: 14, weight: .semibold))
                Spacer()
                if updates.phase == .downloading { Button(L("upd.cancel")) { updates.cancel() }.controlSize(.small) }
            }
            if updates.phase == .extracting {
                ProgressView(value: updates.extractProgress)
                Text(L("upd.extracting")).font(.system(size: 12)).foregroundStyle(.secondary)
            } else if let f = updates.downloadFraction {
                ProgressView(value: f)
                Text(L("upd.downloading", f.formatted(.percent.precision(.fractionLength(0))),
                       ByteCountFormatter.string(fromByteCount: updates.received, countStyle: .file),
                       ByteCountFormatter.string(fromByteCount: updates.expected, countStyle: .file)))
                    .font(.system(size: 12).monospacedDigit())
            } else {
                ProgressView().progressViewStyle(.linear)
                Text(L("upd.starting")).font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Text(L("upd.background")).font(.system(size: 11)).foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }

    private var ready: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(L("upd.readyTitle", updates.latest ?? ""), systemImage: "checkmark.circle.fill")
                .font(.system(size: 15, weight: .bold)).foregroundStyle(.green)
            Text(L("upd.readyBody")).font(.system(size: 12.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 10) {
                Button(L("upd.relaunch")) { updates.relaunch() }.buttonStyle(.borderedProminent).controlSize(.large)
                Button(L("upd.onQuit")) { updates.installOnQuit() }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }

    private func simple(icon: String, text: String, progress: Bool) -> some View {
        HStack(spacing: 10) {
            if progress { ProgressView().controlSize(.small) } else { Image(systemName: icon) }
            Text(text).font(.system(size: 13))
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    static func markdown(_ s: String) -> AttributedString {
        (try? AttributedString(markdown: s, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))) ?? AttributedString(s)
    }
}

/// Kenar çubuğunun altında: indirme sürerken yüzde, hazır olunca "Güncelleme hazır". Tıklayınca Genel Bakış.
struct UpdateSidebarStatus: View {
    @EnvironmentObject var updates: UpdateChecker
    var open: () -> Void

    var body: some View {
        switch updates.phase {
        case .downloading, .extracting:
            Button(action: open) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(L("upd.sidebarDownloading", (updates.downloadFraction ?? 0).formatted(.percent.precision(.fractionLength(0)))))
                        .font(.system(size: 11)).monospacedDigit()
                    if let f = updates.downloadFraction { ProgressView(value: f).controlSize(.mini) }
                    else { ProgressView().progressViewStyle(.linear).controlSize(.mini) }
                }
            }
            .buttonStyle(.plain)
        case .available:
            Button(action: open) {
                Label(L("upd.cardTitle", updates.latest ?? ""), systemImage: "arrow.down.app").font(.system(size: 11))
            }
            .buttonStyle(.plain).foregroundStyle(Color.accentColor)
        case .ready:
            Button(action: open) { Label(L("upd.sidebarReady"), systemImage: "checkmark.circle").font(.system(size: 11)) }
                .buttonStyle(.plain).foregroundStyle(.green)
        default:
            EmptyView()
        }
    }
}
