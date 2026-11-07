import SwiftUI

struct RiskTag: View {
    let text: String
    let color: Color

    init(_ risk: Risk, trusted: Bool = false) {
        text = trusted ? L("tag.trusted") : risk.label
        color = trusted ? .green : risk.color
    }

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(color)
            .background(color.opacity(0.13), in: RoundedRectangle(cornerRadius: 5))
            .fixedSize()
    }
}

struct AppIcon: View {
    let name: String
    let risk: Risk
    var key: String? = nil
    var size: CGFloat = 30

    var body: some View {
        if let key, let img = IconCache.icon(for: key) {
            Image(nsImage: img)
                .resizable()
                .interpolation(.high)
                .frame(width: size, height: size)
                .overlay(alignment: .topTrailing) {
                    if risk >= .caution {
                        Circle().fill(risk.color)
                            .frame(width: size * 0.32, height: size * 0.32)
                            .overlay(Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 1.5))
                            .offset(x: size * 0.06, y: -size * 0.06)
                    }
                }
        } else {
            letterTile
        }
    }

    private var letterTile: some View {
        RoundedRectangle(cornerRadius: size * 0.27)
            .fill(color)
            .frame(width: size, height: size)
            .overlay(
                Text(String(name.prefix(1)).uppercased(with: .current))
                    .font(.system(size: size * 0.47, weight: .bold))
                    .foregroundStyle(.white)
            )
    }

    private var color: Color {
        switch risk {
        case .high: return .red
        case .caution: return .orange
        case .normal:
            let palette: [Color] = [.blue, .indigo, .purple, .teal, .gray, .brown, .cyan, .mint]
            let h = name.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) & 0xffff }
            return palette[h % palette.count]
        }
    }
}

struct Chip: View {
    let title: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 12, weight: selected ? .semibold : .regular))
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .foregroundStyle(selected ? Color(nsColor: .windowBackgroundColor) : .primary)
                .background(
                    Capsule().fill(selected ? Color.primary : Color.clear)
                )
                .overlay(Capsule().strokeBorder(selected ? Color.clear : Color.secondary.opacity(0.3)))
        }
        .buttonStyle(.plain)
    }
}

struct Pill: View {
    let text: String
    let systemImage: String
    var tint: Color = .blue
    var neutral = false

    var body: some View {
        Label(text, systemImage: systemImage)
            .font(.system(size: 12))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .foregroundStyle(neutral ? Color.primary : tint)
            .background((neutral ? Color.secondary : tint).opacity(0.1), in: RoundedRectangle(cornerRadius: 7))
    }
}

enum Icons {
    static func service(_ s: String) -> String {
        switch s {
        case "kTCCServiceMicrophone": return "mic"
        case "kTCCServiceCamera": return "video"
        case "kTCCServiceScreenCapture": return "rectangle.dashed.badge.record"
        case "kTCCServiceAccessibility", "kTCCServicePostEvent": return "accessibility"
        case "kTCCServiceSystemPolicyAllFiles": return "internaldrive"
        case "kTCCServiceSystemPolicyDocumentsFolder", "kTCCServiceSystemPolicyDesktopFolder",
             "kTCCServiceSystemPolicyDownloadsFolder": return "folder"
        case "kTCCServiceListenEvent": return "keyboard"
        default: return "lock"
        }
    }
}

/// Satırlara sığmayan butonları alt satıra kaydırır.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0, maxX: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x > 0 && x + s.width > width { x = 0; y += rowH + spacing; rowH = 0 }
            x += s.width + spacing
            maxX = max(maxX, x - spacing)
            rowH = max(rowH, s.height)
        }
        return CGSize(width: maxX, height: y + rowH)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowH: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x > bounds.minX && x + s.width > bounds.maxX { x = bounds.minX; y += rowH + spacing; rowH = 0 }
            v.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(s))
            x += s.width + spacing
            rowH = max(rowH, s.height)
        }
    }
}
