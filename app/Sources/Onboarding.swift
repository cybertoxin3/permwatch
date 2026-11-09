import SwiftUI

/// İlk açılış: üç adım. Ne yapar → Tam Disk Erişimi (nedeniyle) → "Mac'imi kontrol et".
/// Yönetici modu burada istenmez; gerektiğinde ilgili ekranda açıklanarak sorulur.
struct OnboardingView: View {
    static let doneKey = "onboardingDone"

    @EnvironmentObject var store: Store
    @EnvironmentObject var checks: SecurityChecks
    @EnvironmentObject var scanner: MalwareScanner
    @Binding var isPresented: Bool
    var onFinish: () -> Void

    @State private var step = 0
    @State private var fda = FullDisk.granted
    @State private var startAtLogin = true
    private let timer = Timer.publish(every: 1.5, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                ForEach(0..<3) { i in
                    Capsule().fill(i <= step ? Color.accentColor : Color.secondary.opacity(0.25)).frame(height: 4)
                }
            }
            .padding(.bottom, 26)

            Group {
                switch step {
                case 0: welcome
                case 1: fullDisk
                default: check
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            HStack {
                if step > 0 { Button(L("onb.back")) { step -= 1 } }
                Spacer()
                if step == 1 && !fda { Button(L("onb.later")) { step = 2 } }
                Button(primaryTitle) { primary() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
            .controlSize(.large)
        }
        .padding(32)
        .frame(width: 560, height: 480)
        .onReceive(timer) { _ in
            if !fda && FullDisk.granted { fda = true; store.useSystem() }
        }
    }

    private var primaryTitle: String {
        switch step {
        case 0: return L("onb.start")
        case 1: return fda ? L("onb.next") : L("fda.open")
        default: return L("onb.checkNow")
        }
    }

    private func primary() {
        switch step {
        case 0: step = 1
        case 1: if fda { step = 2 } else { FullDisk.openSettings() }
        default: finish(check: true)
        }
    }

    private func finish(check: Bool) {
        UserDefaults.standard.set(true, forKey: Self.doneKey)
        UserDefaults.standard.set(true, forKey: LoginLaunch.askedKey)
        if startAtLogin && !LoginLaunch.isEnabled { LoginLaunch.set(true) }
        if check {
            let root = RootBridge.shared.active ? RootBridge.shared.data : nil
            checks.run(apps: store.apps, rootProfiles: root?.profiles, rootLsof: root?.lsof)
            scanner.start(.quick)
        }
        isPresented = false
        onFinish()
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 14) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 56, height: 56)
                Text(L("onb.title")).font(.system(size: 24, weight: .bold))
            }
            Text(L("onb.lead")).font(.system(size: 14)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            point("ladybug", L("onb.p1"))
            point("person.badge.shield.checkmark", L("onb.p2"))
            point("hand.raised", L("onb.p3"))
            point("lock", L("onb.privacy"))
        }
    }

    private var fullDisk: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("onb.fdaTitle")).font(.system(size: 22, weight: .bold))
            Text(L("onb.fdaBody")).font(.system(size: 14)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if fda {
                Label(L("onb.fdaDone"), systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.system(size: 14, weight: .semibold))
            } else {
                Text(L("onb.fdaSteps")).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
                    .padding(12)
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }

    private var check: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("onb.checkTitle")).font(.system(size: 22, weight: .bold))
            Text(L("onb.checkBody")).font(.system(size: 14)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 4) {
                Toggle(L("login.setting"), isOn: $startAtLogin).font(.system(size: 13.5, weight: .medium))
                Text(L("login.settingDesc")).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, 20)
            }
            .padding(12)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            Button(L("onb.skip")) { finish(check: false) }.buttonStyle(.link)
        }
    }

    private func point(_ icon: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).font(.system(size: 17)).foregroundStyle(Color.accentColor).frame(width: 24)
            Text(text).font(.system(size: 13.5)).fixedSize(horizontal: false, vertical: true)
        }
    }
}
