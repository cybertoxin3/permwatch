import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct VaultView: View {
    @ObservedObject var vault = Vault.shared

    var body: some View {
        Group {
            if !vault.exists { VaultSetupView() }
            else if !vault.unlocked { VaultLockedView() }
            else { VaultListView() }
        }
        .navigationTitle(L("nav.vault"))
    }
}

// MARK: - Kurulum

struct VaultSetupView: View {
    @ObservedObject var vault = Vault.shared
    @State private var p1 = ""
    @State private var p2 = ""
    @State private var error: String?

    var body: some View {
        VStack(spacing: 18) {
            BackBar(from: .vault)
            Spacer(minLength: 0)
            Image(systemName: "key.viewfinder").font(.system(size: 44)).foregroundStyle(Color.accentColor)
            Text(L("vault.setupTitle")).font(.system(size: 20, weight: .bold))
            Text(L("vault.setupBody")).font(.system(size: 13)).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 8) {
                SecureField(L("vault.master"), text: $p1).textFieldStyle(.roundedBorder)
                StrengthBar(password: p1)
                SecureField(L("vault.masterAgain"), text: $p2).textFieldStyle(.roundedBorder)
                    .onSubmit(create)
            }
            .frame(width: 340)
            if let e = error { Text(e).font(.system(size: 12)).foregroundStyle(.red) }
            Label(L("vault.noRecovery"), systemImage: "exclamationmark.triangle").font(.system(size: 12)).foregroundStyle(.orange)
                .frame(width: 380).fixedSize(horizontal: false, vertical: true)
            Button(L("vault.create"), action: create).buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(p1.isEmpty)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 40).padding(.vertical, 20).frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func create() {
        guard p1.count >= 10 else { error = L("vault.tooShort"); return }
        guard p1 == p2 else { error = L("vault.mismatch"); return }
        do { try vault.create(master: p1); p1 = ""; p2 = "" } catch { self.error = error.localizedDescription }
    }
}

// MARK: - Kilitli

struct VaultLockedView: View {
    @ObservedObject var vault = Vault.shared
    @State private var pw = ""
    @State private var wrong = false
    @State private var working = false

    var body: some View {
        VStack(spacing: 16) {
            BackBar(from: .vault)
            Spacer(minLength: 0)
            Image(systemName: "lock.fill").font(.system(size: 40)).foregroundStyle(.secondary)
            Text(L("vault.locked")).font(.system(size: 18, weight: .bold))
            SecureField(L("vault.master"), text: $pw).textFieldStyle(.roundedBorder).frame(width: 300)
                .onSubmit(unlock)
            if wrong { Text(L("vault.wrong")).font(.system(size: 12)).foregroundStyle(.red) }
            HStack {
                Button(L("vault.unlock"), action: unlock).buttonStyle(.borderedProminent).disabled(pw.isEmpty || working)
                if vault.touchID {
                    Button { vault.unlockWithTouchID { _ in } } label: { Label("Touch ID", systemImage: "touchid") }
                }
            }
            if working { ProgressView().controlSize(.small) }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 40).padding(.vertical, 20).frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { if vault.touchID { vault.unlockWithTouchID { _ in } } }
    }

    private func unlock() {
        working = true
        let p = pw
        // PBKDF2 (600 000 tur) ~0,3 sn: arayüzü dondurmamak için bir sonraki turda.
        DispatchQueue.main.async {
            wrong = !vault.unlock(master: p)
            working = false
            if !wrong { pw = "" }
        }
    }
}

// MARK: - Liste ve ayrıntı

struct VaultListView: View {
    @ObservedObject var vault = Vault.shared
    @State private var search = ""
    @State private var selection: String?
    @State private var editing: VaultItem?
    @State private var importResult: String?
    @State private var showSettings = false

    private var filtered: [VaultItem] {
        let q = search.lowercased()
        let list = vault.items.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        return q.isEmpty ? list : list.filter { $0.title.lowercased().contains(q) || $0.url.lowercased().contains(q) || $0.username.lowercased().contains(q) }
    }

    private var reused: Set<String> {
        var count: [String: Int] = [:]
        for i in vault.items { count[i.password, default: 0] += 1 }
        return Set(count.filter { $0.value > 1 }.keys)
    }

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    TextField(L("vault.search"), text: $search).textFieldStyle(.roundedBorder)
                    Button { editing = VaultItem(title: "", url: "", username: "", password: VaultCrypto.generate()) } label: { Image(systemName: "plus") }
                        .help(L("vault.add"))
                    Menu {
                        Button(L("vault.import")) { importCSV() }
                        Button(L("vault.settings")) { showSettings = true }
                        Divider()
                        Button(L("vault.lock")) { vault.lock() }
                    } label: { Image(systemName: "ellipsis.circle") }.menuIndicator(.hidden).fixedSize()
                }
                .padding(10)
                List(selection: $selection) {
                    ForEach(filtered) { i in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(i.title.isEmpty ? i.url : i.title).font(.system(size: 13, weight: .medium)).lineLimit(1)
                                Text(i.username).font(.system(size: 11.5)).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Spacer()
                            if reused.contains(i.password) || VaultCrypto.strength(i.password) < 50 {
                                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.system(size: 11))
                            }
                        }
                        .tag(i.id)
                    }
                }
                .listStyle(.inset)
                if vault.items.isEmpty {
                    Text(L("vault.empty")).font(.system(size: 12)).foregroundStyle(.secondary).padding()
                }
                if let r = importResult { Text(r).font(.system(size: 11.5)).foregroundStyle(.secondary).padding(8) }
            }
            .frame(width: 300)
            Divider()
            Group {
                if let id = selection, let it = vault.items.first(where: { $0.id == id }) {
                    VaultDetailView(item: it, reused: reused.contains(it.password)) { editing = it }
                } else {
                    VStack(spacing: 8) {
                        Image(systemName: "key").font(.system(size: 30)).foregroundStyle(.tertiary)
                        Text(L("vault.count", vault.items.count)).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(maxWidth: .infinity)
        }
        .sheet(item: $editing) { it in VaultEditView(item: it) { saved in if let s = saved { vault.save(s); selection = s.id }; editing = nil } }
        .sheet(isPresented: $showSettings) { VaultSettingsView { showSettings = false } }
    }

    private func importCSV() {
        let p = NSOpenPanel()
        p.allowedContentTypes = [.commaSeparatedText]
        guard p.runModal() == .OK, let u = p.url, let t = try? String(contentsOf: u, encoding: .utf8) else { return }
        let n = vault.importCSV(t)
        importResult = L("vault.imported", n)
    }
}

struct VaultDetailView: View {
    let item: VaultItem
    let reused: Bool
    let edit: () -> Void
    @ObservedObject var vault = Vault.shared
    @State private var reveal = false
    @State private var pwned: Int?
    @State private var checking = false
    @State private var confirmDelete = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text(item.title.isEmpty ? item.url : item.title).font(.system(size: 20, weight: .bold))
                    Spacer()
                    Button(L("vault.edit"), action: edit)
                }
                field(L("vault.username"), item.username, secret: false)
                field(L("vault.password"), item.password, secret: true)
                if !item.url.isEmpty {
                    HStack {
                        Text(L("vault.url")).font(.system(size: 12)).foregroundStyle(.secondary).frame(width: 90, alignment: .leading)
                        Text(item.url).font(.system(size: 13)).textSelection(.enabled).lineLimit(1)
                        Spacer()
                        if let u = URL(string: item.url.contains("://") ? item.url : "https://" + item.url) {
                            Button { NSWorkspace.shared.open(u) } label: { Image(systemName: "arrow.up.right.square") }.buttonStyle(.borderless)
                        }
                    }
                }
                if !item.notes.isEmpty {
                    Text(item.notes).font(.system(size: 12.5)).textSelection(.enabled)
                        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                }
                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    StrengthBar(password: item.password)
                    if reused { Label(L("vault.reused"), systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.system(size: 12)) }
                    HStack {
                        Button(L("vault.pwnedCheck")) {
                            checking = true
                            Task { pwned = await PwnedCheck.count(item.password); checking = false }
                        }
                        .controlSize(.small).disabled(checking)
                        if checking { ProgressView().controlSize(.small) }
                        if let n = pwned {
                            Text(n > 0 ? L("vault.pwned", n) : L("vault.notPwned")).font(.system(size: 12))
                                .foregroundStyle(n > 0 ? .red : .green)
                        }
                    }
                    Text(L("vault.pwnedHint")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 20)
                Button(L("vault.delete"), role: .destructive) { confirmDelete = true }.controlSize(.small)
            }
            .padding(24)
        }
        .onChange(of: item.id) { _, _ in reveal = false; pwned = nil }
        .confirmationDialog(L("vault.deleteTitle"), isPresented: $confirmDelete) {
            Button(L("vault.delete"), role: .destructive) { vault.delete(item) }
            Button(L("confirm.cancel"), role: .cancel) {}
        }
    }

    private func field(_ label: String, _ value: String, secret: Bool) -> some View {
        HStack {
            Text(label).font(.system(size: 12)).foregroundStyle(.secondary).frame(width: 90, alignment: .leading)
            Text(secret && !reveal ? String(repeating: "•", count: min(value.count, 16)) : value)
                .font(.system(size: 13, design: secret ? .monospaced : .default)).textSelection(.enabled).lineLimit(1)
            Spacer()
            if secret {
                Button { reveal.toggle(); vault.touch() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }.buttonStyle(.borderless)
            }
            Button { vault.copy(value) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless).help(L("vault.copyHint"))
        }
    }
}

struct VaultEditView: View {
    @State var item: VaultItem
    let done: (VaultItem?) -> Void
    @State private var length = 20.0

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(item.title.isEmpty ? L("vault.add") : item.title).font(.system(size: 16, weight: .bold))
            TextField(L("vault.title"), text: $item.title).textFieldStyle(.roundedBorder)
            TextField(L("vault.url"), text: $item.url).textFieldStyle(.roundedBorder)
            TextField(L("vault.username"), text: $item.username).textFieldStyle(.roundedBorder)
            HStack {
                TextField(L("vault.password"), text: $item.password).textFieldStyle(.roundedBorder).font(.system(size: 13, design: .monospaced))
                Button { item.password = VaultCrypto.generate(length: Int(length)) } label: { Image(systemName: "dice") }.help(L("vault.generate"))
            }
            HStack {
                Text(L("vault.length", Int(length))).font(.system(size: 11.5)).foregroundStyle(.secondary).frame(width: 90, alignment: .leading)
                Slider(value: $length, in: 12...40, step: 1)
            }
            StrengthBar(password: item.password)
            TextField(L("vault.notes"), text: $item.notes, axis: .vertical).lineLimit(3...6).textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button(L("confirm.cancel")) { done(nil) }.keyboardShortcut(.cancelAction)
                Button(L("vault.save")) { done(item) }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(item.password.isEmpty || (item.title.isEmpty && item.url.isEmpty))
            }
        }
        .padding(20).frame(width: 440)
    }
}

struct VaultSettingsView: View {
    let close: () -> Void
    @ObservedObject var vault = Vault.shared
    @State private var old = ""
    @State private var new1 = ""
    @State private var new2 = ""
    @State private var msg: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(L("vault.settings")).font(.system(size: 16, weight: .bold))
            Toggle(L("vault.touchID"), isOn: $vault.touchID)
            Text(L("vault.touchIDHint")).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Divider()
            Text(L("vault.changeMaster")).font(.system(size: 13, weight: .semibold))
            SecureField(L("vault.oldMaster"), text: $old).textFieldStyle(.roundedBorder)
            SecureField(L("vault.master"), text: $new1).textFieldStyle(.roundedBorder)
            StrengthBar(password: new1)
            SecureField(L("vault.masterAgain"), text: $new2).textFieldStyle(.roundedBorder)
            if let m = msg { Text(m).font(.system(size: 12)).foregroundStyle(.secondary) }
            HStack {
                Spacer()
                Button(L("vault.change")) {
                    guard new1.count >= 10 else { msg = L("vault.tooShort"); return }
                    guard new1 == new2 else { msg = L("vault.mismatch"); return }
                    msg = vault.changeMaster(old: old, new: new1) ? L("vault.changed") : L("vault.wrong")
                    if msg == L("vault.changed") { old = ""; new1 = ""; new2 = "" }
                }
                .disabled(old.isEmpty || new1.isEmpty)
                Button(L("sg.report.close"), action: close).keyboardShortcut(.cancelAction)
            }
        }
        .padding(20).frame(width: 400)
    }
}

struct StrengthBar: View {
    let password: String

    var body: some View {
        let bits = VaultCrypto.strength(password)
        let (label, color, frac): (String, Color, Double) =
            bits < 40 ? (L("vault.weak"), .red, 0.25) : bits < 60 ? (L("vault.fair"), .orange, 0.5) : bits < 80 ? (L("vault.good"), .yellow, 0.75) : (L("vault.strong"), .green, 1)
        HStack(spacing: 8) {
            GeometryReader { g in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.secondary.opacity(0.15))
                    Capsule().fill(color).frame(width: password.isEmpty ? 0 : g.size.width * frac)
                }
            }
            .frame(height: 5)
            Text(password.isEmpty ? "" : label).font(.system(size: 11)).foregroundStyle(.secondary).frame(width: 60, alignment: .leading)
        }
    }
}

/// Sol üstte "‹ Geri": bir önceki bölüme döner.
struct BackBar: View {
    let from: SidebarItem

    var body: some View {
        HStack {
            Button { ThreatCenter.shared.goBack(from: from) } label: {
                Label(L("nav.back"), systemImage: "chevron.left")
            }
            .buttonStyle(.borderless)
            .keyboardShortcut(.cancelAction)
            Spacer()
        }
    }
}
