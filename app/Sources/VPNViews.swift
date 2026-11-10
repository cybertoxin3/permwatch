import AppKit
import CoreImage.CIFilterBuiltins
import SwiftUI

struct VPNView: View {
    @ObservedObject var vpn = VPNManager.shared
    @ObservedObject var root = RootBridge.shared
    @State private var link = ""
    @State private var addError: String?
    @State private var addedCount: Int?
    @State private var showBuy = false
    @State private var confirmDelete: VPNProfile?

    private var current: VPNProfile? { vpn.profiles.first { $0.id == (vpn.connectedID ?? vpn.selected) } }

    var scrollable = true

    var body: some View {
        Group {
            if scrollable { ScrollView { content } } else { content }
        }
        .navigationTitle(L("nav.vpn"))
        .sheet(isPresented: $showBuy) { VPNBuyView { showBuy = false } }
        .confirmationDialog(L("vpn.deleteTitle"), isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })) {
            Button(L("vault.delete"), role: .destructive) { if let p = confirmDelete { vpn.remove(p) }; confirmDelete = nil }
            Button(L("confirm.cancel"), role: .cancel) { confirmDelete = nil }
        }
    }

    private var content: some View {
            VStack(alignment: .leading, spacing: 18) {
                statusCard
                if !vpn.enginesBundled {
                    Label(L("vpn.noEngine"), systemImage: "exclamationmark.triangle").font(.system(size: 12)).foregroundStyle(.orange)
                }
                profilesCard
                addCard
                planCard
            }
            .padding(24)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity)
    }

    // MARK: Durum

    private var statusCard: some View {
        let on = vpn.state == .connected
        return HStack(spacing: 18) {
            ZStack {
                Circle().fill((on ? Color.green : Color.secondary).opacity(0.15)).frame(width: 74, height: 74)
                Image(systemName: on ? "lock.shield.fill" : "shield.slash").font(.system(size: 30)).foregroundStyle(on ? .green : .secondary)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(stateTitle).font(.system(size: 20, weight: .bold))
                if let p = current { Text("\(p.name) · \(p.kindLabel)").font(.system(size: 13)).foregroundStyle(.secondary) }
                if on, let s = vpn.since {
                    Text("\(Fmt.relative(s)) · ↓ \(bytes(vpn.rx)) ↑ \(bytes(vpn.tx))").font(.system(size: 12)).foregroundStyle(.secondary).monospacedDigit()
                }
                if vpn.state == .error, let e = vpn.error { Text(e).font(.system(size: 12)).foregroundStyle(.red).lineLimit(2) }
                if vpn.connectedID != nil, !root.active { Text(L("vpn.needAdmin")).font(.system(size: 12)).foregroundStyle(.orange) }
            }
            Spacer()
            if vpn.connectedID != nil {
                Button(L("vpn.disconnect")) { vpn.disconnect() }.controlSize(.large)
            } else {
                Button(L("vpn.connect")) { if let p = current { vpn.connect(p) } }
                    .buttonStyle(.borderedProminent).controlSize(.large).disabled(current == nil || !vpn.enginesBundled)
            }
        }
        .padding(18)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14))
    }

    private var stateTitle: String {
        switch vpn.state {
        case .connected: return L("vpn.connected")
        case .connecting: return L("vpn.connecting")
        case .error: return L("vpn.error")
        case .off: return L("vpn.off")
        }
    }

    private func bytes(_ n: Int) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) }

    // MARK: Profiller

    private var profilesCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("vpn.profiles")).font(.system(size: 14, weight: .bold))
            if vpn.profiles.isEmpty {
                Text(L("vpn.noProfiles")).font(.system(size: 12.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            ForEach(vpn.profiles) { p in
                HStack(spacing: 10) {
                    Image(systemName: vpn.selected == p.id ? "largecircle.fill.circle" : "circle")
                        .foregroundStyle(vpn.selected == p.id ? Color.accentColor : .secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(p.name).font(.system(size: 13, weight: .semibold))
                        Text("\(p.kindLabel) · \(p.server) · \(L(p.source == .paid ? "vpn.paid" : "vpn.own"))")
                            .font(.system(size: 11.5)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if vpn.connectedID == p.id, vpn.state == .connected {
                        Label(L("vpn.connected"), systemImage: "checkmark").font(.system(size: 11.5)).foregroundStyle(.green)
                    }
                    Button { confirmDelete = p } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                }
                .contentShape(Rectangle())
                .onTapGesture {
                    vpn.selected = p.id
                    if vpn.connectedID != nil, vpn.connectedID != p.id { vpn.connect(p) }
                }
                .padding(.vertical, 4)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    private var addCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("vpn.addTitle")).font(.system(size: 14, weight: .bold))
            Text(L("vpn.addHint")).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                TextField("vpn://…  ·  vless://…  ·  [Interface]…", text: $link).textFieldStyle(.roundedBorder)
                Button(L("vpn.paste")) { link = NSPasteboard.general.string(forType: .string) ?? link }
                Button(L("vpn.add")) {
                    do {
                        addedCount = try vpn.add(link: link, paid: link.lowercased().hasPrefix("vpn://") && !ownServerHint)
                        addError = nil; link = ""
                    } catch { addError = L("vpn.badLink"); addedCount = nil }
                }
                .buttonStyle(.borderedProminent).disabled(link.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            Toggle(L("vpn.ownServer"), isOn: $ownServerHint).font(.system(size: 12)).toggleStyle(.checkbox)
            if let e = addError { Text(e).font(.system(size: 12)).foregroundStyle(.red) }
            if let n = addedCount { Text(L("vpn.added", n)).font(.system(size: 12)).foregroundStyle(.green) }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }
    @State private var ownServerHint = false

    private var planCard: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "globe.europe.africa.fill").font(.system(size: 30)).foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 6) {
                Text(L("vpn.planTitle", VPNPlan.priceUSD)).font(.system(size: 15, weight: .bold))
                Text(L("vpn.planBody")).font(.system(size: 12.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Text(L("vpn.freeOwn")).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Button(L("vpn.buy")) { showBuy = true }.buttonStyle(.borderedProminent).padding(.top, 4)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Satın alma

struct VPNBuyView: View {
    let close: () -> Void
    @State private var coin = 0
    @State private var tx = ""
    @State private var contact = ""
    @State private var copied: String?
    @State private var sent = false
    @State private var prices: [String: Decimal] = [:]
    @State private var updated: Date?
    @State private var loading = false
    @State private var failed = false
    private let refresh = Timer.publish(every: 60, on: .main, in: .common).autoconnect()

    private var c: VPNPlan.Coin { VPNPlan.coins[coin] }
    private var contactOK: Bool { contact.contains("@") && contact.contains(".") || contact.hasPrefix("@") && contact.count > 3 }
    /// Coinin dolar fiyatı (sabit paralar 1).
    private var price: Decimal? { c.geckoID.map { prices[$0] } ?? 1 }
    private var amount: Decimal? { price.map { VPNPlan.amount(for: c, usdPrice: $0) } }
    private var amountText: String? { amount.map { VPNPlan.format($0, decimals: c.decimals) } }
    private var rateText: String {
        guard let p = price else { return "" }
        return "1 \(c.symbol) = \(VPNPlan.format(p, decimals: 2)) $"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(L("vpn.buyTitle", VPNPlan.priceUSD)).font(.system(size: 17, weight: .bold))
            Text(L("vpn.buyStep1")).font(.system(size: 13, weight: .semibold))
            Picker("", selection: $coin) {
                ForEach(VPNPlan.coins.indices, id: \.self) { i in Text("\(VPNPlan.coins[i].name) · \(VPNPlan.coins[i].network)").tag(i) }
            }
            .labelsHidden()
            if let amt = amount, let amtText = amountText {
                HStack(alignment: .top, spacing: 14) {
                    if let img = qr(VPNPlan.paymentURI(c, amount: amt)) {
                        Image(nsImage: img).interpolation(.none).resizable().frame(width: 140, height: 140)
                            .background(Color.white).clipShape(RoundedRectangle(cornerRadius: 6))
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Text(L("vpn.sendAmount")).font(.system(size: 11.5)).foregroundStyle(.secondary)
                        HStack(spacing: 8) {
                            Text("\(amtText) \(c.symbol)").font(.system(size: 20, weight: .bold, design: .monospaced)).textSelection(.enabled)
                            Button(copied == "amount" ? L("vpn.copied") : L("vpn.copyAmount")) { copy(amtText, "amount") }.controlSize(.small)
                        }
                        if c.geckoID != nil {
                            Text(L("vpn.rate", rateText, updated.map { Fmt.relative($0) } ?? "")).font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Text(c.address).font(.system(size: 11.5, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        Button(copied == "address" ? L("vpn.copied") : L("vpn.copyAddress")) { copy(c.address, "address") }.controlSize(.small)
                        Text(L("vpn.networkWarn", c.network)).font(.system(size: 11.5)).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Text(L("vpn.qrHint")).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } else if failed || (!prices.isEmpty && price == nil) {
                HStack {
                    Label(L("vpn.rateFailed"), systemImage: "wifi.exclamationmark").font(.system(size: 12)).foregroundStyle(.orange)
                    Button(L("vpn.retry")) { load() }.controlSize(.small)
                }
            } else {
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text(L("vpn.rateLoading")).font(.system(size: 12)).foregroundStyle(.secondary) }
            }
            Divider()
            Text(L("vpn.buyStep2")).font(.system(size: 13, weight: .semibold))
            TextField(L("vpn.txField"), text: $tx).textFieldStyle(.roundedBorder).font(.system(size: 12, design: .monospaced))
            if !tx.isEmpty, !VPNPlan.validTx(tx) { Text(L("vpn.txBad")).font(.system(size: 11.5)).foregroundStyle(.orange) }
            TextField(L("vpn.contactField"), text: $contact).textFieldStyle(.roundedBorder)
            Text(L("vpn.buyStep3")).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if sent { Label(L("vpn.sent"), systemImage: "checkmark.circle.fill").font(.system(size: 12)).foregroundStyle(.green) }
            HStack {
                Spacer()
                Button(L("confirm.cancel"), action: close).keyboardShortcut(.cancelAction)
                Button(L("vpn.notify")) {
                    VPNPlan.notify(coin: c.name, network: c.network, tx: tx.trimmingCharacters(in: .whitespaces), contact: contact,
                                   amount: "\(amountText ?? "?") \(c.symbol)", rate: rateText + (updated.map { " @ \($0.formatted(.iso8601))" } ?? ""))
                    sent = true
                }
                .buttonStyle(.borderedProminent).disabled(!VPNPlan.validTx(tx) || !contactOK || amount == nil)
            }
        }
        .padding(22).frame(width: 540)
        .onAppear(perform: load)
        .onReceive(refresh) { _ in load() }
        .onChange(of: coin) { _, _ in copied = nil }
    }

    private func load() {
        guard !loading else { return }
        loading = true
        Task {
            let p = await VPNPlan.fetchPrices()
            await MainActor.run {
                loading = false
                if let p { prices = p; updated = Date(); failed = false } else { failed = prices.isEmpty }
            }
        }
    }

    private func copy(_ s: String, _ what: String) {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(s, forType: .string); copied = what
    }

    private func qr(_ s: String) -> NSImage? {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(s.utf8)
        f.correctionLevel = "M"
        guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: 6, y: 6)) else { return nil }
        let rep = NSCIImageRep(ciImage: out)
        let img = NSImage(size: rep.size)
        img.addRepresentation(rep)
        return img
    }
}
