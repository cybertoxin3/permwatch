// Kare bir resimden macOS uygulama ikonu (1024×1024 PNG) üretir: Apple'ın ikon ızgarasına göre
// 824×824 yuvarlatılmış kare, kenar boşluğu ve hafif gölge.
// Kullanım: swift app/tools/make_icon.swift <kaynak.png> <çıktı.png>
import AppKit
import CoreGraphics

let args = CommandLine.arguments
guard args.count == 3, let src = NSImage(contentsOfFile: args[1]),
      let cg = src.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    FileHandle.standardError.write(Data("kullanım: make_icon.swift <kaynak> <çıktı.png>\n".utf8))
    exit(64)
}

let size = 1024
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
let radius: CGFloat = 185
let space = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
let shape = CGPath(roundedRect: body, cornerWidth: radius, cornerHeight: radius, transform: nil)

// Gölge
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: CGColor(gray: 0, alpha: 0.32))
ctx.addPath(shape)
ctx.setFillColor(CGColor(gray: 1, alpha: 1))
ctx.fillPath()
ctx.restoreGState()

// Resim: kare kırpılmış, gövdeyi dolduracak biçimde
ctx.saveGState()
ctx.addPath(shape)
ctx.clip()
let side = min(cg.width, cg.height)
let crop = cg.cropping(to: CGRect(x: (cg.width - side) / 2, y: (cg.height - side) / 2, width: side, height: side))!
ctx.interpolationQuality = .high
ctx.draw(crop, in: body)
// İnce iç kenar çizgisi (açık zeminde ikonun sınırı belli olsun)
ctx.addPath(shape)
ctx.setStrokeColor(CGColor(gray: 0, alpha: 0.08))
ctx.setLineWidth(2)
ctx.strokePath()
ctx.restoreGState()

let out = ctx.makeImage()!
let rep = NSBitmapImageRep(cgImage: out)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: args[2]))
print("hazır: \(args[2])")
