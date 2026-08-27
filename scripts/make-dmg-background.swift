// Draws the background art for the macOS .dmg, at 1x and 2x.
//
// Run it through scripts/make-dmg-background.sh, which combines the two PNGs
// into the multi-resolution TIFF that Finder actually wants. The output is
// committed, because the release build has to be able to produce a themed dmg
// without a toolchain for redrawing it.
//
// CoreGraphics and CoreText rather than AppKit: this draws into a bitmap with
// no window server involved, which is the difference between working over ssh
// and failing there.

import CoreGraphics
import CoreText
import Foundation
import ImageIO
import UniformTypeIdentifiers

// The dmg window, and where tauri.macos.conf.json puts the two icons in it.
// Everything below is laid out against these — change one and change both.
let W: CGFloat = 660
let H: CGFloat = 400
let appIcon = CGPoint(x: 180, y: 170)   // top-left origin, as in the config
let folderIcon = CGPoint(x: 480, y: 170)

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(
        red: CGFloat((hex >> 16) & 0xff) / 255,
        green: CGFloat((hex >> 8) & 0xff) / 255,
        blue: CGFloat(hex & 0xff) / 255,
        alpha: a)
}

// The app's own palette (ui/index.html :root), so the dmg and the window it
// installs do not look like two different products.
let window = rgb(0x0e1620)
let deep = rgb(0x0a1017)
let glow = rgb(0x142132)
let text = rgb(0xe6edf3)
let muted = rgb(0x8695ab)
let faint = rgb(0x5a6a80)
let accent = rgb(0x4a9eff)

let space = CGColorSpace(name: CGColorSpace.sRGB)!

/// Convert a top-left y (how the icon positions are expressed) to CoreGraphics'
/// bottom-left one.
func flip(_ topY: CGFloat) -> CGFloat { H - topY }

func draw(scale: CGFloat) -> CGImage {
    let ctx = CGContext(
        data: nil,
        width: Int(W * scale), height: Int(H * scale),
        bitsPerComponent: 8, bytesPerRow: 0, space: space,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.scaleBy(x: scale, y: scale)
    ctx.setAllowsAntialiasing(true)

    // Base: a near-black vertical gradient, darkest at the bottom so the icon
    // labels (drawn by Finder in white) stay legible wherever they land.
    let base = CGGradient(
        colorsSpace: space, colors: [window, deep] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(
        base, start: CGPoint(x: 0, y: H), end: CGPoint(x: 0, y: 0), options: [])

    // The window's own top-right glow, repeated here.
    let halo = CGGradient(
        colorsSpace: space,
        colors: [glow, CGColor(colorSpace: space, components: [0.078, 0.129, 0.196, 0])!] as CFArray,
        locations: [0, 1])!
    ctx.drawRadialGradient(
        halo,
        startCenter: CGPoint(x: W * 0.78, y: H * 1.06), startRadius: 0,
        endCenter: CGPoint(x: W * 0.78, y: H * 1.06), endRadius: W * 0.72,
        options: [.drawsAfterEndLocation])

    // ---- the arrow between the two icons ----------------------------------
    //
    // It says what to do without a sentence, and it is the one element that has
    // to line up with the icon positions rather than just look centred.
    let gap = (folderIcon.x - appIcon.x)
    let midY = flip(appIcon.y)
    let x0 = appIcon.x + gap * 0.30
    let x1 = folderIcon.x - gap * 0.30
    ctx.setStrokeColor(accent.copy(alpha: 0.42)!)
    ctx.setLineWidth(2)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.move(to: CGPoint(x: x0, y: midY))
    ctx.addLine(to: CGPoint(x: x1, y: midY))
    ctx.strokePath()
    let head: CGFloat = 9
    ctx.move(to: CGPoint(x: x1 - head, y: midY + head))
    ctx.addLine(to: CGPoint(x: x1, y: midY))
    ctx.addLine(to: CGPoint(x: x1 - head, y: midY - head))
    ctx.strokePath()

    // ---- text --------------------------------------------------------------
    func line(_ s: String, _ font: CTFont, _ color: CGColor, tracking: CGFloat = 0) -> CTLine {
        var attrs: [NSAttributedString.Key: Any] = [
            kCTFontAttributeName as NSAttributedString.Key: font,
            kCTForegroundColorAttributeName as NSAttributedString.Key: color,
        ]
        if tracking != 0 {
            attrs[kCTKernAttributeName as NSAttributedString.Key] = tracking
        }
        return CTLineCreateWithAttributedString(NSAttributedString(string: s, attributes: attrs))
    }

    func centre(_ ctLine: CTLine, topY: CGFloat) {
        let bounds = CTLineGetBoundsWithOptions(ctLine, .useOpticalBounds)
        ctx.textMatrix = .identity
        ctx.textPosition = CGPoint(x: (W - bounds.width) / 2 - bounds.origin.x, y: flip(topY))
        CTLineDraw(ctLine, ctx)
    }

    let title = CTFontCreateUIFontForLanguage(.emphasizedSystem, 21, nil)!
    let sub = CTFontCreateUIFontForLanguage(.system, 12, nil)!
    let hint = CTFontCreateUIFontForLanguage(.system, 12, nil)!

    centre(line("VPN Client", title, text), topY: 62)
    centre(line("IPSEC AND SSL VPN", sub, muted, tracking: 2.2), topY: 88)
    centre(line("Drag VPN Client into Applications to install", hint, faint), topY: 316)

    return ctx.makeImage()!
}

func writePNG(_ image: CGImage, to path: String) {
    let url = URL(fileURLWithPath: path) as CFURL
    guard let dest = CGImageDestinationCreateWithURL(url, UTType.png.identifier as CFString, 1, nil)
    else {
        FileHandle.standardError.write("cannot write \(path)\n".data(using: .utf8)!)
        exit(1)
    }
    CGImageDestinationAddImage(dest, image, nil)
    if !CGImageDestinationFinalize(dest) {
        FileHandle.standardError.write("cannot encode \(path)\n".data(using: .utf8)!)
        exit(1)
    }
}

let args = CommandLine.arguments
guard args.count == 3 else {
    FileHandle.standardError.write("usage: make-dmg-background.swift <1x.png> <2x.png>\n".data(using: .utf8)!)
    exit(2)
}
writePNG(draw(scale: 1), to: args[1])
writePNG(draw(scale: 2), to: args[2])
