import AppKit
let directory = URL(fileURLWithPath: CommandLine.arguments[1])
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
func path(_ x: CGFloat, _ y: CGFloat, _ width: CGFloat, _ height: CGFloat) -> NSBezierPath {
    let p = NSBezierPath()
    p.move(to: NSPoint(x: x, y: y))
    p.line(to: NSPoint(x: x + width, y: y))
    p.line(to: NSPoint(x: x + width, y: y + height - 100))
    p.line(to: NSPoint(x: x + width - 100, y: y + height))
    p.line(to: NSPoint(x: x, y: y + height))
    p.close()
    p.lineJoinStyle = .round
    return p
}
for pixels in [16, 32, 64, 128, 256, 512, 1024] {
    let image = NSImage(size: NSSize(width: pixels, height: pixels))
    image.lockFocus()
    let context = NSGraphicsContext.current!.cgContext
    context.scaleBy(x: CGFloat(pixels) / 1024, y: CGFloat(pixels) / 1024)
    let background = NSBezierPath(roundedRect: NSRect(x: 42, y: 42, width: 940, height: 940), xRadius: 210, yRadius: 210)
    NSGradient(starting: NSColor(calibratedRed: 0.10, green: 0.40, blue: 0.86, alpha: 1),
               ending: NSColor(calibratedRed: 0.18, green: 0.73, blue: 0.93, alpha: 1))!.draw(in: background, angle: 90)
    NSColor.white.withAlphaComponent(0.45).setStroke()
    let back = path(228, 274, 338, 484); back.lineWidth = 44; back.stroke()
    NSColor.white.setFill()
    path(426, 248, 354, 498).fill()
    NSColor(calibratedRed: 0.13, green: 0.51, blue: 0.85, alpha: 1).setStroke()
    let chip = NSBezierPath(roundedRect: NSRect(x: 498, y: 334, width: 210, height: 210), xRadius: 36, yRadius: 36)
    chip.lineWidth = 18; chip.stroke()
    let tracks = NSBezierPath()
    for x: CGFloat in [568, 638] { tracks.move(to: NSPoint(x: x, y: 334)); tracks.line(to: NSPoint(x: x, y: 544)) }
    for y: CGFloat in [404, 474] { tracks.move(to: NSPoint(x: 498, y: y)); tracks.line(to: NSPoint(x: 708, y: y)) }
    tracks.lineWidth = 14; tracks.stroke()
    image.unlockFocus()
    let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
    let data = bitmap.representation(using: .png, properties: [:])!
    let names: [Int: [String]] = [16:["icon_16x16.png"],32:["icon_16x16@2x.png","icon_32x32.png"],64:["icon_32x32@2x.png"],128:["icon_128x128.png"],256:["icon_128x128@2x.png","icon_256x256.png"],512:["icon_256x256@2x.png","icon_512x512.png"],1024:["icon_512x512@2x.png"]]
    for name in names[pixels]! { try data.write(to: directory.appendingPathComponent(name)) }
}
