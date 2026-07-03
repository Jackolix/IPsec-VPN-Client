# Generate the Tauri app icon set (shield glyph) into crates/vpn-desktop/icons.
# Run with Windows PowerShell 5.1 (System.Drawing): powershell.exe -File scripts\gen-icons.ps1
Add-Type -AssemblyName System.Drawing
$dir = Join-Path (Split-Path -Parent $PSScriptRoot) "crates\vpn-desktop\icons"
New-Item -ItemType Directory -Force $dir | Out-Null

function New-IconBmp([int]$size) {
  $bmp = New-Object System.Drawing.Bitmap($size, $size)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'
  $g.Clear([System.Drawing.Color]::Transparent)

  $accent = [System.Drawing.Color]::FromArgb(74, 158, 255)
  $dark = [System.Drawing.Color]::FromArgb(14, 22, 32)
  $pad = [int]($size * 0.06)
  $rw = $size - 2 * $pad
  $d = [int]($size * 0.44)

  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $path.AddArc($pad, $pad, $d, $d, 180, 90)
  $path.AddArc($pad + $rw - $d, $pad, $d, $d, 270, 90)
  $path.AddArc($pad + $rw - $d, $pad + $rw - $d, $d, $d, 0, 90)
  $path.AddArc($pad, $pad + $rw - $d, $d, $d, 90, 90)
  $path.CloseFigure()
  $g.FillPath((New-Object System.Drawing.SolidBrush($accent)), $path)

  $cx = [single]($size / 2.0)
  $sw = [single]($size * 0.42)
  $sh = [single]($size * 0.48)
  $top = [single]($size * 0.25)
  $sp = New-Object System.Drawing.Drawing2D.GraphicsPath
  $sp.AddLine($cx, $top, $cx + $sw / 2, $top + $sh * 0.14)
  $sp.AddLine($cx + $sw / 2, $top + $sh * 0.14, $cx + $sw / 2, $top + $sh * 0.55)
  $sp.AddBezier($cx + $sw / 2, $top + $sh * 0.55, $cx + $sw / 2, $top + $sh * 0.92, $cx, $top + $sh, $cx, $top + $sh)
  $sp.AddBezier($cx, $top + $sh, $cx, $top + $sh, $cx - $sw / 2, $top + $sh * 0.92, $cx - $sw / 2, $top + $sh * 0.55)
  $sp.AddLine($cx - $sw / 2, $top + $sh * 0.55, $cx - $sw / 2, $top + $sh * 0.14)
  $sp.CloseFigure()
  $g.FillPath((New-Object System.Drawing.SolidBrush($dark)), $sp)

  $pen = New-Object System.Drawing.Pen($accent, [single]($size * 0.055))
  $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
  $pts = @(
    (New-Object System.Drawing.PointF([single]($cx - $sw * 0.2), [single]($top + $sh * 0.46))),
    (New-Object System.Drawing.PointF([single]($cx - $sw * 0.02), [single]($top + $sh * 0.62))),
    (New-Object System.Drawing.PointF([single]($cx + $sw * 0.24), [single]($top + $sh * 0.3)))
  )
  $g.DrawLines($pen, $pts)
  $g.Dispose()
  return $bmp
}

foreach ($s in 32, 128, 256) {
  (New-IconBmp $s).Save((Join-Path $dir "${s}x${s}.png"), [System.Drawing.Imaging.ImageFormat]::Png)
}
(New-IconBmp 256).Save((Join-Path $dir "128x128@2x.png"), [System.Drawing.Imaging.ImageFormat]::Png)
(New-IconBmp 512).Save((Join-Path $dir "icon.png"), [System.Drawing.Imaging.ImageFormat]::Png)

$b = New-IconBmp 256
$ico = [System.Drawing.Icon]::FromHandle($b.GetHicon())
$fs = New-Object System.IO.FileStream((Join-Path $dir "icon.ico"), [System.IO.FileMode]::Create)
$ico.Save($fs); $fs.Close()

Write-Output "icons written to $dir"
Get-ChildItem $dir | Select-Object Name, Length
