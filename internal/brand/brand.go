// Package brand holds the product name and logo, shared by the reports,
// the installer and the Windows program icon.
package brand

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
)

const (
	Company = "GE Aerospace"
	Product = "Blackbox"
	Name    = Company + " " + Product // shown in reports, the installer and Settings > Apps
)

// LogoPNG is the GE Aerospace monogram, 256×256 with a transparent
// background.
//
//go:embed logo.png
var LogoPNG []byte

// LogoDataURI is the logo as a data: URI, so a report stays one
// self-contained file.
func LogoDataURI() string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(LogoPNG)
}

// Logo returns the logo scaled to size×size, each pixel the average of the
// source pixels it covers (weighted by alpha, so edges stay clean).
func Logo(size int) *image.NRGBA {
	src, err := png.Decode(bytes.NewReader(LogoPNG))
	if err != nil {
		panic("brand: embedded logo: " + err.Error())
	}
	b := src.Bounds()
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	sx, sy := float64(b.Dx())/float64(size), float64(b.Dy())/float64(size)
	for y := 0; y < size; y++ {
		y0, y1 := int(float64(y)*sy), int(float64(y+1)*sy+0.999)
		for x := 0; x < size; x++ {
			x0, x1 := int(float64(x)*sx), int(float64(x+1)*sx+0.999)
			var r, g, bl, a, n float64
			for py := y0; py < y1 && py < b.Dy(); py++ {
				for px := x0; px < x1 && px < b.Dx(); px++ {
					c := color.NRGBAModel.Convert(src.At(b.Min.X+px, b.Min.Y+py)).(color.NRGBA)
					w := float64(c.A)
					r, g, bl, a, n = r+float64(c.R)*w, g+float64(c.G)*w, bl+float64(c.B)*w, a+w, n+1
				}
			}
			if a > 0 {
				dst.SetNRGBA(x, y, color.NRGBA{uint8(r / a), uint8(g / a), uint8(bl / a), uint8(a / n)})
			}
		}
	}
	return dst
}
