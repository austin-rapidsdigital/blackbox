//go:build windows

package gui

import (
	"image"
	"unsafe"
)

// hicon makes a Windows icon from an image (with its transparency).
func hicon(img *image.NRGBA) uintptr {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	bi := bitmapInfoHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}
	var bits unsafe.Pointer
	hdc, _, _ := pGetDC.Call(0)
	color, _, _ := pCreateDIBSection.Call(hdc, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	pReleaseDC.Call(0, hdc)
	if color == 0 || bits == nil {
		return 0
	}
	px := unsafe.Slice((*byte)(bits), w*h*4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			s := img.PixOffset(x+img.Bounds().Min.X, y+img.Bounds().Min.Y)
			d := (y*w + x) * 4
			px[d], px[d+1], px[d+2], px[d+3] = img.Pix[s+2], img.Pix[s+1], img.Pix[s], img.Pix[s+3]
		}
	}
	mask, _, _ := pCreateBitmap.Call(uintptr(w), uintptr(h), 1, 1, 0)
	ii := iconInfo{Icon: 1, Mask: mask, Color: color}
	icon, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	pDeleteObject.Call(color)
	pDeleteObject.Call(mask)
	return icon
}
