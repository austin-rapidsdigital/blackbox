package brand

import "testing"

func TestLogoScales(t *testing.T) {
	for _, n := range []int{16, 32, 48, 256} {
		img := Logo(n)
		if img.Bounds().Dx() != n {
			t.Fatalf("size %d: got %v", n, img.Bounds())
		}
		// The monogram is a filled circle: the centre is opaque, the corners clear.
		if img.NRGBAAt(n/2, n/2).A < 200 || img.NRGBAAt(0, 0).A > 40 {
			t.Errorf("size %d: centre %v corner %v", n, img.NRGBAAt(n/2, n/2), img.NRGBAAt(0, 0))
		}
	}
}
