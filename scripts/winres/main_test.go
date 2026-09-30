package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"image/png"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"
)

// TestObject parses the generated object the way the linker does and walks
// the resource tree: type, ID and language directories, then data entries
// whose relocated addresses point at each resource's bytes.
func TestObject(t *testing.T) {
	res := Resources("1.2.3")
	obj, err := Object("amd64", append([]Resource(nil), res...))
	if err != nil {
		t.Fatal(err)
	}
	f, err := pe.NewFile(bytes.NewReader(obj))
	if err != nil {
		t.Fatal(err)
	}
	if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || len(f.Sections) != 1 || f.Sections[0].Name != ".rsrc" {
		t.Fatalf("unexpected object layout: machine %#x, %d sections", f.Machine, len(f.Sections))
	}
	sec := f.Sections[0]
	d, _ := sec.Data()
	if len(sec.Relocs) != len(res) {
		t.Errorf("got %d relocations, want one per resource (%d)", len(sec.Relocs), len(res))
	}
	relocated := map[uint32]bool{}
	for _, r := range sec.Relocs {
		if r.Type != 3 || r.SymbolTableIndex != 0 {
			t.Errorf("relocation %+v: want ADDR32NB against the section symbol", r)
		}
		relocated[r.VirtualAddress] = true
	}

	le := binary.LittleEndian
	found := map[[2]uint32][]byte{}
	var walk func(off int, path []uint32)
	walk = func(off int, path []uint32) {
		n := int(le.Uint16(d[off+14:]))
		for i := 0; i < n; i++ {
			id, to := le.Uint32(d[off+16+8*i:]), le.Uint32(d[off+20+8*i:])
			p := append(append([]uint32(nil), path...), id)
			if to&0x80000000 != 0 {
				walk(int(to&0x7fffffff), p)
				continue
			}
			if len(p) != 3 || p[2] != langEnUS {
				t.Fatalf("data entry at depth %d / language %#x", len(p), p[len(p)-1])
			}
			if !relocated[to] {
				t.Errorf("data entry at %#x has no relocation", to)
			}
			at, size := le.Uint32(d[to:]), le.Uint32(d[to+4:])
			found[[2]uint32{p[0], p[1]}] = d[at : at+size]
		}
	}
	walk(0, nil)

	for _, r := range res {
		if got := found[[2]uint32{uint32(r.Type), uint32(r.ID)}]; !bytes.Equal(got, r.Data) {
			t.Errorf("resource type %d id %d: data does not match", r.Type, r.ID)
		}
	}
	group := found[[2]uint32{rtGroupIcon, 1}]
	if n := int(le.Uint16(group[4:])); n != 6 || len(group) != 6+14*n {
		t.Errorf("icon group lists %d icons in %d bytes", n, len(group))
	}
	if _, err := png.Decode(bytes.NewReader(found[[2]uint32{rtIcon, 6}])); err != nil {
		t.Errorf("256px icon is not a valid PNG: %v", err)
	}
}

func TestVersionInfo(t *testing.T) {
	v := versionInfo("0.1.2-rc1")
	if int(binary.LittleEndian.Uint16(v)) != len(v) {
		t.Errorf("length field %d, block is %d bytes", binary.LittleEndian.Uint16(v), len(v))
	}
	fixed := v[40:] // header (6) + "VS_VERSION_INFO\0" (32) + padding (2)
	if sig := binary.LittleEndian.Uint32(fixed); sig != 0xFEEF04BD {
		t.Fatalf("fixed info signature %#x", sig)
	}
	if ms, ls := binary.LittleEndian.Uint32(fixed[8:]), binary.LittleEndian.Uint32(fixed[12:]); ms != 0x00000001 || ls != 0x00020000 {
		t.Errorf("file version %#x.%#x, want 0.1.2.0", ms, ls)
	}
	u := make([]uint16, len(v)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(v[2*i:])
	}
	text := string(utf16.Decode(u))
	// Each key is followed by its terminator and up to one padding character.
	for _, kv := range [][2]string{{"CompanyName", "Austin Case"}, {"ProductVersion", "0.1.2-rc1"}, {"FileVersion", "0.1.2-rc1"}} {
		if !regexp.MustCompile(kv[0] + "\x00\x00?" + regexp.QuoteMeta(kv[1]) + "\x00").MatchString(text) {
			t.Errorf("version info missing %s = %s", kv[0], kv[1])
		}
	}
	if !strings.Contains(text, "Translation") {
		t.Error("version info missing the translation table")
	}
}

func TestIconSharpAtSmallSizes(t *testing.T) {
	// On the 16-unit grid, every pixel of the 16 and 32 pixel icons is
	// either fully transparent or fully opaque (no blurred edges).
	for _, size := range []int{16, 32} {
		img := Icon(size)
		for i := 3; i < len(img.Pix); i += 4 {
			if a := img.Pix[i]; a != 0 && a != 255 {
				t.Fatalf("%dpx icon has a partly transparent pixel (alpha %d)", size, a)
			}
		}
	}
}
