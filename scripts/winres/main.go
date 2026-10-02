// Command winres writes the Windows resources for blackbox.exe (the program
// icon and version details) as a COFF object (.syso) that `go build` links
// in automatically. It uses only the standard library, so the build stays
// free of third-party tools.
//
//	go run ./scripts/winres -version 0.1.2 -o cmd/blackbox/rsrc_windows_amd64.syso
//
// scripts/build.sh runs this before building for Windows. With -windowed it
// instead writes a copy of a built program marked windowed (no console),
// which is how the setup file is made:
//
//	go run ./scripts/winres -windowed blackbox.exe -o Blackbox-Setup.exe
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/png"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/casea1/blackbox/internal/brand"
	"github.com/casea1/blackbox/internal/winexe"
)

// Details shown in the file's Properties and in Settings > Apps.
const (
	Publisher   = "Austin Case"
	ProductName = brand.Name
	Description = brand.Name + " audit log reporter"
	Copyright   = "Copyright Austin Case"
)

func main() {
	version := flag.String("version", "dev", "program version, e.g. 0.1.2")
	out := flag.String("o", "cmd/blackbox/rsrc_windows_amd64.syso", "output .syso file")
	arch := flag.String("arch", "amd64", "amd64 or 386")
	preview := flag.String("png", "", "also write a 256px PNG preview of the icon here")
	windowed := flag.String("windowed", "", "write a copy of this program marked windowed to -o, and do nothing else")
	flag.Parse()

	if *windowed != "" {
		b, err := os.ReadFile(*windowed)
		if err == nil {
			b, err = winexe.SetSubsystem(b, true)
		}
		if err == nil {
			err = os.WriteFile(*out, b, 0o755)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "winres:", err)
			os.Exit(1)
		}
		return
	}

	obj, err := Object(*arch, Resources(*version))
	if err == nil {
		err = os.WriteFile(*out, obj, 0o644)
	}
	if err == nil && *preview != "" {
		err = os.WriteFile(*preview, pngBytes(Icon(256)), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "winres:", err)
		os.Exit(1)
	}
}

// Resource types and the language used for every entry (English, US).
const (
	rtIcon      = 3
	rtGroupIcon = 14
	rtVersion   = 16
	rtManifest  = 24
	langEnUS    = 0x0409
)

// Resource is one entry in the resource tree.
type Resource struct {
	Type, ID uint16
	Data     []byte
}

// Resources returns the icon images, the icon group that points at them,
// the version information and the manifest.
func Resources(version string) []Resource {
	sizes := []int{16, 24, 32, 48, 64, 256}
	var res []Resource
	group := new(bytes.Buffer)
	binary.Write(group, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	for i, s := range sizes {
		img := Icon(s)
		var data []byte
		if s >= 256 {
			data = pngBytes(img) // large sizes are stored as PNG
		} else {
			data = dib(img) // small sizes as bitmaps, which every part of Windows reads
		}
		id := uint16(i + 1)
		res = append(res, Resource{rtIcon, id, data})
		// GRPICONDIRENTRY: width and height of 256 are written as 0.
		group.Write([]byte{byte(s), byte(s), 0, 0})
		binary.Write(group, binary.LittleEndian, struct {
			Planes, BitCount uint16
			Bytes            uint32
			ID               uint16
		}{1, 32, uint32(len(data)), id})
	}
	res = append(res, Resource{rtGroupIcon, 1, group.Bytes()})
	res = append(res, Resource{rtVersion, 1, versionInfo(version)})
	res = append(res, Resource{rtManifest, 1, []byte(Manifest)})
	return res
}

// Manifest tells Windows how to run the program: with the rights of
// whoever starts it (setup asks for administrator rights itself, so the
// tray and the command line never prompt), with the current look of
// buttons and other controls, and sharp at any display scaling.
const Manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Blackbox" version="1.0.0.0" processorArchitecture="*"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2, PerMonitor</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
`

// Icon is the program icon at size×size pixels: the GE Aerospace logo.
func Icon(size int) *image.NRGBA { return brand.Logo(size) }

func pngBytes(img image.Image) []byte {
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

// dib encodes an image as an icon bitmap: a BITMAPINFOHEADER with double
// height, 32-bit BGRA rows bottom-up, then the 1-bit transparency mask.
func dib(img *image.NRGBA) []byte {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	maskRow := (w + 31) / 32 * 4
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, struct {
		Size                   uint32
		Width, Height          int32
		Planes, BitCount       uint16
		Compression, SizeImage uint32
		XPels, YPels           int32
		ClrUsed, ClrImportant  uint32
	}{40, int32(w), int32(2 * h), 1, 32, 0, uint32(w*h*4 + maskRow*h), 0, 0, 0, 0})
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(x, y)
			b.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	for y := h - 1; y >= 0; y-- {
		row := make([]byte, maskRow)
		for x := 0; x < w; x++ {
			if img.NRGBAAt(x, y).A == 0 {
				row[x/8] |= 0x80 >> (x % 8)
			}
		}
		b.Write(row)
	}
	return b.Bytes()
}

// versionInfo builds a VS_VERSIONINFO block: what Windows shows on the
// Details tab of the file's Properties.
func versionInfo(version string) []byte {
	var nums [4]uint16
	for i, p := range strings.SplitN(strings.SplitN(version, "-", 2)[0], ".", 4) {
		n, _ := strconv.ParseUint(p, 10, 16)
		nums[i] = uint16(n)
	}
	ms := uint32(nums[0])<<16 | uint32(nums[1])
	ls := uint32(nums[2])<<16 | uint32(nums[3])
	fixed := new(bytes.Buffer)
	binary.Write(fixed, binary.LittleEndian, [13]uint32{
		0xFEEF04BD, 0x00010000, // signature, structure version
		ms, ls, ms, ls, // file and product version
		0x3F, 0, // flags mask, flags
		0x00040004, // VOS_NT_WINDOWS32
		1, 0,       // VFT_APP
		0, 0, // date
	})
	strs := [][2]string{
		{"CompanyName", Publisher},
		{"FileDescription", Description},
		{"FileVersion", version},
		{"InternalName", "blackbox"},
		{"LegalCopyright", Copyright},
		{"OriginalFilename", "blackbox.exe"},
		{"ProductName", ProductName},
		{"ProductVersion", version},
	}
	var table [][]byte
	for _, s := range strs {
		v := utf16z(s[1])
		table = append(table, node(s[0], 1, uint16(len(v)/2), v, nil))
	}
	stringInfo := node("StringFileInfo", 1, 0, nil, [][]byte{node("040904B0", 1, 0, nil, table)})
	translation := []byte{0x09, 0x04, 0xB0, 0x04} // English (US), Unicode
	varInfo := node("VarFileInfo", 1, 0, nil, [][]byte{node("Translation", 0, 4, translation, nil)})
	return node("VS_VERSION_INFO", 0, uint16(fixed.Len()), fixed.Bytes(), [][]byte{stringInfo, varInfo})
}

// node writes one version-information block: length, value length, type,
// key, padding, value, then each child aligned to 4 bytes.
func node(key string, typ, valueLen uint16, value []byte, children [][]byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, valueLen, typ})
	b.Write(utf16z(key))
	pad4(&b)
	b.Write(value)
	for _, c := range children {
		pad4(&b)
		b.Write(c)
	}
	out := b.Bytes()
	binary.LittleEndian.PutUint16(out, uint16(len(out)))
	return out
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

func utf16z(s string) []byte {
	u := append(utf16.Encode([]rune(s)), 0)
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// Object lays the resources out as a .rsrc section (type, then ID, then
// language directories, then data entries and data) inside a COFF object.
// Each data entry's address is relative to the section, with a relocation
// so the linker turns it into the final address.
func Object(arch string, res []Resource) ([]byte, error) {
	var machine, relType uint16
	switch arch {
	case "amd64":
		machine, relType = 0x8664, 0x0003 // IMAGE_REL_AMD64_ADDR32NB
	case "386":
		machine, relType = 0x014c, 0x0007 // IMAGE_REL_I386_DIR32NB
	default:
		return nil, fmt.Errorf("unsupported architecture %q", arch)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Type != res[j].Type {
			return res[i].Type < res[j].Type
		}
		return res[i].ID < res[j].ID
	})
	var types []uint16
	byType := map[uint16][]Resource{}
	for _, r := range res {
		if len(byType[r.Type]) == 0 {
			types = append(types, r.Type)
		}
		byType[r.Type] = append(byType[r.Type], r)
	}

	// Sizes: a directory is 16 bytes plus 8 per entry; a data entry is 16.
	dirSize := func(n int) int { return 16 + 8*n }
	off := dirSize(len(types))
	typeDir := map[uint16]int{}
	for _, t := range types {
		typeDir[t] = off
		off += dirSize(len(byType[t]))
	}
	langDir := make([]int, len(res))
	for i := range res {
		langDir[i] = off
		off += dirSize(1)
	}
	entry := make([]int, len(res))
	for i := range res {
		entry[i] = off
		off += 16
	}
	data := make([]int, len(res))
	for i, r := range res {
		off = (off + 7) &^ 7
		data[i] = off
		off += len(r.Data)
	}

	sec := make([]byte, (off+3)&^3)
	le := binary.LittleEndian
	writeDir := func(at int, entries [][2]uint32) {
		le.PutUint16(sec[at+14:], uint16(len(entries))) // all entries are IDs
		for i, e := range entries {
			le.PutUint32(sec[at+16+8*i:], e[0])
			le.PutUint32(sec[at+16+8*i+4:], e[1])
		}
	}
	const subdir = 0x80000000
	var root [][2]uint32
	for _, t := range types {
		root = append(root, [2]uint32{uint32(t), subdir | uint32(typeDir[t])})
	}
	writeDir(0, root)
	i := 0
	for _, t := range types {
		var ids [][2]uint32
		for _, r := range byType[t] {
			ids = append(ids, [2]uint32{uint32(r.ID), subdir | uint32(langDir[i])})
			i++
		}
		writeDir(typeDir[t], ids)
	}
	var relocs []uint32
	for i, r := range res {
		writeDir(langDir[i], [][2]uint32{{langEnUS, uint32(entry[i])}})
		le.PutUint32(sec[entry[i]:], uint32(data[i]))
		le.PutUint32(sec[entry[i]+4:], uint32(len(r.Data)))
		copy(sec[data[i]:], r.Data)
		relocs = append(relocs, uint32(entry[i]))
	}

	// COFF: file header, one section header, section data, relocations,
	// one symbol (the section itself), and an empty string table.
	const fileHdr, secHdr = 20, 40
	secAt := fileHdr + secHdr
	relAt := secAt + len(sec)
	symAt := relAt + 10*len(relocs)
	var b bytes.Buffer
	binary.Write(&b, le, struct {
		Machine, Sections  uint16
		Time, Symtab, Syms uint32
		OptHdr, Flags      uint16
	}{machine, 1, 0, uint32(symAt), 1, 0, 0})
	binary.Write(&b, le, struct {
		Name                              [8]byte
		VSize, VAddr, Size, Data, Rel, Ln uint32
		NRel, NLn                         uint16
		Flags                             uint32
	}{[8]byte{'.', 'r', 's', 'r', 'c'}, 0, 0, uint32(len(sec)), uint32(secAt), uint32(relAt), 0,
		uint16(len(relocs)), 0, 0x40000040}) // initialized data, readable
	b.Write(sec)
	for _, r := range relocs {
		binary.Write(&b, le, struct {
			Addr, Sym uint32
			Type      uint16
		}{r, 0, relType})
	}
	binary.Write(&b, le, struct {
		Name        [8]byte
		Value       uint32
		Section     int16
		Type        uint16
		Class, NAux uint8
	}{[8]byte{'.', 'r', 's', 'r', 'c'}, 0, 1, 0, 3, 0}) // static, section 1
	binary.Write(&b, le, uint32(4)) // string table: just its own size
	return b.Bytes(), nil
}
