package winexe

import (
	"bytes"
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The switch is checked against Go's own PE reader, on a real Windows
// build of a small program.
func TestSetSubsystem(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644)
	exe := filepath.Join(dir, "x.exe")
	cmd := exec.Command("go", "build", "-o", exe, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build a Windows program here: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(exe)
	subsystem := func(b []byte) uint16 {
		f, err := pe.NewFile(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		return f.OptionalHeader.(*pe.OptionalHeader64).Subsystem
	}
	if subsystem(b) != pe.IMAGE_SUBSYSTEM_WINDOWS_CUI {
		t.Fatalf("a Go build should start as a console program")
	}
	w, err := SetSubsystem(b, true)
	if err != nil {
		t.Fatal(err)
	}
	if subsystem(w) != pe.IMAGE_SUBSYSTEM_WINDOWS_GUI {
		t.Error("not marked windowed")
	}
	if ok, _ := IsWindowed(w); !ok {
		t.Error("IsWindowed: want true")
	}
	if subsystem(b) != pe.IMAGE_SUBSYSTEM_WINDOWS_CUI {
		t.Error("the original must not change")
	}
	c, _ := SetSubsystem(w, false)
	if !bytes.Equal(c, b) {
		t.Error("switching back should give the original bytes")
	}
	if _, err := SetSubsystem([]byte("hello"), true); err == nil {
		t.Error("want an error for a file that is not a program")
	}
}

// A10: a signed program whose mark changes loses its signature rather than
// keeping one that no longer matches; one whose mark doesn't change keeps
// it.
func TestSignatureDroppedWhenMarkChanges(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644)
	exe := filepath.Join(dir, "x.exe")
	cmd := exec.Command("go", "build", "-o", exe, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build a Windows program here: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(exe)
	// A stand-in certificate table at the end, as signtool appends one.
	cert := bytes.Repeat([]byte{0xAB}, 512)
	off, _ := subsystemOffset(b)
	e, _ := securityDir(b, off)
	signed := append(append([]byte(nil), b...), cert...)
	putU32(signed[e:], uint32(len(b)))
	putU32(signed[e+4:], uint32(len(cert)))
	if !Signed(signed) {
		t.Fatal("stand-in signature not seen")
	}
	same, _ := SetSubsystem(signed, false) // already console
	if !bytes.Equal(same, signed) {
		t.Error("an unchanged mark changed the file")
	}
	w, _ := SetSubsystem(signed, true)
	if Signed(w) || len(w) != len(b) {
		t.Errorf("signature kept after the mark changed (signed %v, %d bytes, want %d)", Signed(w), len(w), len(b))
	}
	if _, err := pe.NewFile(bytes.NewReader(w)); err != nil {
		t.Errorf("result is not a valid program: %v", err)
	}
}

func putU32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
