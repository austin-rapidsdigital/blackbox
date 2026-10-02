//go:build windows

package gui

import (
	"syscall"
	"unsafe"
)

// The Windows folder picker (IFileOpenDialog in folder mode), called
// through its COM interface.

type iFileDialog struct{ vtbl *iFileDialogVtbl }

type iFileDialogVtbl struct {
	QueryInterface, AddRef, Release                  uintptr
	Show                                             uintptr
	SetFileTypes, SetFileTypeIndex, GetFileTypeIndex uintptr
	Advise, Unadvise, SetOptions, GetOptions         uintptr
	SetDefaultFolder, SetFolder, GetFolder           uintptr
	GetCurrentSelection, SetFileName, GetFileName    uintptr
	SetTitle, SetOkButtonLabel, SetFileNameLabel     uintptr
	GetResult                                        uintptr
}

type iShellItem struct{ vtbl *iShellItemVtbl }

type iShellItemVtbl struct {
	QueryInterface, AddRef, Release          uintptr
	BindToHandler, GetParent, GetDisplayName uintptr
}

var (
	clsidFileOpenDialog = guid{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	iidIFileOpenDialog  = guid{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
	iidIShellItem       = guid{0x43826D1E, 0xE718, 0x42EE, [8]byte{0xBC, 0x55, 0xA1, 0xE2, 0x61, 0xC3, 0x7B, 0xFE}}
)

const (
	fosPickFolders     = 0x20
	fosForceFileSystem = 0x40
	fosNoChangeDir     = 0x08
	sigdnFileSysPath   = 0x80058000
)

// newFolderDialog creates the folder picker, or returns nil.
func newFolderDialog() *iFileDialog {
	var d *iFileDialog
	hr, _, _ := pCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidFileOpenDialog)), 0, 1, // CLSCTX_INPROC_SERVER
		uintptr(unsafe.Pointer(&iidIFileOpenDialog)), uintptr(unsafe.Pointer(&d)))
	if int32(hr) < 0 || d == nil {
		return nil
	}
	return d
}

func (d *iFileDialog) release() {
	syscall.SyscallN(d.vtbl.Release, uintptr(unsafe.Pointer(d)))
}

// pickFolder asks for a folder, starting at start; "" when cancelled.
func pickFolder(owner uintptr, title, start string) string {
	d := newFolderDialog()
	if d == nil {
		return ""
	}
	defer d.release()
	var opts uint32
	syscall.SyscallN(d.vtbl.GetOptions, uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(&opts)))
	syscall.SyscallN(d.vtbl.SetOptions, uintptr(unsafe.Pointer(d)), uintptr(opts|fosPickFolders|fosForceFileSystem|fosNoChangeDir))
	syscall.SyscallN(d.vtbl.SetTitle, uintptr(unsafe.Pointer(d)), ptr(title))
	if start != "" {
		var item *iShellItem
		hr, _, _ := pSHCreateItemFromParsing.Call(ptr(start), 0, uintptr(unsafe.Pointer(&iidIShellItem)), uintptr(unsafe.Pointer(&item)))
		if int32(hr) >= 0 && item != nil {
			syscall.SyscallN(d.vtbl.SetFolder, uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(item)))
			syscall.SyscallN(item.vtbl.Release, uintptr(unsafe.Pointer(item)))
		}
	}
	if hr, _, _ := syscall.SyscallN(d.vtbl.Show, uintptr(unsafe.Pointer(d)), owner); int32(hr) < 0 {
		return "" // cancelled
	}
	var item *iShellItem
	if hr, _, _ := syscall.SyscallN(d.vtbl.GetResult, uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(&item))); int32(hr) < 0 || item == nil {
		return ""
	}
	defer syscall.SyscallN(item.vtbl.Release, uintptr(unsafe.Pointer(item)))
	var name *uint16
	if hr, _, _ := syscall.SyscallN(item.vtbl.GetDisplayName, uintptr(unsafe.Pointer(item)), sigdnFileSysPath, uintptr(unsafe.Pointer(&name))); int32(hr) < 0 || name == nil {
		return ""
	}
	defer pCoTaskMemFree.Call(uintptr(unsafe.Pointer(name)))
	return utf16z(name)
}

// utf16z reads a NUL-terminated string the system allocated.
func utf16z(p *uint16) string {
	n := 0
	for *(*uint16)(unsafe.Add(unsafe.Pointer(p), 2*n)) != 0 {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}
