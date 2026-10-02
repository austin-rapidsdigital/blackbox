//go:build windows

package gui

import (
	"os"
	"syscall"
	"unsafe"
)

// Launched reports whether the program was started from Explorer (double-
// clicked) rather than typed at a prompt: either it is the windowed copy
// and has no console, or Windows made a console just for it, which is
// then hidden.
func Launched() bool {
	h, _, _ := pGetConsoleWindow.Call()
	if h == 0 {
		return true
	}
	return hideOwnConsole()
}

// hideOwnConsole hides the console Windows made for this program alone
// (when it was started from Explorer, or restarted with administrator
// rights). A console shared with a prompt is left alone.
func hideOwnConsole() bool {
	h, _, _ := pGetConsoleWindow.Call()
	if h == 0 {
		return false
	}
	var ids [4]uint32
	n, _, _ := pGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), 4)
	if n == 1 {
		pShowWindow.Call(h, swHide)
		pFreeConsole.Call()
		return true
	}
	return false
}

// AttachConsole lets the windowed copy (the setup file) print to the
// prompt it was started from, for scripted installs. Output that is
// already redirected to a file is left alone.
func AttachConsole() {
	if h, _, _ := pGetConsoleWindow.Call(); h != 0 {
		return
	}
	if h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE); err == nil && h != 0 && h != syscall.InvalidHandle {
		return
	}
	if r, _, _ := pAttachConsole.Call(^uintptr(0)); r == 0 { // ATTACH_PARENT_PROCESS
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
}
