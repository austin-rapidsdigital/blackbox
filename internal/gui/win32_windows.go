//go:build windows

package gui

// The few Windows API functions, constants and structures the setup window
// and the status icon use, called directly (standard library only).

import (
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pRegisterClassExW        = user32.NewProc("RegisterClassExW")
	pCreateWindowExW         = user32.NewProc("CreateWindowExW")
	pDefWindowProcW          = user32.NewProc("DefWindowProcW")
	pDestroyWindow           = user32.NewProc("DestroyWindow")
	pShowWindow              = user32.NewProc("ShowWindow")
	pUpdateWindow            = user32.NewProc("UpdateWindow")
	pGetMessageW             = user32.NewProc("GetMessageW")
	pTranslateMessage        = user32.NewProc("TranslateMessage")
	pDispatchMessageW        = user32.NewProc("DispatchMessageW")
	pIsDialogMessageW        = user32.NewProc("IsDialogMessageW")
	pPostQuitMessage         = user32.NewProc("PostQuitMessage")
	pPostMessageW            = user32.NewProc("PostMessageW")
	pSendMessageW            = user32.NewProc("SendMessageW")
	pSetWindowTextW          = user32.NewProc("SetWindowTextW")
	pGetWindowTextW          = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW    = user32.NewProc("GetWindowTextLengthW")
	pEnableWindow            = user32.NewProc("EnableWindow")
	pSetWindowPos            = user32.NewProc("SetWindowPos")
	pGetDpiForWindow         = user32.NewProc("GetDpiForWindow")
	pGetDpiForSystem         = user32.NewProc("GetDpiForSystem")
	pAdjustWindowRectEx      = user32.NewProc("AdjustWindowRectEx")
	pMessageBoxW             = user32.NewProc("MessageBoxW")
	pLoadCursorW             = user32.NewProc("LoadCursorW")
	pSetCursor               = user32.NewProc("SetCursor")
	pSetFocus                = user32.NewProc("SetFocus")
	pGetSystemMetrics        = user32.NewProc("GetSystemMetrics")
	pCreatePopupMenu         = user32.NewProc("CreatePopupMenu")
	pAppendMenuW             = user32.NewProc("AppendMenuW")
	pSetMenuDefaultItem      = user32.NewProc("SetMenuDefaultItem")
	pTrackPopupMenu          = user32.NewProc("TrackPopupMenu")
	pDestroyMenu             = user32.NewProc("DestroyMenu")
	pSetForegroundWindow     = user32.NewProc("SetForegroundWindow")
	pGetCursorPos            = user32.NewProc("GetCursorPos")
	pCreateIconIndirect      = user32.NewProc("CreateIconIndirect")
	pDestroyIcon             = user32.NewProc("DestroyIcon")
	pBeginPaint              = user32.NewProc("BeginPaint")
	pEndPaint                = user32.NewProc("EndPaint")
	pFillRect                = user32.NewProc("FillRect")
	pDrawTextW               = user32.NewProc("DrawTextW")
	pDrawIconEx              = user32.NewProc("DrawIconEx")
	pGetClientRect           = user32.NewProc("GetClientRect")
	pInvalidateRect          = user32.NewProc("InvalidateRect")
	pSetTimer                = user32.NewProc("SetTimer")
	pKillTimer               = user32.NewProc("KillTimer")
	pRegisterWindowMessageW  = user32.NewProc("RegisterWindowMessageW")
	pGetDC                   = user32.NewProc("GetDC")
	pReleaseDC               = user32.NewProc("ReleaseDC")
	pIsWindowVisible         = user32.NewProc("IsWindowVisible")
	pSendMessageTimeoutW     = user32.NewProc("SendMessageTimeoutW")
	pCreateFontIndirectW     = gdi32.NewProc("CreateFontIndirectW")
	pDeleteObject            = gdi32.NewProc("DeleteObject")
	pCreateSolidBrush        = gdi32.NewProc("CreateSolidBrush")
	pSetBkMode               = gdi32.NewProc("SetBkMode")
	pSetBkColor              = gdi32.NewProc("SetBkColor")
	pSetTextColor            = gdi32.NewProc("SetTextColor")
	pSelectObject            = gdi32.NewProc("SelectObject")
	pCreateDIBSection        = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap            = gdi32.NewProc("CreateBitmap")
	pShellNotifyIconW        = shell32.NewProc("Shell_NotifyIconW")
	pShellExecuteW           = shell32.NewProc("ShellExecuteW")
	pSHCreateItemFromParsing = shell32.NewProc("SHCreateItemFromParsingName")
	pCoInitializeEx          = ole32.NewProc("CoInitializeEx")
	pCoCreateInstance        = ole32.NewProc("CoCreateInstance")
	pCoTaskMemFree           = ole32.NewProc("CoTaskMemFree")
	pGetModuleHandleW        = kernel32.NewProc("GetModuleHandleW")
	pGetConsoleWindow        = kernel32.NewProc("GetConsoleWindow")
	pGetConsoleProcessList   = kernel32.NewProc("GetConsoleProcessList")
	pFreeConsole             = kernel32.NewProc("FreeConsole")
	pAttachConsole           = kernel32.NewProc("AttachConsole")
	pCreateMutexW            = kernel32.NewProc("CreateMutexW")
	pCreateEventW            = kernel32.NewProc("CreateEventW")
	pWaitForSingleObject     = kernel32.NewProc("WaitForSingleObject")
	pInitCommonControlsEx    = comctl32.NewProc("InitCommonControlsEx")
	pSetDpiAwarenessContext  = user32.NewProc("SetProcessDpiAwarenessContext")
	pAdjustWindowRectExDpi   = user32.NewProc("AdjustWindowRectExForDpi")
	pGetAncestor             = user32.NewProc("GetAncestor")
	pRtlMoveMemory           = kernel32.NewProc("RtlMoveMemory")
	pIsWindow                = user32.NewProc("IsWindow")
	pImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	pRevertToSelf            = advapi32.NewProc("RevertToSelf")
)

// Window messages.
const (
	wmDestroy           = 0x0002
	wmSize              = 0x0005
	wmPaint             = 0x000F
	wmClose             = 0x0010
	wmSetFont           = 0x0030
	wmGetMinMaxInfo     = 0x0024
	wmNotify            = 0x004E
	wmContextMenu       = 0x007B
	wmKeyDown           = 0x0100
	wmCommand           = 0x0111
	wmTimer             = 0x0113
	wmCtlColorEdit      = 0x0133
	wmCtlColorBtn       = 0x0135
	wmCtlColorStatic    = 0x0138
	wmLButtonUp         = 0x0202
	wmRButtonUp         = 0x0205
	wmDpiChanged        = 0x02E0
	wmApp               = 0x8000
	wmNull              = 0x0000
	emSetSel            = 0x00B1
	emReplaceSel        = 0x00C2
	emSetLimitText      = 0x00C5
	emSetCueBanner      = 0x1501
	bmGetCheck          = 0x00F0
	bmSetCheck          = 0x00F1
	bmSetStyle          = 0x00F4
	cbAddString         = 0x0143
	cbGetCurSel         = 0x0147
	cbSetCurSel         = 0x014E
	cbSetMinVisible     = 0x1701
	pbmSetMarquee       = 0x040A
	pbmSetPos           = 0x0402
	stmSetImage         = 0x0172
	bnClicked           = 0
	cbnSelChange        = 1
	cbnEditChange       = 5
	enChange            = 0x0300
	ninSelect           = 0x0400
	ninKeySelect        = 0x0401
	ninBalloonUserClick = 0x0405
)

// Window and control styles.
const (
	wsOverlapped      = 0x00000000
	wsCaption         = 0x00C00000
	wsSysMenu         = 0x00080000
	wsMinimizeBox     = 0x00020000
	wsChild           = 0x40000000
	wsVisible         = 0x10000000
	wsTabStop         = 0x00010000
	wsGroup           = 0x00020000
	wsVScroll         = 0x00200000
	wsHScroll         = 0x00100000
	wsBorder          = 0x00800000
	wsClipChildren    = 0x02000000
	wsExClientEdge    = 0x00000200
	wsExDlgModal      = 0x00000001
	wsExControlParent = 0x00010000
	esAutoHScroll     = 0x0080
	esAutoVScroll     = 0x0040
	esMultiline       = 0x0004
	esReadOnly        = 0x0800
	esPassword        = 0x0020
	bsPushButton      = 0x0000
	bsDefPushButton   = 0x0001
	bsAutoCheckBox    = 0x0003
	bsAutoRadio       = 0x0009
	bsMultiLine       = 0x2000
	cbsDropDown       = 0x0002
	cbsDropDownList   = 0x0003
	ssLeft            = 0x0000
	ssNoPrefix        = 0x0080
	ssEditControl     = 0x2000
	pbsMarquee        = 0x08
)

const (
	swHide         = 0
	swShowNormal   = 1
	swShow         = 5
	swpNoZOrder    = 0x0004
	swpNoActivate  = 0x0010
	idOK           = 1
	idCancel       = 2
	idYes          = 6
	idNo           = 7
	mbOK           = 0x0
	mbYesNo        = 0x4
	mbYesNoCancel  = 0x3
	mbIconError    = 0x10
	mbIconQuestion = 0x20
	mbIconWarning  = 0x30
	mbIconInfo     = 0x40
	mfString       = 0x0000
	mfGrayed       = 0x0001
	mfSeparator    = 0x0800
	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	tpmBottomAlign = 0x0020
	dtLeft         = 0x0000
	dtWordBreak    = 0x0010
	dtSingleLine   = 0x0020
	dtVCenter      = 0x0004
	dtEndEllipsis  = 0x8000
	dtNoPrefix     = 0x0800
	transparent    = 1
	smCxScreen     = 0
	smCyScreen     = 1
	idcArrow       = 32512
	idcWait        = 32514
	diNormal       = 3
)

type point struct{ X, Y int32 }

type rect struct{ Left, Top, Right, Bottom int32 }

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type paintStruct struct {
	Hdc         uintptr
	Erase       int32
	Paint       rect
	Restore     int32
	IncUpdate   int32
	RGBReserved [32]byte
}

type logFont struct {
	Height         int32
	Width          int32
	Escapement     int32
	Orientation    int32
	Weight         int32
	Italic         byte
	Underline      byte
	StrikeOut      byte
	CharSet        byte
	OutPrecision   byte
	ClipPrecision  byte
	Quality        byte
	PitchAndFamily byte
	FaceName       [32]uint16
}

type iconInfo struct {
	Icon     int32
	XHotspot uint32
	YHotspot uint32
	Mask     uintptr
	Color    uintptr
}

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type notifyIconData struct {
	Size            uint32
	Wnd             uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32 // union with uTimeout
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        guid
	BalloonIcon     uintptr
}

type initCommonControlsEx struct {
	Size uint32
	ICC  uint32
}

// wstr converts a Go string for the Windows API.
func wstr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("")
	}
	return p
}

func ptr(s string) uintptr { return uintptr(unsafe.Pointer(wstr(s))) }

func loword(v uintptr) uint16 { return uint16(v & 0xFFFF) }
func hiword(v uintptr) uint16 { return uint16((v >> 16) & 0xFFFF) }

func send(h uintptr, m uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(h, uintptr(m), w, l)
	return r
}

func post(h uintptr, m uint32, w, l uintptr) {
	pPostMessageW.Call(h, uintptr(m), w, l)
}

func setText(h uintptr, s string) { pSetWindowTextW.Call(h, ptr(s)) }

func getText(h uintptr) string {
	n, _, _ := pGetWindowTextLengthW.Call(h)
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func enable(h uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	pEnableWindow.Call(h, v)
}

func show(h uintptr, on bool) {
	v := uintptr(swHide)
	if on {
		v = swShow
	}
	pShowWindow.Call(h, v)
}

func checked(h uintptr) bool { return send(h, bmGetCheck, 0, 0) == 1 }

func setChecked(h uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	send(h, bmSetCheck, v, 0)
}

func rgb(r, g, b byte) uintptr { return uintptr(r) | uintptr(g)<<8 | uintptr(b)<<16 }

// messageBox shows a standard message and returns the button pressed.
func messageBox(owner uintptr, text, title string, flags uintptr) uintptr {
	r, _, _ := pMessageBoxW.Call(owner, ptr(text), ptr(title), flags)
	return r
}

func moduleHandle() uintptr {
	h, _, _ := pGetModuleHandleW.Call(0)
	return h
}
