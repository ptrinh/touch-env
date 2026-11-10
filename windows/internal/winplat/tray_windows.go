package winplat

// "touchenv tray": the notification-area icon while a grant or 5-minute approval is on, like the Mac's menu bar
// item. It shows the time left, lists what is allowed, offers Lock Now, and pops a notification each time one is
// used. It runs as you in your session and only shows what the service tells it: a program running as you can close
// it, so it is a way to see, not a safeguard. touchenv status shows the same from the service at any time.

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"golang.org/x/sys/windows"
)

var (
	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostMessage      = user32.NewProc("PostMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procSetTimer         = user32.NewProc("SetTimer")
	procLoadIcon         = user32.NewProc("LoadIconW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wmTimer       = 0x0113
	wmCommand     = 0x0111
	wmApp         = 0x8000
	wmTrayIcon    = wmApp + 1
	wmUpdate      = wmApp + 2
	wmRButtonUp   = 0x0205
	wmLButtonUp   = 0x0202
	wmContextMenu = 0x007B
	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nifMessage    = 0x1
	nifIcon       = 0x2
	nifTip        = 0x4
	nifInfo       = 0x10
	niifInfo      = 0x1
	mfString      = 0x0
	mfGrayed      = 0x1
	mfSeparator   = 0x800
	tpmReturnCmd  = 0x100
	tpmRightBtn   = 0x2
	idiShield     = 32518
	cmdLock       = 1
)

// notifyIconData is NOTIFYICONDATAW.
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
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        windows.GUID
	BalloonIcon     uintptr
}

// wndClassEx is WNDCLASSEXW.
type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type msg struct {
	Wnd     uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
	Private uint32
}

type tray struct {
	mu       sync.Mutex
	wnd      uintptr
	icon     uintptr
	items    []core.Item
	received time.Time // when items arrived (their Left counts from then)
	notices  []core.Notice
	seen     bool      // got at least one non-empty state
	shown    time.Time // last notice, kept on screen a few seconds even after the last use
	closed   bool
}

var theTray tray

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(strings.ReplaceAll(s, "\x00", ""))
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

func (t *tray) left(it core.Item) int {
	return max(0, it.Left-int(time.Since(t.received)/time.Second))
}

func (t *tray) notify(op uintptr, flags uint32, fill func(*notifyIconData)) {
	d := notifyIconData{Wnd: t.wnd, ID: 1, Flags: flags, CallbackMessage: wmTrayIcon, Icon: t.icon}
	d.Size = uint32(unsafe.Sizeof(d))
	if fill != nil {
		fill(&d)
	}
	procShellNotifyIcon.Call(op, uintptr(unsafe.Pointer(&d)))
}

// refresh updates the tooltip, shows queued notices, and quits when nothing is left.
func (t *tray) refresh() {
	t.mu.Lock()
	items, notices, closed := t.items, t.notices, t.closed
	t.notices = nil
	if len(notices) > 0 {
		t.shown = time.Now()
	}
	recent := time.Since(t.shown) < 8*time.Second
	longest := 0
	for _, it := range items {
		longest = max(longest, t.left(it))
	}
	t.mu.Unlock()
	if closed && !recent || (t.seen && longest == 0 && !recent) {
		t.notify(nimDelete, 0, nil)
		procPostQuitMessage.Call(0)
		return
	}
	tip := "touchenv: " + core.Clock(longest) + " left. Right-click: Lock Now"
	t.notify(nimModify, nifTip, func(d *notifyIconData) { copyUTF16(d.Tip[:], tip) })
	for _, n := range notices {
		body := n.Detail
		if n.Intent != "" {
			body = "Intent: " + n.Intent + "\n" + body
		}
		t.notify(nimModify, nifInfo, func(d *notifyIconData) {
			copyUTF16(d.InfoTitle[:], n.Title)
			copyUTF16(d.Info[:], body)
			d.InfoFlags = niifInfo
		})
	}
}

func (t *tray) menu() {
	t.mu.Lock()
	var lines []string
	for _, it := range t.items {
		names := strings.Join(it.Names, ", ")
		if it.Grant {
			lines = append(lines, fmt.Sprintf("%s and what it runs can read %s without asking: %s, %s left",
				it.Who, names, core.Times(it.Uses), core.Clock(t.left(it))))
		} else {
			lines = append(lines, fmt.Sprintf("%s can read %s without asking", it.Who, names))
		}
	}
	t.mu.Unlock()
	m, _, _ := procCreatePopupMenu.Call()
	if m == 0 {
		return
	}
	defer procDestroyMenu.Call(m)
	for _, line := range lines {
		procAppendMenu.Call(m, mfString|mfGrayed, 0, uintptr(unsafe.Pointer(utf16z(line))))
	}
	procAppendMenu.Call(m, mfSeparator, 0, 0)
	procAppendMenu.Call(m, mfString, cmdLock, uintptr(unsafe.Pointer(utf16z("Lock Now"))))
	var pt struct{ X, Y int32 }
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWin.Call(t.wnd)
	cmd, _, _ := procTrackPopupMenu.Call(m, tpmReturnCmd|tpmRightBtn, uintptr(pt.X), uintptr(pt.Y), 0, t.wnd, 0)
	if cmd == cmdLock {
		go lockNow()
	}
}

func lockNow() {
	conn, err := (Service{}).Dial()
	if err != nil {
		return
	}
	core.Ask(conn, core.Request{Op: "lock"})
	conn.Close()
}

func trayProc(wnd, message, wParam, lParam uintptr) uintptr {
	switch uint32(message) {
	case wmTrayIcon:
		switch uint32(lParam) & 0xFFFF {
		case wmRButtonUp, wmLButtonUp, wmContextMenu:
			theTray.menu()
		}
		return 0
	case wmUpdate, wmTimer:
		theTray.refresh()
		return 0
	}
	r, _, _ := procDefWindowProc.Call(wnd, message, wParam, lParam)
	return r
}

// watch reads the service's events for this session until it hangs up.
func (t *tray) watch() {
	defer func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		procPostMessage.Call(t.wnd, wmUpdate, 0, 0)
	}()
	conn, err := (Service{}).Dial()
	if err != nil {
		return
	}
	defer conn.Close()
	if err := core.WriteFrame(conn, core.Request{V: core.ProtocolVersion, Op: "watch"}, nil); err != nil {
		return
	}
	for {
		var reply core.Reply
		if _, err := core.ReadFrame(conn, &reply); err != nil || reply.Event == nil {
			return
		}
		t.mu.Lock()
		t.items, t.received = reply.Event.Items, time.Now()
		if len(reply.Event.Items) > 0 {
			t.seen = true
		}
		if reply.Event.Notice != nil {
			t.notices = append(t.notices, *reply.Event.Notice)
		}
		t.mu.Unlock()
		procPostMessage.Call(t.wnd, wmUpdate, 0, 0)
	}
}

// RunTray runs "touchenv tray": one per session (a named mutex), gone when nothing is allowed any more.
func RunTray() int {
	runtime.LockOSThread()
	mutex, err := windows.CreateMutex(nil, false, utf16z(trayMutexName))
	if err != nil { // ERROR_ALREADY_EXISTS: one runs already
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		return 0
	}
	defer windows.CloseHandle(mutex)
	t := &theTray
	class := utf16z("touchenvTray")
	wc := wndClassEx{WndProc: windows.NewCallback(trayProc), ClassName: class}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, _ := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return 1
	}
	t.wnd, _, _ = procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(utf16z("touchenv"))),
		0, 0, 0, 0, 0, 0, 0, 0, 0)
	if t.wnd == 0 {
		return 1
	}
	t.icon, _, _ = procLoadIcon.Call(0, idiShield)
	t.notify(nimAdd, nifMessage|nifIcon|nifTip, func(d *notifyIconData) { copyUTF16(d.Tip[:], "touchenv") })
	procSetTimer.Call(t.wnd, 1, 1000, 0)
	go t.watch()
	// If no grant shows up in the first seconds (the one that started the tray failed), stop.
	go func() {
		time.Sleep(15 * time.Second)
		t.mu.Lock()
		if !t.seen {
			t.closed = true
		}
		t.mu.Unlock()
		procPostMessage.Call(t.wnd, wmUpdate, 0, 0)
	}()
	var m msg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	t.notify(nimDelete, 0, nil)
	return 0
}
