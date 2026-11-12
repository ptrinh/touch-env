// touchenv for Windows: secrets on this PC, every read behind Windows Hello. See ../docs/windows.md and internal/core.
package main

import (
	"os"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"github.com/ptrinh/touch-env/windows/internal/winplat"
	"golang.org/x/sys/windows/svc"
)

func main() {
	args := os.Args[1:]
	// Entry points touchenv starts itself; anything else goes to the command line.
	if len(args) >= 2 && args[0] == "service" {
		switch args[1] {
		case "run": // started by the Service Control Manager
			if isService, err := svc.IsWindowsService(); err == nil && isService {
				os.Exit(winplat.RunService(args[2:]))
			}
		case "install-elevated", "uninstall-elevated": // the copy Windows starts after the UAC prompt
			os.Exit(winplat.Elevated(args[1:]))
		}
	}
	if len(args) == 3 && args[0] == "ssh" && args[1] == "agent" && args[2] == "serve" {
		winplat.HideConsole() // the SSH agent runs in the background, started at logon
	}
	if len(args) == 1 && args[0] == "tray" {
		os.Exit(winplat.RunTray())
	}
	restore := winplat.UTF8Console()
	code := core.Main(args, core.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Platform: winplat.New(), Hello: winplat.NewHello(), Service: winplat.NewService(),
		SSH: winplat.NewSSHHost()})
	restore()
	os.Exit(code)
}
