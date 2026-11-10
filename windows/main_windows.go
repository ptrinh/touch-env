// touchenv for Windows: secrets on this PC, every read behind Windows Hello. See ../README.md and internal/core.
package main

import (
	"os"

	"github.com/ptrinh/touch-env/windows/internal/core"
	"github.com/ptrinh/touch-env/windows/internal/winplat"
)

func main() {
	restore := winplat.UTF8Console()
	code := core.Main(os.Args[1:], core.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Platform: winplat.New(), Hello: winplat.NewHello()})
	restore()
	os.Exit(code)
}
