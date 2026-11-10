package winplat

const cpUTF8 = 65001

var (
	procGetConsoleOutputCP = kernel32.NewProc("GetConsoleOutputCP")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
)

// UTF8Console switches the console to UTF-8 for touchenv's messages ("…", names) and returns a function that
// puts back what was there, so the shell is left as it was.
func UTF8Console() func() {
	before, _, _ := procGetConsoleOutputCP.Call()
	if before == 0 || before == cpUTF8 {
		return func() {}
	}
	procSetConsoleOutputCP.Call(cpUTF8)
	return func() { procSetConsoleOutputCP.Call(before) }
}
