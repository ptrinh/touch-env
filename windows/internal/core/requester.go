package core

import "strings"

// Requester is who touchenv names in the prompt: the nearest ancestor that is not a shell or a wrapper.
type Requester struct {
	Name    string
	IsAgent bool
}

// Shells and wrappers between the asker and touchenv (lower case, no ".exe").
var passThrough = map[string]bool{
	"cmd": true, "powershell": true, "pwsh": true, "bash": true, "sh": true, "zsh": true, "fish": true, "dash": true,
	"env": true, "sudo": true, "gsudo": true, "conhost": true, "openconsole": true, "winpty-agent": true,
	"timeout": true, "xargs": true, "make": true, "mingw32-make": true, "nohup": true, "time": true, "script": true,
	"tmux": true, "screen": true, "wsl": true, "wslhost": true, "busybox": true,
}

// AI agents by executable name: they must say why (--intent). Same list as touchenv.swift.
var agents = map[string]bool{
	"claude": true, "codex": true, "cursor-agent": true, "gemini": true, "aider": true, "goose": true, "opencode": true,
}

var known = map[string]string{
	"claude": "Claude Code", "codex": "Codex", "cursor-agent": "Cursor", "cursor": "Cursor", "gemini": "Gemini CLI",
	"aider": "aider", "goose": "Goose", "opencode": "opencode", "windowsterminal": "Windows Terminal",
	"code": "VS Code", "wezterm-gui": "WezTerm", "alacritty": "Alacritty", "warp": "Warp", "mintty": "Git Bash",
	"explorer": "Windows", "kitty": "kitty", "tabby": "Tabby", "hyper": "Hyper",
}

// ClassifyChain picks the requester from the ancestor chain (nearest first), as touchenv.swift's requester() does.
func ClassifyChain(chain []Process) Requester {
	for i, p := range chain {
		if i >= 32 {
			break
		}
		base := p.Name
		if strings.HasSuffix(strings.ToLower(base), ".exe") {
			base = base[:len(base)-4]
		}
		name := strings.ToLower(base)
		if name == "" {
			break
		}
		if passThrough[strings.Trim(name, "-")] {
			continue
		}
		display := known[name]
		if display == "" {
			display = base
		}
		return Requester{Name: display, IsAgent: agents[name]}
	}
	return Requester{Name: "a process"}
}
