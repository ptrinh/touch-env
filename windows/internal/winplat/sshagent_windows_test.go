package winplat

// Runs on Windows (CI): the SSH agent's pipe for real. An agent serving an empty keyring answers an ssh-agent client
// on \\.\pipe\touchenv-ssh-<SID> with the client's pid, a second agent can't start beside it, and stop ends it.
// (Windows Hello and the store are covered by core's tests with fakes.)

import (
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

func TestSSHAgentPipe(t *testing.T) {
	host := SSHHost{}
	pipe, err := host.AgentPipe()
	if err != nil {
		t.Fatal(err)
	}
	if pipeServer(pipe) != "" {
		t.Skip("an SSH agent is already running for this user")
	}
	pids := make(chan uint32, 8) // pipeServer's probes connect too; every client here is this process
	served := make(chan error, 1)
	go func() {
		served <- host.Serve(func(conn io.ReadWriteCloser, pid uint32) {
			pids <- pid
			agent.ServeAgent(agent.NewKeyring(), conn)
			conn.Close()
		})
	}()
	server := ""
	for i := 0; i < 50 && server == ""; i++ {
		if server = pipeServer(pipe); server == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if server == "" {
		t.Fatal("the agent didn't start serving")
	}

	h, err := windows.CreateFile(utf16z(pipe), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), pipe)
	keys, err := agent.NewClient(f).List()
	f.Close()
	if err != nil || len(keys) != 0 {
		t.Fatalf("List = %v, %v", keys, err)
	}
	if pid := <-pids; pid != windows.GetCurrentProcessId() {
		t.Fatalf("client pid %d, want %d", pid, windows.GetCurrentProcessId())
	}

	if err := (SSHHost{}).Serve(func(io.ReadWriteCloser, uint32) {}); err == nil {
		t.Fatal("a second agent started beside the first")
	}

	host.stop()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop didn't end the agent")
	}
}
