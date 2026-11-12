package winplat

// Runs on Windows (CI): the SSH agent's pipe for real. An agent serving an empty keyring answers an ssh-agent client
// on \\.\pipe\touchenv-ssh-<SID> with the client's pid, a second agent can't start beside it, and stop ends it.
// (Windows Hello and the store are covered by core's tests with fakes.)

import (
	"fmt"
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

	// ssh opens the pipe for overlapped I/O. So does this client; Go's agent client reads in the background while
	// it writes, which a synchronous handle can't do (the pending read would hold up the write for ever).
	answered := func(name string, ask func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- ask() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s client: %v", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("%s client: no answer in 10 seconds", name)
		}
		select {
		case pid := <-pids:
			if pid != windows.GetCurrentProcessId() {
				t.Errorf("%s client: pid %d, want %d", name, pid, windows.GetCurrentProcessId())
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s client: the agent never saw it", name)
		}
	}
	open := func(flags uint32) windows.Handle {
		t.Helper()
		h, err := windows.CreateFile(utf16z(pipe), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, flags, 0)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	for len(pids) > 0 { // pipeServer's probes
		<-pids
	}
	answered("overlapped", func() error {
		f := os.NewFile(uintptr(open(windows.FILE_FLAG_OVERLAPPED)), pipe)
		defer f.Close()
		keys, err := agent.NewClient(f).List()
		if err == nil && len(keys) != 0 {
			err = fmt.Errorf("%d keys from an empty keyring", len(keys))
		}
		return err
	})
	// A synchronous client that writes its request and then reads the answer, after the agent is already waiting.
	answered("synchronous", func() error {
		h := open(0)
		defer windows.CloseHandle(h)
		time.Sleep(300 * time.Millisecond)
		var n uint32
		if err := windows.WriteFile(h, []byte{0, 0, 0, 1, 11}, &n, nil); err != nil { // SSH_AGENTC_REQUEST_IDENTITIES
			return err
		}
		reply := make([]byte, 9)
		for got := 0; got < len(reply); got += int(n) {
			if err := windows.ReadFile(h, reply[got:], &n, nil); err != nil {
				return err
			}
		}
		if want := []byte{0, 0, 0, 5, 12, 0, 0, 0, 0}; string(reply) != string(want) { // SSH_AGENT_IDENTITIES_ANSWER, none
			return fmt.Errorf("reply % x, want % x", reply, want)
		}
		return nil
	})

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
