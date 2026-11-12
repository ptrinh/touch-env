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

	// Clients of both kinds (ssh opens the pipe for overlapped I/O; other programs may not), writing at once and
	// after the agent is already waiting to read. None may hang.
	for _, c := range []struct {
		name       string
		overlapped bool
		delay      time.Duration
	}{{"overlapped", true, 0}, {"overlapped, agent reading first", true, 300 * time.Millisecond},
		{"synchronous", false, 0}, {"synchronous, agent reading first", false, 300 * time.Millisecond}} {
		flags := uint32(0)
		if c.overlapped {
			flags = windows.FILE_FLAG_OVERLAPPED
		}
		h, err := windows.CreateFile(utf16z(pipe), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, flags, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var conn io.ReadWriteCloser = os.NewFile(uintptr(h), pipe)
		if c.overlapped {
			if conn, err = newPipeConn(h); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(c.delay)
		listed := make(chan error, 1)
		go func() {
			keys, err := agent.NewClient(conn).List()
			if err == nil && len(keys) != 0 {
				err = fmt.Errorf("%d keys from an empty keyring", len(keys))
			}
			listed <- err
		}()
		select {
		case err := <-listed:
			if err != nil {
				t.Errorf("%s client: %v", c.name, err)
			}
			conn.Close()
		case <-time.After(10 * time.Second):
			t.Errorf("%s client: no answer in 10 seconds", c.name) // left open: closing could block too
		}
		select {
		case pid := <-pids:
			if pid != windows.GetCurrentProcessId() {
				t.Errorf("%s client: pid %d, want %d", c.name, pid, windows.GetCurrentProcessId())
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s client: the agent never saw it", c.name)
		}
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
