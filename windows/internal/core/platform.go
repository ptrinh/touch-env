package core

import (
	"crypto/rsa"
	"errors"
	"io"
)

// Hello is the Windows Hello key that guards the store. The real one (internal/winplat) is an RSA key in the
// Microsoft Passport key storage provider; tests use a software stand-in that counts prompts.
type Hello interface {
	// Ready says whether a prompt can be shown here and now (Hello set up, interactive desktop, not Remote
	// Desktop). The error's text is shown as is.
	Ready() error
	// PublicKey opens touchenv's key without any prompt and checks it was made the way touchenv makes it (Hello
	// asks on every use, private key not imported). ErrNoKey when there is none and create is false; with create,
	// makes one (Windows may ask for Hello to make it).
	PublicKey(create bool) (*rsa.PublicKey, error)
	// Decrypt undoes an RSA PKCS #1 v1.5 encryption to the key. Windows asks for Hello first, showing message.
	Decrypt(message string, ciphertext []byte) ([]byte, error)
	// Sign makes an RSA PKCS #1 v1.5 SHA-256 signature over digest. Windows asks for Hello first, showing message.
	Sign(message string, digest []byte) ([]byte, error)
}

var (
	// ErrNoKey: no Windows Hello key for touchenv yet.
	ErrNoKey = errors.New("no Windows Hello key")
	// ErrCancelled: the person said no (or let the prompt time out).
	ErrCancelled = errors.New("not approved")
)

// Process is one entry in the chain from touchenv's parent upward: the executable's base name without ".exe".
type Process struct {
	Name string
}

// Platform is everything else touchenv needs from Windows. Tests use a fake.
type Platform interface {
	// Ancestors lists the processes from touchenv's parent upward (nearest first).
	Ancestors() []Process
	// DataDir is where the store lives (%LOCALAPPDATA%\touchenv), made private to the user if missing.
	DataDir() (string, error)
	// WriteFilePrivate replaces path atomically with data, readable and writable by the user only.
	WriteFilePrivate(path string, data []byte) error
	// Lock serializes changes to the store across touchenv processes.
	Lock(path string) (unlock func(), err error)
	// ReadSecret reads a secret from stdin: one line with no echo from a console, else everything.
	ReadSecret(stdin io.Reader, stderr io.Writer) ([]byte, error)
	// StdoutIsTerminal: export refuses to print to a console.
	StdoutIsTerminal() bool
	// Hostname names this machine in exports.
	Hostname() string
	// NewRunDir makes a private folder for :file secrets. cleanup removes it and says whether it could.
	NewRunDir() (dir string, cleanup func() error, err error)
	// SweepRunDirs removes :file folders left by touchenv runs that ended without cleaning up.
	SweepRunDirs()
	// CommandLine is what will run, for the prompt: the resolved program and the exact command line Windows gets.
	// It fails when the command can't be shown faithfully (a .bat or .cmd with characters cmd.exe interprets).
	CommandLine(argv []string) (string, error)
	// Run runs argv with env (KEY=VALUE pairs), waits, and returns its exit code. Ctrl-C reaches the command;
	// touchenv keeps waiting so it can clean up.
	Run(argv []string, env []string) (int, error)
	// Environ is touchenv's own environment.
	Environ() []string
}

// Service reaches the touchenv service, which holds grants and 5-minute approvals (holder.go). Tests use one that
// runs a Holder in the same process.
type Service interface {
	// Dial connects to the service. ErrNoService when it isn't installed or isn't running; ErrNotService when
	// something else answers on its pipe.
	Dial() (io.ReadWriteCloser, error)
	// AskKeep shows the "Don't ask again for 5 minutes?" question (before Windows Hello): proceed false means the
	// person cancelled; keep true means they chose 5 minutes.
	AskKeep(text string) (proceed, keep bool, err error)
	// StartTray starts the notification-area icon that shows each use and offers Lock Now, unless one runs already.
	StartTray()
	// Install installs or updates the service (asking for administrator approval when needed); Uninstall removes
	// it. Both report to out.
	Install(offerKeep bool, out io.Writer) error
	Uninstall(out io.Writer) error
}

var (
	// ErrNoService: the touchenv service isn't installed, or isn't running.
	ErrNoService = errors.New("the touchenv service isn't running")
	// ErrNotService: something other than the touchenv service answers on its pipe.
	ErrNotService = errors.New("something other than the touchenv service is answering on \\\\.\\pipe\\touchenv")
)
