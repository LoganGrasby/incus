package drivers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// smolvmCmd implements the instance.Cmd interface for a streaming exec call
// against a per-instance smolvm-server. The actual SSE pump runs in a
// goroutine started by smolvm.Exec; this type just owns the wait/cancel
// handles and the captured exit status.
type smolvmCmd struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu       sync.Mutex
	exitCode int
	err      error
}

// PID returns 0 — the command runs inside the libkrun guest, not on the host.
func (c *smolvmCmd) PID() int { return 0 }

// Signal cancels the streaming exec for SIGKILL/SIGTERM and rejects everything
// else. The smolvm-server doesn't expose per-process signal forwarding; the
// best we can do is hang up the SSE stream, which the agent treats as an
// abort.
func (c *smolvmCmd) Signal(sig unix.Signal) error {
	switch sig {
	case unix.SIGKILL, unix.SIGTERM, unix.SIGINT:
		c.cancel()
		return nil
	}

	return errors.New("smolvm exec only supports SIGKILL/SIGTERM/SIGINT")
}

// WindowResize is unsupported — smolvm exec is non-interactive.
func (c *smolvmCmd) WindowResize(fd, width, height int) error {
	return errors.New("smolvm exec does not support PTY")
}

// Wait blocks until the streaming exec completes and returns the captured
// exit status (or -1 on transport error).
func (c *smolvmCmd) Wait() (int, error) {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitCode, c.err
}

// smolvmExecStartFailureExitCode maps an ExecStream startup error to a POSIX
// shell-style exit code (127 for missing binary, 126 for not-executable).
// Returns 0 if the error doesn't look like an exec startup failure.
//
// smolvm-server reports these as 5xx because the agent's execve fails after
// the API request has been accepted; the underlying Rust std::io::Error
// formatter passes the libc strerror through verbatim, so matching on
// "(os error 2)" / "(os error 13)" is the most robust signal we have.
func smolvmExecStartFailureExitCode(err error, command []string) (int, string) {
	if err == nil {
		return 0, ""
	}

	msg := err.Error()
	cmdName := ""
	if len(command) > 0 {
		cmdName = command[0]
	}

	switch {
	case strings.Contains(msg, "(os error 2)") || strings.Contains(msg, "No such file or directory"):
		return 127, fmt.Sprintf("exec: %q: not found", cmdName)
	case strings.Contains(msg, "(os error 13)") || strings.Contains(msg, "Permission denied"):
		return 126, fmt.Sprintf("exec: %q: Permission denied", cmdName)
	}

	return 0, ""
}
