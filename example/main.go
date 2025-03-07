package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/oomol-lab/ovm-ssh-agent/pkg/identity"
	"github.com/oomol-lab/ovm-ssh-agent/pkg/sshagent"
	"github.com/oomol-lab/ovm-ssh-agent/pkg/system"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	upstreamSocket := system.GetSSHAgent()
	if upstreamSocket == "" {
		panic("failed to get remote auth socket")
	}

	sshAgent, err := sshagent.NewSSHAgent(ctx, upstreamSocket)
	if err != nil {
		panic(fmt.Errorf("failed to create agent: %w", err))
	}

	// find local private keys ~/.ssh
	{
		keys := identity.FindPrivateKeys()
		sshAgent.LoadLocalKeys(keys...)
	}

	localSocket := filepath.Join(os.TempDir(), "a.sock")
	_ = os.Remove(localSocket)
	fmt.Printf("start listening: %q", localSocket)
	listener, err := net.Listen("unix", localSocket)
	if err != nil {
		panic(fmt.Errorf("failed to listen unix socket: %w", err))
	}
	defer listener.Close()

	if err := sshAgent.Serve(listener); err != nil {
		panic(fmt.Errorf("failed to serve: %w", err))
	}
}
