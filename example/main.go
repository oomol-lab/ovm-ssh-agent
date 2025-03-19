package main

import (
	"context"
	"fmt"
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

	localSocket := filepath.Join(os.TempDir(), "a.sock")
	_ = os.Remove(localSocket)

	sshAgent := sshagent.NewSSHAgent(ctx, upstreamSocket, localSocket)

	// find local private keys ~/.ssh
	{
		keys := identity.FindPrivateKeys()
		sshAgent.LoadLocalKeys(keys...)
	}

	fmt.Printf("start listening: %q", localSocket)

	if err := sshAgent.Serve(); err != nil {
		panic(fmt.Errorf("failed to serve: %w", err))
	}
}
