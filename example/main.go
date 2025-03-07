package main

import (
	"context"
	"github.com/oomol-lab/ovm-ssh-agent/pkg/identity"
	"github.com/oomol-lab/ovm-ssh-agent/pkg/sshagent"
	"github.com/oomol-lab/ovm-ssh-agent/pkg/system"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sshAgent, err := sshagent.NewSSHAgent(ctx)
	if err != nil {
		logrus.Fatalf("failed to create agent: %v", err)
	}

	// Conventional function to find local private keys ~/.ssh
	localPrivateKeys := identity.FindConventionalPrivateKeys()
	sshAgent.UsingLocalKeys(localPrivateKeys...)

	// Conventional function to find system auth socket
	localAuthSocket := system.GetSystemSSHAgentUDF()
	sshAgent.UsingUpstreamAgentSocks(localAuthSocket)

	socketFile := sshAgent.LocalAgent.SocketFile
	_ = os.Remove(socketFile)
	logrus.Infof("start listening: %q", socketFile)
	listener, err := net.Listen("unix", socketFile)
	if err != nil {
		logrus.Fatalf("failed to open socket:%v", err)
	}

	defer listener.Close()

	if err := sshAgent.Serve(listener); err != nil {
		logrus.Fatalf("serve exit: %q", err)
	}
}
