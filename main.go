/*
 * SPDX-FileCopyrightText: 2024 OOMOL, Inc. <https://www.oomol.com>
 * SPDX-License-Identifier: MPL-2.0
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/oomol-lab/ovm-ssh-agent/pkg/identity"
	"github.com/oomol-lab/ovm-ssh-agent/pkg/sshagent"
)

type Log struct {
}

func (l *Log) Infof(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func (l *Log) Warnf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func main() {
	temp, err := os.MkdirTemp("", "ovm-ssh-agent")
	if err != nil {
		panic(temp)
	}

	pid := os.Getpid()

	socketPath := fmt.Sprintf("%s/agent.%d", temp, pid)

	log := &Log{}
	agent, err := sshagent.New(socketPath, log)
	if err != nil {
		panic(err)
	}

	fmt.Println("ssh agent socket path:", socketPath)

	if val, ok := os.LookupEnv("SSH_AUTH_SOCK"); ok {
		agent.SetExtendedAgent(val)
		fmt.Println("proxy ssh agent socket path:", val)
	}

	keys := identity.FindAll(log)
	if err := agent.AddIdentities(keys...); err != nil {
		panic(err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fmt.Println("stop ssh agent")
		agent.Close()
	}()

	fmt.Println("start ssh agent")
	agent.Listen()
}
