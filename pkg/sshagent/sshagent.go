/*
 * SPDX-FileCopyrightText: 2024 OOMOL, Inc. <https://www.oomol.com>
 * SPDX-License-Identifier: MPL-2.0
 */

package sshagent

import (
	"fmt"
	"io"
	"net"

	"github.com/oomol-lab/ovm-ssh-agent/pkg/types"
	"golang.org/x/crypto/ssh/agent"
)

type SSHAgent struct {
	socketPath string
	l          net.Listener
	log        types.Logger
	done       chan struct{}
	poxyAgent  *ProxyAgent
}

func New(socketPath string, log types.Logger) (*SSHAgent, error) {
	s := &SSHAgent{
		socketPath: socketPath,
		log:        log,
		done:       make(chan struct{}),
		poxyAgent:  NewProxyAgent(log),
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix socket failed: %w", err)
	}

	s.l = l

	return s, nil
}

func (s *SSHAgent) SetExtendedAgent(p string) {
	s.poxyAgent.SetExtendedAgent(p)
}

func (s *SSHAgent) AddIdentities(key ...agent.AddedKey) error {
	return s.poxyAgent.AddIdentities(key...)
}

func (s *SSHAgent) Listen() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				s.log.Warnf("error accepting socket connection: %v", err)
				return
			}
		}

		go func(conn net.Conn) {
			defer conn.Close()

			if err := agent.ServeAgent(s.poxyAgent, conn); err != io.EOF {
				s.log.Warnf("error serving agent: %v", err)
			}
		}(conn)
	}
}

func (s *SSHAgent) Close() {
	close(s.done)
	_ = s.l.Close()
}
