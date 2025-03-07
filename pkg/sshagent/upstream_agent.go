package sshagent

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type upstreamAgent struct {
	conn   net.Conn
	agent  agent.ExtendedAgent
	socket string
	io.Closer
}

func newUpstreamAgent(socket string) *upstreamAgent {
	return &upstreamAgent{
		socket: socket,
	}
}

func (u *upstreamAgent) refresh() error {
	conn, err := net.Dial("unix", u.socket)
	if err != nil {
		return fmt.Errorf("failed to dial upstream agent: %w", err)
	}

	u.conn = conn
	u.agent = agent.NewClient(conn)

	return nil
}

func (u *upstreamAgent) List() ([]*agent.Key, error) {
	if err := u.refresh(); err != nil {
		return []*agent.Key{}, nil
	}

	defer u.conn.Close()

	return u.agent.List()
}

func (u *upstreamAgent) Signers() (out []ssh.Signer, _ error) {
	if err := u.refresh(); err != nil {
		return []ssh.Signer{}, nil
	}

	defer u.conn.Close()

	return u.agent.Signers()
}

func (u *upstreamAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if err := u.refresh(); err != nil {
		return nil, err
	}

	defer u.conn.Close()

	return u.agent.SignWithFlags(key, data, flags)
}

func (u *upstreamAgent) Close() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}
