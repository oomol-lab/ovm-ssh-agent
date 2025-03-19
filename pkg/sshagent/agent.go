package sshagent

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type SSHAgent struct {
	localAgent      agent.ExtendedAgent
	upstreamAgent   *upstreamAgent
	localSocketFile string

	context context.Context
	cancel  context.CancelFunc
}

func NewSSHAgent(ctx context.Context, upstreamSocket, localSocketFile string) *SSHAgent {
	ctx, cancel := context.WithCancel(ctx)

	sshAgent := &SSHAgent{
		localAgent:      agent.NewKeyring().(agent.ExtendedAgent),
		upstreamAgent:   newUpstreamAgent(upstreamSocket),
		localSocketFile: localSocketFile,
		context:         ctx,
		cancel:          cancel,
	}

	return sshAgent
}

// LoadLocalKeys load local keys from files
func (s *SSHAgent) LoadLocalKeys(keys ...string) {
	for _, f := range keys {
		r, err := os.ReadFile(f)
		if err != nil {
			continue
		}

		privateKey, err := ssh.ParseRawPrivateKey(r)
		if err != nil {
			continue
		}

		_ = s.localAgent.Add(agent.AddedKey{
			PrivateKey: privateKey,
		})
	}
}

func (s *SSHAgent) Serve() error {
	listener, err := net.Listen("unix", s.localSocketFile)
	if err != nil {
		return fmt.Errorf("failed to listen unix socket: %w", err)
	}
	context.AfterFunc(s.context, func() {
		_ = listener.Close()
	})

	for {
		if s.context.Err() != nil {
			return fmt.Errorf("stop ssh agent serve, because ctx done: %w", s.context.Err())
		}

		if conn, err := listener.Accept(); err == nil {
			go func(conn net.Conn) {
				_ = agent.ServeAgent(s, conn)
			}(conn)
		}
	}
}

// Remove only remove key from local agent
func (s *SSHAgent) Remove(key ssh.PublicKey) error {
	return s.localAgent.Remove(key)
}

// RemoveAll only remove all key from local agent
func (s *SSHAgent) RemoveAll() error {
	return s.localAgent.RemoveAll()
}

func (s *SSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.SignWithFlags(key, data, 0)
}

// Add only add private key into local agent
func (s *SSHAgent) Add(key agent.AddedKey) error {
	return s.localAgent.Add(key)
}

func (s *SSHAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return s.localAgent.Extension(extensionType, contents)
}

// List return all keys from upstream and local agent
func (s *SSHAgent) List() ([]*agent.Key, error) {
	keys := make([]*agent.Key, 0, 10)

	uks, err := s.upstreamAgent.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list upstream keys: %w", err)
	}
	keys = append(keys, uks...)

	lks, err := s.localAgent.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list local keys: %w", err)
	}

	keys = append(keys, lks...)
	return keys, nil
}

// Signers return all signers from upstream and local agent
func (s *SSHAgent) Signers() (out []ssh.Signer, _ error) {
	signer := make([]ssh.Signer, 0, 10)

	uks, err := s.upstreamAgent.Signers()
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream signers: %w", err)
	}
	signer = append(signer, uks...)

	localSigner, err := s.localAgent.Signers()
	if err != nil {
		return nil, fmt.Errorf("failed to get local signers: %w", err)
	}

	signer = append(signer, localSigner...)
	return signer, nil
}

// SignWithFlags generate signature a with public key from upstream and local agent
func (s *SSHAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if signature, err := s.upstreamAgent.SignWithFlags(key, data, flags); err == nil {
		return signature, nil
	}

	signature, err := s.localAgent.SignWithFlags(key, data, flags)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with local and upstream key: %w", err)
	}

	return signature, nil
}

// Unlock only unlock local agent
func (s *SSHAgent) Unlock(passphrase []byte) error {
	return s.localAgent.Unlock(passphrase)
}

// Lock only lock local agent
func (s *SSHAgent) Lock(passphrase []byte) error {
	return s.localAgent.Lock(passphrase)
}

func (s *SSHAgent) Close() {
	s.cancel()
	_ = s.upstreamAgent.Close()
}
