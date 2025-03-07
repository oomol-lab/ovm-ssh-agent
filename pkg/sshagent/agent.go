package sshagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type agentServer struct {
	AgentServer agent.ExtendedAgent
	SocketFile  string
}

type localAgent agentServer
type upstreamAgent agentServer

type SSHAgent struct {
	// agent server mode
	LocalAgent *localAgent
	// proxy mode, can work with agent server mod together
	upstreamAgent *upstreamAgent
	context       context.Context
	cancel        context.CancelFunc
}

func marshal(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func marshalPrivate(key interface{}) (string, error) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	return marshal(signer.PublicKey()), nil
}

func NewSSHAgent(ctx context.Context) (*SSHAgent, error) {
	ctx, cancel := context.WithCancel(ctx)
	sshAgent := &SSHAgent{
		LocalAgent: &localAgent{
			AgentServer: agent.NewKeyring().(agent.ExtendedAgent),
			// default listen dir is $TMPDIR/oo-ssh-agent.socks
			SocketFile: filepath.Join(os.TempDir(), "oo-ssh-agent.socks"),
		},
		upstreamAgent: nil,
		context:       ctx,
		cancel:        cancel,
	}
	return sshAgent, nil
}

// UsingUpstreamAgentSocks connect upstream ssh agent socks, current only support one
// upstream agent socks
func (s *SSHAgent) UsingUpstreamAgentSocks(socketFile string) {
	upstreamConn, err := net.Dial("unix", socketFile)
	if err != nil {
		logrus.Errorf("failed to refresh upstream agent: %v", err)
	}
	s.upstreamAgent = &upstreamAgent{
		AgentServer: agent.NewClient(upstreamConn),
		SocketFile:  socketFile,
	}
}

// UsingLocalKeys load local keys from files
func (s *SSHAgent) UsingLocalKeys(keys ...string) {
	for _, f := range keys {
		r, err := os.ReadFile(f)
		if err != nil {
			logrus.Errorf("failed to read file %q: %v", f, err)
			continue
		}
		privateKey, err := ssh.ParseRawPrivateKey(r)
		if err != nil {
			logrus.Errorf("failed to parse private key %q: %v", f, err)
			continue
		}

		addedKey := agent.AddedKey{
			PrivateKey: privateKey,
		}

		if err = s.LocalAgent.AgentServer.Add(addedKey); err != nil {
			logrus.Errorf("failed to add key %q: %v", f, err)
		}
	}
}

// refreshUpstreamAgent reconnect upstream agent socket
func (s *SSHAgent) refreshUpstreamAgent() {
	if s.upstreamAgent != nil {
		s.UsingUpstreamAgentSocks(s.upstreamAgent.SocketFile)
	}
}

func (s *SSHAgent) Serve(listener net.Listener) error {
	connChan, errs := make(chan net.Conn), make(chan error)
	go func() {
		for {
			if conn, err := listener.Accept(); err != nil {
				errs <- err
			} else {
				connChan <- conn
			}
		}
	}()
	for {
		select {
		case <-s.context.Done():
			return context.Cause(s.context)
		case conn := <-connChan:
			logrus.Infoln("receiving new connection")
			go func(conn net.Conn) {
				if err := agent.ServeAgent(s, conn); err != nil && err != io.EOF {
					errs <- err
				}
			}(conn)
		case err := <-errs:
			return fmt.Errorf("unexpected error: %w", err)
		}
	}
}

// Remove only remove key from local agent
func (s *SSHAgent) Remove(key ssh.PublicKey) error {
	logrus.Infof("removing a key: %q", marshal(key))
	return s.LocalAgent.AgentServer.Remove(key)
}

// RemoveAll only remove all key from local agent
func (s *SSHAgent) RemoveAll() error {
	logrus.Infof("removing all keys")
	return s.LocalAgent.AgentServer.RemoveAll()
}

func (s *SSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	logrus.Infof("signing data with a piblic key: %q", marshal(key))
	return s.SignWithFlags(key, data, 0)
}

func flagsToString(flags agent.SignatureFlags) string {
	out, underlying := "", flags
	if underlying&agent.SignatureFlagReserved == agent.SignatureFlagReserved {
		out += "|reserved"
	}
	if underlying&agent.SignatureFlagRsaSha256 == agent.SignatureFlagRsaSha256 {
		out += "|rsa-sha256"
	}
	if underlying&agent.SignatureFlagRsaSha512 == agent.SignatureFlagRsaSha512 {
		out += "|rsa-sha256"
	}
	if out == "" {
		return "none"
	}
	return out[1:]
}

// Add only add private key into local agent
func (s *SSHAgent) Add(key agent.AddedKey) error {
	privateKey, err := marshalPrivate(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	logrus.Infof("adding new key: %q", privateKey)
	return s.LocalAgent.AgentServer.Add(key)
}

func (s *SSHAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	logrus.Infof("extension type: %q", extensionType)
	return s.LocalAgent.AgentServer.Extension(extensionType, contents)
}

// List return all keys from upstream and local agent
func (s *SSHAgent) List() ([]*agent.Key, error) {
	logrus.Infof("listing keys")
	keys := make([]*agent.Key, 0)

	// get keys list from upstream agent
	if s.upstreamAgent != nil {
		logrus.Infof("List(): refreshUpstreamAgent")
		s.refreshUpstreamAgent()
		upstreamKeys, err := s.upstreamAgent.AgentServer.List()
		if err != nil {
			return nil, fmt.Errorf("failed to list upstream keys: %w", err)
		}
		keys = append(keys, upstreamKeys...)
	}

	localKeys, err := s.LocalAgent.AgentServer.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list local keys: %w", err)
	}
	keys = append(keys, localKeys...)
	return keys, nil
}

// Signers return all signers from upstream and local agent
func (s *SSHAgent) Signers() (out []ssh.Signer, _ error) {
	logrus.Infof("returning signers")
	signer := make([]ssh.Signer, 0)

	// get signer from upstream agent
	if s.upstreamAgent != nil {
		logrus.Infof("Signers(): refreshUpstreamAgent")
		s.refreshUpstreamAgent()
		upstreamSigner, err := s.upstreamAgent.AgentServer.Signers()
		if err != nil {
			return nil, fmt.Errorf("failed to get upstream signers: %w", err)
		}
		signer = append(signer, upstreamSigner...)
	}

	localSigner, err := s.LocalAgent.AgentServer.Signers()
	if err != nil {
		return nil, fmt.Errorf("failed to get local signers: %w", err)
	}
	signer = append(signer, localSigner...)
	return signer, nil
}

// SignWithFlags generate signature a with public key from upstream and local agent
func (s *SSHAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	// First try upstreamAgent
	if s.upstreamAgent != nil {
		logrus.Infof("SignWithFlags(): refreshUpstreamAgent")
		s.refreshUpstreamAgent()
		logrus.Infof("try using upstream agent signing data with key %q and flag: %q", ssh.MarshalAuthorizedKey(key), flagsToString(flags))
		signature, err := s.upstreamAgent.AgentServer.SignWithFlags(key, data, flags)
		if err != nil {
			logrus.Infof("SignWithFlags with upstream agent err: %v", err)
		} else {
			return signature, nil
		}
	}

	logrus.Infof("try using local agent signing data with key %q and flag: %q", ssh.MarshalAuthorizedKey(key), flagsToString(flags))
	signature, err := s.LocalAgent.AgentServer.SignWithFlags(key, data, flags)
	if err != nil {
		logrus.Infof("SignWithFlags with local agent error: %v", err)
	} else {
		return signature, nil
	}

	return nil, errors.New("failed to sign data using upstream and local agent")
}

// Unlock only unlock local agent
func (s *SSHAgent) Unlock(passphrase []byte) error {
	logrus.Infof("try unlocking agent")
	return s.LocalAgent.AgentServer.Unlock(passphrase)
}

// Lock only lock local agent
func (s *SSHAgent) Lock(passphrase []byte) error {
	logrus.Infof("try locking agent")
	return s.LocalAgent.AgentServer.Lock(passphrase)
}

func (s *SSHAgent) Close() {
	s.cancel()
}
