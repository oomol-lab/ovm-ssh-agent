/*
 * SPDX-FileCopyrightText: 2024 OOMOL, Inc. <https://www.oomol.com>
 * SPDX-License-Identifier: MPL-2.0
 */

package sshagent

import (
	"net"

	"github.com/oomol-lab/ovm-ssh-agent/pkg/types"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ProxyAgent struct {
	local              agent.Agent
	upstreamSocketPath string
	log                types.Logger
}

func NewProxyAgent(log types.Logger) *ProxyAgent {
	return &ProxyAgent{
		local: agent.NewKeyring(),
		log:   log,
	}
}

func (a *ProxyAgent) SetExtendedAgent(socketPath string) {
	a.upstreamSocketPath = socketPath
}

func (a *ProxyAgent) AddIdentities(key ...agent.AddedKey) error {
	for _, k := range key {
		if err := a.Add(k); err != nil {
			return err
		}
	}

	return nil
}

func (a *ProxyAgent) refreshExtendedAgent() agent.ExtendedAgent {
	p := a.upstreamSocketPath
	if p == "" {
		return nil
	}

	conn, err := net.Dial("unix", p)
	if err != nil {
		a.log.Warnf("dial extended agent failed: %v", err)
		return nil
	}

	return agent.NewClient(conn)
}

func (a *ProxyAgent) List() ([]*agent.Key, error) {
	l, err := a.local.List()

	if ea := a.refreshExtendedAgent(); ea != nil {
		us, err2 := ea.List()
		err = err2

		if err != nil {
			a.log.Warnf("get upstream list failed: %v", err)
		} else {
			l = append(l, us...)
		}
	}

	return l, err
}

func (a *ProxyAgent) Add(key agent.AddedKey) error {
	return a.local.Add(key)
}

func (a *ProxyAgent) Remove(key ssh.PublicKey) error {
	return a.local.Remove(key)
}

func (a *ProxyAgent) RemoveAll() error {
	return a.local.RemoveAll()
}

func (a *ProxyAgent) Lock(passphrase []byte) error {
	err := a.local.Lock(passphrase)
	if err != nil {
		a.log.Warnf("lock local agent failed: %v", err)
	}

	if ea := a.refreshExtendedAgent(); ea != nil {
		err = ea.Lock(passphrase)
	}

	return err
}

func (a *ProxyAgent) Unlock(passphrase []byte) error {
	err := a.local.Unlock(passphrase)
	if err != nil {
		a.log.Warnf("unlock local agent failed: %v", err)
	}

	if ea := a.refreshExtendedAgent(); ea != nil {
		err = ea.Unlock(passphrase)
	}

	return err
}

func (a *ProxyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	sig, err := a.local.Sign(key, data)
	if err == nil {
		return sig, nil
	}

	if ea := a.refreshExtendedAgent(); ea != nil {
		sig, err = ea.Sign(key, data)
	}

	return sig, err
}

func (a *ProxyAgent) Signers() ([]ssh.Signer, error) {
	signers, err := a.local.Signers()
	if err != nil {
		a.log.Warnf("get local signers failed: %v", err)
	}

	if ea := a.refreshExtendedAgent(); ea != nil {
		us, err2 := ea.Signers()
		err = err2

		if err != nil {
			a.log.Warnf("get upstream signers failed: %v", err)
		} else {
			signers = append(signers, us...)
		}
	}

	return signers, err
}

func (a *ProxyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	sig, err := a.local.(agent.ExtendedAgent).SignWithFlags(key, data, flags)
	if err == nil {
		return sig, nil
	}

	if ea := a.refreshExtendedAgent(); ea != nil {
		sig, err = ea.SignWithFlags(key, data, flags)
	}

	return sig, err
}

func (a *ProxyAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
