package identity

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// FindPrivateKeys finds all private keys in ~/.ssh
func FindPrivateKeys() (keys []string) {
	keys = make([]string, 0)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if err = filepath.Walk(sshDir, addPrivateKeyToList(&keys)); err != nil {
		return nil
	}

	return keys
}

func addPrivateKeyToList(keys *[]string) func(path string, info os.FileInfo, err error) error {
	ignoreFiles := []string{
		"authorized_keys",
		"known_hosts",
		"known_hosts.old",
		"config",
		".DS_Store",
		"allowed_signers",
	}

	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		for _, ignore := range ignoreFiles {
			if info.Name() == ignore {
				return nil
			}
		}

		if strings.HasSuffix(info.Name(), ".pub") {
			return nil
		}

		// ignore large files
		if info.Size() > 1024*50 {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		_, err = ssh.ParseRawPrivateKey(content)
		if err != nil {
			return nil
		}

		*keys = append(*keys, path)

		return nil
	}
}
