package identity

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// FindConventionalPrivateKeys finds all private keys in ~/.ssh
func FindConventionalPrivateKeys() []string {
	dirname, err := os.UserHomeDir()

	if err != nil {
		logrus.Errorf("get user home dir failed: %v", err)
		return []string{}
	}

	sshDir := filepath.Join(dirname, ".ssh")

	keys := make([]string, 0)
	if err = filepath.Walk(sshDir, addPrivateKeyToList(&keys)); err != nil {
		logrus.Errorf("walk ssh dir failed: %v", err)
		return nil
	}

	logrus.Infof("key list: %v", keys)
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
				logrus.Warnf("ignoring file %s", path)
				return nil
			}
		}

		if strings.HasSuffix(info.Name(), ".pub") {
			logrus.Warnf("ignoring file %s cause end with .pub", path)
			return nil
		}

		// ignore large files
		if info.Size() > 1024*50 {
			logrus.Warnf("ignoring file %s cause size %d", path, info.Size())
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			logrus.Warnf("ignoring file, read file %s failed: %v", path, err)
			return nil
		}

		_, err = ssh.ParseRawPrivateKey(content)
		if err != nil {
			logrus.Warnf("ignoring file, parse private key %s failed: %v", path, err)
			return nil
		}

		*keys = append(*keys, path)

		return nil
	}
}
