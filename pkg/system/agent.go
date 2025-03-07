package system

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// GetSystemSSHAgentUDF get system agent UFD,
func GetSystemSSHAgentUDF() string {
	upstreamSocket := ""
	if socketFile := getFromEnv(); socketFile != "" {
		logrus.Infof("using socket file from $SSH_AUTH_SOCK as upstream agent socket: %q", socketFile)
		upstreamSocket = socketFile
	} else if socketFile = getFromLaunchctl(); socketFile != "" {
		logrus.Infof("using socket file from launchctl as upstream agent socket: %q", socketFile)
		upstreamSocket = socketFile
	} else if socketFile = getFrom1Password(); socketFile != "" {
		upstreamSocket = socketFile
	}

	// if upstreamSocket unix socket file, return empty
	if !isUnixSocket(upstreamSocket) {
		return ""
	}

	return upstreamSocket
}

// isUnixSocket checks if the given file path is a Unix socket.
func isUnixSocket(filePath string) bool {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		logrus.Warnf("failed to stat file %q: %v", filePath, err)
		return false
	}

	if fileInfo.Mode()&os.ModeSocket == 0 {
		logrus.Warnf("file %q exists but is not a unix socket", filePath)
		return false
	}

	return true
}

func getFromEnv() string {
	val, ok := os.LookupEnv("SSH_AUTH_SOCK")
	if !ok {
		return ""
	}

	return strings.TrimSpace(val)
}

func getFromLaunchctl() string {
	output, err := exec.Command("/bin/launchctl", "asuser", strconv.Itoa(os.Getuid()), "launchctl", "getenv", "SSH_AUTH_SOCK").Output()
	if err != nil {
		logrus.Warnf("failed to get auth socket from launchctl: %v", err)
		return ""
	}

	return string(bytes.TrimSpace(output))
}

func getFrom1Password() string {
	knownAgentPaths := []string{
		".1password/agent.sock",
		"Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
	}

	for _, agentPath := range knownAgentPaths {
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		if isUnixSocket(filepath.Join(userHomeDir, agentPath)) {
			return agentPath
		}
	}
	return ""
}
