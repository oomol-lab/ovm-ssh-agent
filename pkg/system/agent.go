package system

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// GetSSHAgent get system agent
func GetSSHAgent() string {
	fallback := ""

	if s := GetSSHAgentEnv(); s != "" {
		if strings.Contains(s, "com.apple.launchd.") {
			fallback = s
		} else {
			return s
		}
	}

	if s := GetSSHAgent1Password(); s != "" {
		return s
	}

	if s := GetSSHAgentLaunchctl(); s != "" {
		return s
	}

	return fallback
}

// IsUnixSocket checks if the given file path is a Unix socket
func IsUnixSocket(filePath string) bool {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	if fileInfo.Mode()&os.ModeSocket == 0 {
		return false
	}

	return true
}

func GetSSHAgentEnv() string {
	val, ok := os.LookupEnv("SSH_AUTH_SOCK")
	if !ok {
		return ""
	}

	val = strings.TrimSpace(val)
	if !IsUnixSocket(val) {
		return ""
	}

	return val
}

func GetSSHAgentLaunchctl() string {
	output, err := exec.Command("/bin/launchctl", "asuser", strconv.Itoa(os.Getuid()), "launchctl", "getenv", "SSH_AUTH_SOCK").Output()
	if err != nil {
		return ""
	}

	val := string(bytes.TrimSpace(output))
	if !IsUnixSocket(val) {
		return ""
	}

	return val
}

func GetSSHAgent1Password() string {
	knownAgentPaths := []string{
		".1password/agent.sock",
		"Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	for _, agentPath := range knownAgentPaths {
		p := filepath.Join(homeDir, agentPath)
		if IsUnixSocket(p) {
			return p
		}
	}

	return ""
}
