package agent

import (
	"net"
	"os"
	"runtime"
	"strings"
)

// osString returns a best-effort OS description (distro from os-release on
// Linux, else GOOS).
func osString() string {
	if runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
					return strings.Trim(v, `"`)
				}
			}
		}
		return "linux"
	}
	return runtime.GOOS
}

// localIPs returns non-loopback unicast addresses of the host.
func localIPs() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil || ipnet.IP.IsGlobalUnicast() {
				out = append(out, ipnet.IP.String())
			}
		}
	}
	return out
}
