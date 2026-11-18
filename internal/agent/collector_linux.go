//go:build linux

package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
)

type linuxCollector struct {
	authLogPaths []string
	logOffsets   map[string]int64
	lastCPUTotal uint64
	lastCPUIdle  uint64
}

func newOSCollector(authPaths []string) OSCollector {
	if len(authPaths) == 0 {
		authPaths = []string{"/var/log/auth.log", "/var/log/secure"}
	}
	return &linuxCollector{
		authLogPaths: authPaths,
		logOffsets:   make(map[string]int64),
	}
}

// CollectProcesses inspects /proc/<pid> entries safely without spawning external shells.
func (c *linuxCollector) CollectProcesses(_ context.Context) ([]domain.ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []domain.ProcessInfo
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		base := filepath.Join("/proc", ent.Name())
		commRaw, err := os.ReadFile(filepath.Join(base, "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(commRaw))
		cmdRaw, _ := os.ReadFile(filepath.Join(base, "cmdline"))
		cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmdRaw), "\x00", " "))
		exe, _ := os.Readlink(filepath.Join(base, "exe"))
		ppid, uid := readProcStatus(filepath.Join(base, "status"))

		var sha string
		if exe != "" && len(out) < 60 {
			if st, err := os.Stat(exe); err == nil && st.Size() <= 8*1024*1024 {
				sha = quickHash(exe)
			}
		}

		out = append(out, domain.ProcessInfo{
			PID:        pid,
			PPID:       ppid,
			Name:       name,
			Executable: exe,
			Cmdline:    cmdline,
			User:       uid,
			SHA256:     sha,
		})
	}
	return out, nil
}

func readProcStatus(path string) (int, string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var ppid int
	var uid string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ppid, _ = strconv.Atoi(fields[1])
			}
		} else if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid = fields[1]
			}
		}
	}
	return ppid, uid
}

func quickHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 8*1024*1024)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CollectNetConnections parses /proc/net/tcp for passive socket state inventory.
func (c *linuxCollector) CollectNetConnections(_ context.Context) ([]domain.NetworkInfo, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var out []domain.NetworkInfo
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		srcIP, srcPort := parseProcAddr4(fields[1])
		dstIP, dstPort := parseProcAddr4(fields[2])
		out = append(out, domain.NetworkInfo{
			Protocol: "TCP",
			SrcIP:    srcIP,
			SrcPort:  srcPort,
			DstIP:    dstIP,
			DstPort:  dstPort,
			State:    tcpStateName(fields[3]),
		})
	}
	return out, sc.Err()
}

func parseProcAddr4(hexAddr string) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 || len(parts[0]) != 8 {
		return "", 0
	}
	rawIP, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return "", 0
	}
	port64, _ := strconv.ParseInt(parts[1], 16, 32)
	ip := net.IPv4(byte(rawIP), byte(rawIP>>8), byte(rawIP>>16), byte(rawIP>>24)).String()
	return ip, int(port64)
}

func tcpStateName(code string) string {
	switch code {
	case "01":
		return "ESTABLISHED"
	case "0A":
		return "LISTEN"
	case "06":
		return "TIME_WAIT"
	case "02":
		return "SYN_SENT"
	default:
		return code
	}
}

var (
	reSSHFailed  = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+)`)
	reSSHSuccess = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from (\S+)`)
)

// CollectAuthEvents tails configured Linux auth log files cleanly with byte offset persistence.
func (c *linuxCollector) CollectAuthEvents(_ context.Context) ([]domain.AuthInfo, error) {
	var out []domain.AuthInfo
	for _, p := range c.authLogPaths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		off, known := c.logOffsets[p]
		if !known || st.Size() < off {
			// Start at current EOF on initial startup or after log rotation
			off = st.Size()
			if !known && st.Size() > 8192 {
				off = st.Size() - 8192
			}
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		_, _ = f.Seek(off, io.SeekStart)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if m := reSSHFailed.FindStringSubmatch(line); len(m) == 3 {
				out = append(out, domain.AuthInfo{
					User:     m[1],
					SourceIP: m[2],
					Outcome:  "failure",
					Service:  "sshd",
					Method:   "password",
				})
			} else if m := reSSHSuccess.FindStringSubmatch(line); len(m) == 3 {
				out = append(out, domain.AuthInfo{
					User:     m[1],
					SourceIP: m[2],
					Outcome:  "success",
					Service:  "sshd",
					Method:   "auth",
				})
			}
		}
		newOff, _ := f.Seek(0, io.SeekCurrent)
		c.logOffsets[p] = newOff
		_ = f.Close()
	}
	return out, nil
}

// CollectServices enumerates active systemd units if systemctl is present.
func (c *linuxCollector) CollectServices(ctx context.Context) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend", "--plain").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 0 {
			svcs = append(svcs, fields[0])
		}
	}
	return svcs, nil
}

// CollectHostMetrics reads /proc/stat, /proc/meminfo, and Go runtime memory stats.
func (c *linuxCollector) CollectHostMetrics(_ context.Context) (HostMetrics, error) {
	m := HostMetrics{IPAddress: primaryIP()}

	var memTotalKB, memAvailKB float64
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseFloat(fields[1], 64)
			if fields[0] == "MemTotal:" {
				memTotalKB = val
			} else if fields[0] == "MemAvailable:" {
				memAvailKB = val
			}
		}
		if memTotalKB > 0 {
			m.MemoryTotalMB = memTotalKB / 1024.0
			m.MemoryUsedMB = (memTotalKB - memAvailKB) / 1024.0
		}
	}

	if raw, err := os.ReadFile("/proc/stat"); err == nil {
		lines := strings.Split(string(raw), "\n")
		if len(lines) > 0 && strings.HasPrefix(lines[0], "cpu ") {
			fields := strings.Fields(lines[0])[1:]
			var total, idle uint64
			for idx, f := range fields {
				v, _ := strconv.ParseUint(f, 10, 64)
				total += v
				if idx == 3 || idx == 4 {
					idle += v
				}
			}
			if c.lastCPUTotal > 0 && total > c.lastCPUTotal {
				dt := float64(total - c.lastCPUTotal)
				di := float64(idle - c.lastCPUIdle)
				m.CPUPercent = ((dt - di) / dt) * 100.0
			}
			c.lastCPUTotal = total
			c.lastCPUIdle = idle
		}
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.AgentRSSMB = float64(ms.Alloc) / (1024.0 * 1024.0)
	return m, nil
}

func primaryIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return fmt.Sprintf("127.0.0.1")
}
