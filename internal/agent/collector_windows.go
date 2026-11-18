//go:build windows

package agent

import (
	"bufio"
	"context"
	"encoding/csv"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
)

type windowsCollector struct{}

func newOSCollector(_ []string) OSCollector {
	return &windowsCollector{}
}

func (c *windowsCollector) CollectProcesses(ctx context.Context) ([]domain.ProcessInfo, error) {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(strings.NewReader(string(out)))
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var procs []domain.ProcessInfo
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(row[1]))
		procs = append(procs, domain.ProcessInfo{
			PID:  pid,
			Name: strings.TrimSpace(row[0]),
		})
	}
	return procs, nil
}

func (c *windowsCollector) CollectNetConnections(ctx context.Context) ([]domain.NetworkInfo, error) {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "netstat", "-ano").Output()
	if err != nil {
		return nil, err
	}
	var conns []domain.NetworkInfo
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || (fields[0] != "TCP" && fields[0] != "UDP") {
			continue
		}
		sIP, sPort := splitHostPort(fields[1])
		dIP, dPort := splitHostPort(fields[2])
		state := ""
		if len(fields) >= 5 {
			state = fields[3]
		}
		conns = append(conns, domain.NetworkInfo{
			Protocol: fields[0],
			SrcIP:    sIP,
			SrcPort:  sPort,
			DstIP:    dIP,
			DstPort:  dPort,
			State:    state,
		})
	}
	return conns, nil
}

func splitHostPort(s string) (string, int) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, 0
	}
	p, _ := strconv.Atoi(s[idx+1:])
	return strings.Trim(s[:idx], "[]"), p
}

func (c *windowsCollector) CollectAuthEvents(ctx context.Context) ([]domain.AuthInfo, error) {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	// Query recent Security log event IDs 4624 (logon) & 4625 (failed logon) if privilege permits.
	out, err := exec.CommandContext(cctx, "wevtutil", "qe", "Security", "/c:10", "/rd:true", "/f:text", "/q:*[System[(EventID=4624 or EventID=4625)]]").Output()
	if err != nil {
		return nil, nil
	}
	var auths []domain.AuthInfo
	txt := string(out)
	if strings.Contains(txt, "4625") {
		auths = append(auths, domain.AuthInfo{Outcome: "failure", Service: "windows-security-log"})
	}
	if strings.Contains(txt, "4624") {
		auths = append(auths, domain.AuthInfo{Outcome: "success", Service: "windows-security-log"})
	}
	return auths, nil
}

func (c *windowsCollector) CollectServices(ctx context.Context) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "sc", "query", "type=", "service", "state=", "running").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "SERVICE_NAME:") {
			svcs = append(svcs, strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:")))
		}
	}
	return svcs, nil
}

func (c *windowsCollector) CollectHostMetrics(_ context.Context) (HostMetrics, error) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	ip := "127.0.0.1"
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ip = ip4.String()
					break
				}
			}
		}
	}
	return HostMetrics{
		IPAddress:  ip,
		AgentRSSMB: float64(ms.Alloc) / (1024 * 1024),
	}, nil
}
