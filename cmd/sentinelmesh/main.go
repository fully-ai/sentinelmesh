package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	scrypto "github.com/fully-ai/sentinelmesh/internal/crypto"
	"github.com/fully-ai/sentinelmesh/internal/detection"
	"github.com/fully-ai/sentinelmesh/internal/netmon"
	"github.com/fully-ai/sentinelmesh/internal/threatintel"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "pcap":
		cmdPCAP(os.Args[2:])
	case "rules":
		cmdRules(os.Args[2:])
	case "ioc":
		cmdIOC(os.Args[2:])
	case "api":
		cmdAPI(os.Args[2:])
	case "keygen":
		cmdKeygen()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`SentinelMesh Operator CLI

Usage:
  sentinelmesh pcap analyze <file.pcap>      Dissect an authorized PCAP and flag DNS/TLS anomalies
  sentinelmesh rules validate <rule.yml>     Validate YAML detection/correlation rule syntax
  sentinelmesh rules defaults                Print bundled detection rule IDs
  sentinelmesh ioc parse-csv <file.csv>      Parse and validate Threat Intel CSV indicators
  sentinelmesh api get <server_url> <path>   Query authenticated REST API (uses SENTINELMESH_TOKEN)
  sentinelmesh keygen                        Generate Ed25519 keypair for release manifest signing`)
}

func cmdPCAP(args []string) {
	if len(args) < 2 || args[0] != "analyze" {
		fmt.Fprintln(os.Stderr, "usage: sentinelmesh pcap analyze <file.pcap>")
		os.Exit(1)
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read pcap: %v\n", err)
		os.Exit(1)
	}
	summary, err := netmon.ParsePCAP(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse pcap: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(out))
}

func cmdRules(args []string) {
	if len(args) < 1 {
		os.Exit(1)
	}
	switch args[0] {
	case "validate":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: sentinelmesh rules validate <rule.yml>")
			os.Exit(1)
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "read rule: %v\n", err)
			os.Exit(1)
		}
		spec, err := detection.ParseRuleYAML(string(raw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID RULE: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("VALID RULE: %s (%s, severity=%s, version=%d)\n", spec.ID, spec.Name, spec.Severity, spec.Version)
	case "defaults":
		specs, _, err := detection.ParseDefaultRules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		for _, s := range specs {
			fmt.Printf("%-18s [%-8s] %s\n", s.ID, s.Severity, s.Name)
		}
	default:
		os.Exit(1)
	}
}

func cmdIOC(args []string) {
	if len(args) < 2 || args[0] != "parse-csv" {
		fmt.Fprintln(os.Stderr, "usage: sentinelmesh ioc parse-csv <file.csv>")
		os.Exit(1)
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read csv: %v\n", err)
		os.Exit(1)
	}
	list, err := threatintel.ParseCSV(raw, "default", time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse csv: %v\n", err)
		os.Exit(1)
	}
	out, _ := threatintel.ExportJSON(list)
	fmt.Println(string(out))
}

func cmdAPI(args []string) {
	if len(args) < 3 || args[0] != "get" {
		fmt.Fprintln(os.Stderr, "usage: sentinelmesh api get <server_url> <path>")
		os.Exit(1)
	}
	tok := os.Getenv("SENTINELMESH_TOKEN")
	url := strings.TrimRight(args[1], "/") + args[2]
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request: %v\n", err)
		os.Exit(1)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	fmt.Println(string(body))
	if resp.StatusCode >= 300 {
		os.Exit(1)
	}
}

func cmdKeygen() {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
	_ = scrypto.SHA256Hex(pub)
	fmt.Printf("ED25519_PUBLIC_B64=%s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("ED25519_PRIVATE_B64=%s\n", base64.StdEncoding.EncodeToString(priv))
}
