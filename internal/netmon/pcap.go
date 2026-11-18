package netmon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/google/uuid"
)

const (
	pcapMagicLE  uint32 = 0xa1b2c3d4
	pcapMagicBE  uint32 = 0xd4c3b2a1
	maxPacketLen        = 65535
)

// PacketRecord summarizes a parsed network packet from an authorized PCAP capture.
type PacketRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	Protocol   string    `json:"protocol"`
	SrcIP      string    `json:"src_ip"`
	SrcPort    int       `json:"src_port,omitempty"`
	DstIP      string    `json:"dst_ip"`
	DstPort    int       `json:"dst_port,omitempty"`
	Length     int       `json:"length"`
	DNSQuery   string    `json:"dns_query,omitempty"`
	DNSAnomaly bool      `json:"dns_anomaly,omitempty"`
	TLSSNI     string    `json:"tls_sni,omitempty"`
}

// PCAPSummary aggregates protocol, endpoint, and anomaly telemetry from a PCAP.
type PCAPSummary struct {
	PacketCount int            `json:"packet_count"`
	ByteCount   uint64         `json:"byte_count"`
	Protocols   map[string]int `json:"protocols"`
	DNSQueries  []string       `json:"dns_queries,omitempty"`
	TLSSNIs     []string       `json:"tls_snis,omitempty"`
	Anomalies   []string       `json:"anomalies,omitempty"`
	TopTalkers  map[string]int `json:"top_talkers"`
	Packets     []PacketRecord `json:"packets"`
}

// ParsePCAP dissects a libpcap byte buffer safely without panics or unbounded allocations.
func ParsePCAP(data []byte) (*PCAPSummary, error) {
	if len(data) < 24 {
		return nil, errors.New("pcap too small for global header")
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	var bo binary.ByteOrder
	switch magic {
	case pcapMagicLE:
		bo = binary.LittleEndian
	case pcapMagicBE:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("unsupported pcap magic 0x%08x", magic)
	}

	linkType := bo.Uint32(data[20:24])
	if linkType != 1 { // LINKTYPE_ETHERNET
		return nil, fmt.Errorf("unsupported pcap linktype %d (expected Ethernet=1)", linkType)
	}

	summary := &PCAPSummary{
		Protocols:  make(map[string]int),
		TopTalkers: make(map[string]int),
	}

	offset := 24
	for offset+16 <= len(data) {
		tsSec := bo.Uint32(data[offset : offset+4])
		tsUsec := bo.Uint32(data[offset+4 : offset+8])
		inclLen := bo.Uint32(data[offset+8 : offset+12])
		origLen := bo.Uint32(data[offset+12 : offset+16])
		offset += 16

		if inclLen > maxPacketLen || int(inclLen) > len(data)-offset {
			break
		}
		pkt := data[offset : offset+int(inclLen)]
		offset += int(inclLen)

		rec := parseEthernetFrame(pkt, time.Unix(int64(tsSec), int64(tsUsec)*1000).UTC(), int(origLen))
		summary.PacketCount++
		summary.ByteCount += uint64(origLen)
		if rec.Protocol != "" {
			summary.Protocols[rec.Protocol]++
		}
		if rec.SrcIP != "" {
			summary.TopTalkers[rec.SrcIP]++
		}
		if rec.DNSQuery != "" {
			summary.DNSQueries = append(summary.DNSQueries, rec.DNSQuery)
			if rec.DNSAnomaly {
				summary.Anomalies = append(summary.Anomalies, fmt.Sprintf("High-entropy/long DNS query: %s", rec.DNSQuery))
			}
		}
		if rec.TLSSNI != "" {
			summary.TLSSNIs = append(summary.TLSSNIs, rec.TLSSNI)
		}
		if len(summary.Packets) < 500 {
			summary.Packets = append(summary.Packets, rec)
		}
	}
	return summary, nil
}

func parseEthernetFrame(pkt []byte, ts time.Time, origLen int) PacketRecord {
	rec := PacketRecord{Timestamp: ts, Length: origLen, Protocol: "OTHER"}
	if len(pkt) < 14 {
		return rec
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	l3 := pkt[14:]
	if etherType == 0x8100 && len(l3) >= 4 {
		etherType = binary.BigEndian.Uint16(l3[2:4])
		l3 = l3[4:]
	}

	var proto byte
	var l4 []byte
	switch etherType {
	case 0x0800: // IPv4
		if len(l3) < 20 {
			return rec
		}
		ihl := int(l3[0]&0x0f) * 4
		if ihl < 20 || len(l3) < ihl {
			return rec
		}
		proto = l3[9]
		rec.SrcIP = net.IP(l3[12:16]).String()
		rec.DstIP = net.IP(l3[16:20]).String()
		l4 = l3[ihl:]
	case 0x86dd: // IPv6
		if len(l3) < 40 {
			return rec
		}
		proto = l3[6]
		rec.SrcIP = net.IP(l3[8:24]).String()
		rec.DstIP = net.IP(l3[24:40]).String()
		l4 = l3[40:]
	default:
		if etherType == 0x0806 {
			rec.Protocol = "ARP"
		}
		return rec
	}

	switch proto {
	case 1, 58:
		rec.Protocol = "ICMP"
	case 6: // TCP
		rec.Protocol = "TCP"
		if len(l4) >= 20 {
			rec.SrcPort = int(binary.BigEndian.Uint16(l4[0:2]))
			rec.DstPort = int(binary.BigEndian.Uint16(l4[2:4]))
			dataOff := int((l4[12]>>4)&0x0f) * 4
			if dataOff >= 20 && len(l4) > dataOff {
				payload := l4[dataOff:]
				if rec.DstPort == 443 || rec.SrcPort == 443 {
					if sni := extractTLSSNI(payload); sni != "" {
						rec.TLSSNI = sni
						rec.Protocol = "TLS"
					}
				}
			}
		}
	case 17: // UDP
		rec.Protocol = "UDP"
		if len(l4) >= 8 {
			rec.SrcPort = int(binary.BigEndian.Uint16(l4[0:2]))
			rec.DstPort = int(binary.BigEndian.Uint16(l4[2:4]))
			payload := l4[8:]
			if rec.DstPort == 53 || rec.SrcPort == 53 {
				if qname := extractDNSQName(payload); qname != "" {
					rec.Protocol = "DNS"
					rec.DNSQuery = qname
					rec.DNSAnomaly = isSuspiciousDNSName(qname)
				}
			}
		}
	}
	return rec
}

func extractDNSQName(payload []byte) string {
	if len(payload) < 13 {
		return ""
	}
	qdCount := binary.BigEndian.Uint16(payload[4:6])
	if qdCount == 0 {
		return ""
	}
	name, _ := decodeDNSName(payload, 12, 0)
	return name
}

func decodeDNSName(msg []byte, pos, depth int) (string, int) {
	if depth > 8 || pos < 0 || pos >= len(msg) {
		return "", pos
	}
	var labels []string
	cur := pos
	jumped := false
	endPos := pos
	for steps := 0; steps < 64 && cur < len(msg); steps++ {
		ln := int(msg[cur])
		if ln == 0 {
			if !jumped {
				endPos = cur + 1
			}
			break
		}
		if ln&0xc0 == 0xc0 {
			if cur+1 >= len(msg) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(msg[cur:cur+2]) & 0x3fff)
			if !jumped {
				endPos = cur + 2
			}
			sub, _ := decodeDNSName(msg, ptr, depth+1)
			if sub != "" {
				labels = append(labels, sub)
			}
			jumped = true
			break
		}
		if ln > 63 || cur+1+ln > len(msg) {
			break
		}
		label := string(msg[cur+1 : cur+1+ln])
		labels = append(labels, label)
		cur += 1 + ln
		if !jumped {
			endPos = cur
		}
	}
	return strings.Join(labels, "."), endPos
}

func extractTLSSNI(payload []byte) string {
	// TLS Record (5 bytes) + Handshake header (4) + Version (2) + Random (32)
	if len(payload) < 44 || payload[0] != 0x16 || payload[5] != 0x01 {
		return ""
	}
	pos := 43
	if pos >= len(payload) {
		return ""
	}
	sessLen := int(payload[pos])
	pos += 1 + sessLen
	if pos+2 > len(payload) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + cipherLen
	if pos+1 > len(payload) {
		return ""
	}
	compLen := int(payload[pos])
	pos += 1 + compLen
	if pos+2 > len(payload) {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotal
	if extEnd > len(payload) {
		extEnd = len(payload)
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		if extType == 0 && extLen >= 5 { // server_name
			nameLen := int(binary.BigEndian.Uint16(payload[pos+3 : pos+5]))
			if 5+nameLen <= extLen {
				return string(payload[pos+5 : pos+5+nameLen])
			}
		}
		pos += extLen
	}
	return ""
}

// isSuspiciousDNSName flags unusually long or high-entropy leftmost DNS labels.
func isSuspiciousDNSName(name string) bool {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(parts) < 2 {
		return false
	}
	sub := parts[0]
	if len(sub) >= 40 {
		return true
	}
	if len(sub) >= 24 && shannonEntropy(sub) >= 3.8 {
		return true
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var ent float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// PacketsToEvents converts parsed PCAP records into canonical SentinelMesh network events.
func PacketsToEvents(tenantID, agentID, host string, summary *PCAPSummary) []domain.Event {
	out := make([]domain.Event, 0, len(summary.Packets))
	for _, p := range summary.Packets {
		if p.SrcIP == "" && p.DstIP == "" {
			continue
		}
		sev := domain.SeverityInfo
		meta := map[string]string{"source": "pcap_import"}
		action := "packet_observed"
		msg := fmt.Sprintf("%s %s:%d -> %s:%d", p.Protocol, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
		if p.DNSQuery != "" {
			action = "dns_query"
			msg = fmt.Sprintf("DNS query %s from %s", p.DNSQuery, p.SrcIP)
			if p.DNSAnomaly {
				meta["dns_anomaly"] = "true"
				sev = domain.SeverityMedium
			}
		} else if p.TLSSNI != "" {
			action = "tls_handshake"
			msg = fmt.Sprintf("TLS SNI %s -> %s:%d", p.TLSSNI, p.DstIP, p.DstPort)
		}
		out = append(out, domain.Event{
			ID:         uuid.NewString(),
			TenantID:   tenantID,
			AgentID:    agentID,
			Host:       host,
			Category:   domain.CategoryNetwork,
			Action:     action,
			Severity:   sev,
			OccurredAt: p.Timestamp,
			IngestedAt: time.Now().UTC(),
			Summary:    msg,
			Network: &domain.NetworkInfo{
				Protocol: p.Protocol,
				SrcIP:    p.SrcIP,
				SrcPort:  p.SrcPort,
				DstIP:    p.DstIP,
				DstPort:  p.DstPort,
				DNSQuery: p.DNSQuery,
				TLSSNI:   p.TLSSNI,
				Bytes:    uint64(p.Length),
			},
			Metadata: meta,
		})
	}
	return out
}
