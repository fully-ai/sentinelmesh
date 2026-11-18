package netmon

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func buildTestDNSPCAP(qname string) []byte {
	// Encode DNS question
	var q []byte
	q = append(q, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, lbl := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		q = append(q, byte(len(lbl)))
		q = append(q, []byte(lbl)...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01)

	udpLen := uint16(8 + len(q))
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 51515)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], udpLen)

	ipLen := uint16(20 + len(udp) + len(q))
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], ipLen)
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], net.ParseIP("10.0.0.15").To4())
	copy(ip[16:20], net.ParseIP("1.1.1.1").To4())

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)

	frame := append(eth, ip...)
	frame = append(frame, udp...)
	frame = append(frame, q...)

	// Global PCAP LE header (24 bytes) + packet header (16 bytes)
	out := make([]byte, 24+16)
	binary.LittleEndian.PutUint32(out[0:4], pcapMagicLE)
	binary.LittleEndian.PutUint16(out[4:6], 2)
	binary.LittleEndian.PutUint16(out[6:8], 4)
	binary.LittleEndian.PutUint32(out[16:20], 65535)
	binary.LittleEndian.PutUint32(out[20:24], 1)

	binary.LittleEndian.PutUint32(out[24:28], 1700000000)
	binary.LittleEndian.PutUint32(out[32:36], uint32(len(frame)))
	binary.LittleEndian.PutUint32(out[36:40], uint32(len(frame)))
	return append(out, frame...)
}

func TestParsePCAPAndDNSAnomaly(t *testing.T) {
	normal := buildTestDNSPCAP("api.sentinelmesh.local")
	sum, err := ParsePCAP(normal)
	if err != nil {
		t.Fatalf("ParsePCAP normal: %v", err)
	}
	if sum.PacketCount != 1 || sum.Protocols["DNS"] != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if len(sum.DNSQueries) != 1 || sum.DNSQueries[0] != "api.sentinelmesh.local" {
		t.Fatalf("unexpected dns queries: %+v", sum.DNSQueries)
	}
	if len(sum.Anomalies) != 0 {
		t.Fatalf("expected 0 anomalies for benign query, got %+v", sum.Anomalies)
	}

	tunnel := buildTestDNSPCAP("a9f8d7c6b5e4a1f29d8c7b6a5e4f3a2b1c0d9e8f7a6b.exfil.example.invalid")
	sum2, err := ParsePCAP(tunnel)
	if err != nil {
		t.Fatalf("ParsePCAP tunnel: %v", err)
	}
	if len(sum2.Anomalies) == 0 {
		t.Fatal("expected long/high-entropy DNS query anomaly")
	}
}

func FuzzParsePCAP(f *testing.F) {
	f.Add(buildTestDNSPCAP("example.com"))
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 1})
	f.Add([]byte("garbage-non-pcap"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePCAP(data)
	})
}
