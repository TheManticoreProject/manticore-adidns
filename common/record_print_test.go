package common_test

import (
	"net"
	"strings"
	"testing"

	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
	"github.com/TheManticoreProject/adidns/common"
)

// mustRecord builds a DNS_RECORD of the given type carrying the marshalled payload.
func mustRecord(t *testing.T, rtype msdnsp.RecordType, serial uint32, payload interface {
	Marshal() ([]byte, error)
}) *msdnsp.DNS_RECORD {
	t.Helper()
	rec := msdnsp.NewDNS_RECORD()
	rec.Type = rtype
	rec.Serial = serial
	if err := rec.SetData(payload); err != nil {
		t.Fatalf("SetData failed: %v", err)
	}
	return rec
}

func TestFormatRecordA(t *testing.T) {
	a := msdnsp.NewDNS_RPC_RECORD_A()
	if err := a.SetIPv4(net.ParseIP("10.0.0.5")); err != nil {
		t.Fatalf("SetIPv4: %v", err)
	}
	lines := common.FormatRecord(mustRecord(t, msdnsp.DNS_TYPE_A, 42, a))

	want := []string{"Type: DNS_TYPE_A (Serial: 42)", "Address: 10.0.0.5"}
	assertLines(t, lines, want)
}

func TestFormatRecordAAAA(t *testing.T) {
	aaaa := msdnsp.NewDNS_RPC_RECORD_AAAA()
	if err := aaaa.SetIPv6(net.ParseIP("2001:db8::1")); err != nil {
		t.Fatalf("SetIPv6: %v", err)
	}
	lines := common.FormatRecord(mustRecord(t, msdnsp.DNS_TYPE_AAAA, 7, aaaa))

	if lines[0] != "Type: DNS_TYPE_AAAA (Serial: 7)" {
		t.Errorf("line 0 = %q", lines[0])
	}
	if lines[1] != "Address: 2001:db8::1" {
		t.Errorf("line 1 = %q; want the AAAA address", lines[1])
	}
}

func TestFormatRecordCNAME(t *testing.T) {
	nn := msdnsp.NewDNS_RPC_RECORD_NODE_NAME()
	if err := nn.NameNode.SetFQDN("target.domain.local"); err != nil {
		t.Fatalf("SetFQDN: %v", err)
	}
	lines := common.FormatRecord(mustRecord(t, msdnsp.DNS_TYPE_CNAME, 1, nn))

	assertLines(t, lines, []string{"Type: DNS_TYPE_CNAME (Serial: 1)", "Address: target.domain.local"})
}

func TestFormatRecordSOA(t *testing.T) {
	soa := msdnsp.NewDNS_RPC_RECORD_SOA()
	soa.DwSerialNo = 100
	soa.DwRefresh = 900
	soa.DwRetry = 600
	soa.DwExpire = 86400
	soa.DwMinimumTtl = 3600
	if err := soa.NamePrimaryServer.SetFQDN("ns.domain.local"); err != nil {
		t.Fatalf("SetFQDN primary: %v", err)
	}
	if err := soa.ZoneAdminEmail.SetFQDN("hostmaster.domain.local"); err != nil {
		t.Fatalf("SetFQDN admin: %v", err)
	}
	lines := common.FormatRecord(mustRecord(t, msdnsp.DNS_TYPE_SOA, 100, soa))

	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		"Type: DNS_TYPE_SOA (Serial: 100)",
		"Serial: 100", "Refresh: 900", "Retry: 600", "Expire: 86400", "Minimum TTL: 3600",
		"Primary server: ns.domain.local", "Zone admin email: hostmaster.domain.local",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("SOA output missing %q; got:\n%s", want, joined)
		}
	}
}

func TestFormatRecordSRV(t *testing.T) {
	srv := msdnsp.NewDNS_RPC_RECORD_SRV()
	srv.WPriority = 10
	srv.WWeight = 20
	srv.WPort = 443
	if err := srv.NameTarget.SetFQDN("svc.domain.local"); err != nil {
		t.Fatalf("SetFQDN: %v", err)
	}
	lines := common.FormatRecord(mustRecord(t, msdnsp.DNS_TYPE_SRV, 3, srv))

	assertLines(t, lines, []string{
		"Type: DNS_TYPE_SRV (Serial: 3)",
		"Priority: 10", "Weight: 20", "Port: 443", "Name: svc.domain.local",
	})
}

func TestFormatRecordTombstone(t *testing.T) {
	ts := msdnsp.NewDNS_RPC_RECORD_TS()
	// Any non-zero entombed time; we only assert the "Tombstoned at:" prefix.
	ts.EntombedTime = 133000000000000000
	lines := common.FormatRecord(mustRecord(t, msdnsp.DNS_TYPE_ZERO, 0, ts))

	if lines[0] != "Type: DNS_TYPE_ZERO (Serial: 0)" {
		t.Errorf("line 0 = %q", lines[0])
	}
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "Tombstoned at: ") {
		t.Errorf("expected a Tombstoned at: line, got %v", lines)
	}
}

func assertLines(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d lines %v; want %d lines %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q; want %q", i, got[i], want[i])
		}
	}
}
