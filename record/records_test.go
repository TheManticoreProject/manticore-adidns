package record

import (
	"testing"

	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
)

func TestRequireAType(t *testing.T) {
	for _, ok := range []string{"A", "a"} {
		if err := requireAType(ok); err != nil {
			t.Errorf("requireAType(%q) returned error: %v", ok, err)
		}
	}
	for _, bad := range []string{"AAAA", "CNAME", ""} {
		if err := requireAType(bad); err == nil {
			t.Errorf("requireAType(%q) = nil; want error", bad)
		}
	}
}

func TestParseIPv4(t *testing.T) {
	if _, err := parseIPv4("10.0.0.5"); err != nil {
		t.Errorf("parseIPv4(10.0.0.5) returned error: %v", err)
	}
	for _, bad := range []string{"", "not-an-ip", "2001:db8::1", "999.0.0.1"} {
		if _, err := parseIPv4(bad); err == nil {
			t.Errorf("parseIPv4(%q) = nil error; want error", bad)
		}
	}
}

func TestNewARecord(t *testing.T) {
	rec, err := newARecord(42, 300, "10.20.30.40")
	if err != nil {
		t.Fatalf("newARecord returned error: %v", err)
	}
	if rec.Type != msdnsp.DNS_TYPE_A {
		t.Errorf("Type = %s; want DNS_TYPE_A", rec.Type)
	}
	if rec.Serial != 42 {
		t.Errorf("Serial = %d; want 42", rec.Serial)
	}
	if rec.TtlSeconds != 300 {
		t.Errorf("TtlSeconds = %d; want 300", rec.TtlSeconds)
	}
	if rec.Rank != rankZone {
		t.Errorf("Rank = 0x%X; want 0x%X", rec.Rank, rankZone)
	}

	// The payload must round-trip back to the same address.
	a := &msdnsp.DNS_RPC_RECORD_A{}
	if _, err := a.Unmarshal(rec.Data); err != nil {
		t.Fatalf("payload Unmarshal: %v", err)
	}
	if got := a.GetIPv4().String(); got != "10.20.30.40" {
		t.Errorf("payload address = %s; want 10.20.30.40", got)
	}
}

func TestNewARecordInvalidIP(t *testing.T) {
	if _, err := newARecord(1, 180, "nope"); err == nil {
		t.Error("newARecord with invalid IP = nil error; want error")
	}
}

func TestNewTombstoneRecord(t *testing.T) {
	rec, err := newTombstoneRecord(7)
	if err != nil {
		t.Fatalf("newTombstoneRecord returned error: %v", err)
	}
	if rec.Type != msdnsp.DNS_TYPE_ZERO {
		t.Errorf("Type = %s; want DNS_TYPE_ZERO", rec.Type)
	}
	if rec.Serial != 7 {
		t.Errorf("Serial = %d; want 7", rec.Serial)
	}
	if rec.Rank != rankZone {
		t.Errorf("Rank = 0x%X; want 0x%X", rec.Rank, rankZone)
	}

	ts := &msdnsp.DNS_RPC_RECORD_TS{}
	if _, err := ts.Unmarshal(rec.Data); err != nil {
		t.Fatalf("payload Unmarshal: %v", err)
	}
	if ts.GetTime().IsZero() {
		t.Error("tombstone time is zero; want the current time")
	}
}
