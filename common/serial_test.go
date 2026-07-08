package common_test

import (
	"testing"

	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
	"github.com/TheManticoreProject/adidns/common"
)

// soaRecordBytes builds a marshalled dnsRecord value carrying an SOA with the given serial.
func soaRecordBytes(t *testing.T, serial uint32) []byte {
	t.Helper()
	soa := msdnsp.NewDNS_RPC_RECORD_SOA()
	soa.DwSerialNo = serial
	if err := soa.NamePrimaryServer.SetFQDN("ns.domain.local"); err != nil {
		t.Fatalf("SetFQDN primary: %v", err)
	}
	if err := soa.ZoneAdminEmail.SetFQDN("hostmaster.domain.local"); err != nil {
		t.Fatalf("SetFQDN admin: %v", err)
	}
	rec := msdnsp.NewDNS_RECORD()
	rec.Type = msdnsp.DNS_TYPE_SOA
	if err := rec.SetData(soa); err != nil {
		t.Fatalf("SetData: %v", err)
	}
	raw, err := rec.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

// aRecordBytes builds a marshalled dnsRecord value carrying an A record (a non-SOA record used
// to prove SerialFromRecords skips over it).
func aRecordBytes(t *testing.T) []byte {
	t.Helper()
	rec := msdnsp.NewDNS_RECORD()
	rec.Type = msdnsp.DNS_TYPE_A
	rec.Data = []byte{10, 0, 0, 1}
	raw, err := rec.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

func TestSerialFromRecords(t *testing.T) {
	raws := [][]byte{aRecordBytes(t), soaRecordBytes(t, 2024010101)}
	serial, ok := common.SerialFromRecords(raws)
	if !ok {
		t.Fatal("SerialFromRecords did not find the SOA record")
	}
	if serial != 2024010101 {
		t.Errorf("serial = %d; want 2024010101", serial)
	}
}

func TestSerialFromRecordsNoSOA(t *testing.T) {
	if _, ok := common.SerialFromRecords([][]byte{aRecordBytes(t)}); ok {
		t.Error("SerialFromRecords reported an SOA where there is none")
	}
}

func TestSerialFromRecordsIgnoresGarbage(t *testing.T) {
	raws := [][]byte{{0x00, 0x01, 0x02}, soaRecordBytes(t, 5)}
	serial, ok := common.SerialFromRecords(raws)
	if !ok || serial != 5 {
		t.Errorf("SerialFromRecords = (%d, %v); want (5, true)", serial, ok)
	}
}
