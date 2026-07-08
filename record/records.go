package record

import (
	"fmt"
	"net"
	"strings"
	"time"

	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
)

// rankZone is the Rank byte written on records created by this tool (RANK_ZONE), matching
// dnstool.py's new_record.
const rankZone uint8 = 0xF0

// tombstoneTTL is the TTL, in seconds, stamped on a tombstone record, matching dnstool.py.
const tombstoneTTL uint32 = 180

// requireAType enforces the v1 restriction that only A records can be written.
//
// Parameters:
//
//	rtype (string): The requested record type.
//
// Returns:
//
//	error: An error if rtype is not "A" (case-insensitive), nil otherwise.
func requireAType(rtype string) error {
	if !strings.EqualFold(rtype, "A") {
		return fmt.Errorf("only A records are supported for writes (got %q)", rtype)
	}
	return nil
}

// parseIPv4 parses s as an IPv4 address.
//
// Parameters:
//
//	s (string): The address to parse.
//
// Returns:
//
//	net.IP: The 4-byte IPv4 address.
//	error: An error if s is not a valid IPv4 address.
func parseIPv4(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %q", s)
	}
	return ip.To4(), nil
}

// newARecord builds a DNS_RECORD carrying an A (IPv4) payload.
//
// Parameters:
//
//	serial (uint32): The zone serial to stamp on the record.
//	ttl (int): The record TTL in seconds.
//	ip (string): The IPv4 address.
//
// Returns:
//
//	*msdnsp.DNS_RECORD: The assembled record.
//	error: An error if ip is not a valid IPv4 address.
func newARecord(serial uint32, ttl int, ip string) (*msdnsp.DNS_RECORD, error) {
	v4, err := parseIPv4(ip)
	if err != nil {
		return nil, err
	}
	payload := msdnsp.NewDNS_RPC_RECORD_A()
	if err := payload.SetIPv4(v4); err != nil {
		return nil, err
	}

	rec := msdnsp.NewDNS_RECORD()
	rec.Type = msdnsp.DNS_TYPE_A
	rec.Serial = serial
	rec.TtlSeconds = uint32(ttl)
	rec.Rank = rankZone
	if err := rec.SetData(payload); err != nil {
		return nil, err
	}
	return rec, nil
}

// newTombstoneRecord builds a tombstone (DNS_TYPE_ZERO) DNS_RECORD stamped with the current
// time, used to deactivate a node.
//
// Parameters:
//
//	serial (uint32): The zone serial to stamp on the record.
//
// Returns:
//
//	*msdnsp.DNS_RECORD: The assembled tombstone record.
//	error: An error if marshalling the payload fails.
func newTombstoneRecord(serial uint32) (*msdnsp.DNS_RECORD, error) {
	payload := msdnsp.NewDNS_RPC_RECORD_TS()
	payload.SetTime(time.Now().UTC())

	rec := msdnsp.NewDNS_RECORD()
	rec.Type = msdnsp.DNS_TYPE_ZERO
	rec.Serial = serial
	rec.TtlSeconds = tombstoneTTL
	rec.Rank = rankZone
	if err := rec.SetData(payload); err != nil {
		return nil, err
	}
	return rec, nil
}

// marshalValue marshals a record to the string form expected by the LDAP layer (raw octets
// carried in a Go string).
func marshalValue(rec *msdnsp.DNS_RECORD) (string, error) {
	raw, err := rec.Marshal()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
