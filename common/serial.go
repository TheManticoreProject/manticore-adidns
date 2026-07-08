package common

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
)

// SerialFromRecords returns the SOA serial number found among a set of raw dnsRecord values.
//
// Parameters:
//
//	raws ([][]byte): The raw dnsRecord attribute values of a node.
//
// Returns:
//
//	uint32: The SOA serial number.
//	bool: true if an SOA record was found and parsed, false otherwise.
func SerialFromRecords(raws [][]byte) (uint32, bool) {
	for _, raw := range raws {
		rec := &msdnsp.DNS_RECORD{}
		if _, err := rec.Unmarshal(raw); err != nil {
			continue
		}
		if rec.Type != msdnsp.DNS_TYPE_SOA {
			continue
		}
		soa := &msdnsp.DNS_RPC_RECORD_SOA{}
		if _, err := soa.Unmarshal(rec.Data); err != nil {
			continue
		}
		return soa.DwSerialNo, true
	}
	return 0, false
}

// NextSerial returns the serial number to stamp on a new or updated record: the zone's SOA
// serial plus one. The SOA is read from the zone apex node (DC=@) over the existing LDAP
// connection, so no live DNS query is needed. If the SOA cannot be read it warns and returns 1.
//
// Returns:
//
//	uint32: The next serial number.
func (ctx *Context) NextSerial() uint32 {
	base := fmt.Sprintf("DC=@,%s", ctx.SearchBase)
	entries, err := ctx.Session.QueryBaseObject(base, "(objectClass=dnsNode)", []string{"dnsRecord"})
	if err != nil || len(entries) == 0 {
		logger.Warn("Could not read the zone apex (DC=@) SOA record; defaulting serial to 1")
		return 1
	}
	if serial, ok := SerialFromRecords(entries[0].GetEqualFoldRawAttributeValues("dnsRecord")); ok {
		return serial + 1
	}
	logger.Warn("No SOA record found in the zone apex; defaulting serial to 1")
	return 1
}
