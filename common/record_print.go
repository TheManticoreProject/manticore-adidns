package common

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
)

// tombstoneTimeLayout renders a tombstone timestamp.
const tombstoneTimeLayout = "2006-01-02 15:04:05 MST"

// FormatRecord renders a DNS_RECORD as human-readable lines: a "Type: ... (Serial: ...)" line
// followed by one line per decoded field. The rendering mirrors dnstool.py's print_record and
// additionally decodes AAAA records. Record types without a decoder produce only the Type line.
//
// Parameters:
//
//	rec (*msdnsp.DNS_RECORD): The record to render.
//
// Returns:
//
//	[]string: The lines describing the record.
func FormatRecord(rec *msdnsp.DNS_RECORD) []string {
	lines := []string{fmt.Sprintf("Type: %s (Serial: %d)", rec.Type, rec.Serial)}

	switch rec.Type {
	case msdnsp.DNS_TYPE_ZERO:
		ts := &msdnsp.DNS_RPC_RECORD_TS{}
		if _, err := ts.Unmarshal(rec.Data); err == nil {
			lines = append(lines, fmt.Sprintf("Tombstoned at: %s", ts.GetTime().UTC().Format(tombstoneTimeLayout)))
		}
	case msdnsp.DNS_TYPE_A:
		a := &msdnsp.DNS_RPC_RECORD_A{}
		if _, err := a.Unmarshal(rec.Data); err == nil {
			lines = append(lines, fmt.Sprintf("Address: %s", a.GetIPv4()))
		}
	case msdnsp.DNS_TYPE_AAAA:
		aaaa := &msdnsp.DNS_RPC_RECORD_AAAA{}
		if _, err := aaaa.Unmarshal(rec.Data); err == nil {
			lines = append(lines, fmt.Sprintf("Address: %s", aaaa.GetIPv6()))
		}
	case msdnsp.DNS_TYPE_NS, msdnsp.DNS_TYPE_CNAME, msdnsp.DNS_TYPE_PTR, msdnsp.DNS_TYPE_DNAME:
		nn := &msdnsp.DNS_RPC_RECORD_NODE_NAME{}
		if _, err := nn.Unmarshal(rec.Data); err == nil {
			if fqdn, err := nn.NameNode.GetFQDN(); err == nil {
				lines = append(lines, fmt.Sprintf("Address: %s", fqdn))
			}
		}
	case msdnsp.DNS_TYPE_SOA:
		soa := &msdnsp.DNS_RPC_RECORD_SOA{}
		if _, err := soa.Unmarshal(rec.Data); err == nil {
			primary, _ := soa.NamePrimaryServer.GetFQDN()
			admin, _ := soa.ZoneAdminEmail.GetFQDN()
			lines = append(lines,
				fmt.Sprintf("Serial: %d", soa.DwSerialNo),
				fmt.Sprintf("Refresh: %d", soa.DwRefresh),
				fmt.Sprintf("Retry: %d", soa.DwRetry),
				fmt.Sprintf("Expire: %d", soa.DwExpire),
				fmt.Sprintf("Minimum TTL: %d", soa.DwMinimumTtl),
				fmt.Sprintf("Primary server: %s", primary),
				fmt.Sprintf("Zone admin email: %s", admin),
			)
		}
	case msdnsp.DNS_TYPE_SRV:
		srv := &msdnsp.DNS_RPC_RECORD_SRV{}
		if _, err := srv.Unmarshal(rec.Data); err == nil {
			target, _ := srv.NameTarget.GetFQDN()
			lines = append(lines,
				fmt.Sprintf("Priority: %d", srv.WPriority),
				fmt.Sprintf("Weight: %d", srv.WWeight),
				fmt.Sprintf("Port: %d", srv.WPort),
				fmt.Sprintf("Name: %s", target),
			)
		}
	}

	return lines
}

// PrintRecord logs a record's details as an indented tree, colouring each field value blue. The
// caller supplies the indent that positions the record beneath its node in the output tree.
//
// Parameters:
//
//	rec (*msdnsp.DNS_RECORD): The record to print.
//	indent (string): The leading whitespace placed before each line's tree glyph.
func PrintRecord(rec *msdnsp.DNS_RECORD, indent string) {
	lines := FormatRecord(rec)
	for i, line := range lines {
		glyph := "├──"
		if i == len(lines)-1 {
			glyph = "└──"
		}
		logger.Print(fmt.Sprintf("%s%s %s", indent, glyph, colourValue(line)))
	}
}

// colourValue colours the value part of a "Key: value" line blue, leaving the key uncoloured.
func colourValue(line string) string {
	key, value, found := strings.Cut(line, ": ")
	if !found {
		return line
	}
	return fmt.Sprintf("%s: \x1b[94m%s\x1b[0m", key, value)
}
