// Package record implements the adidns "record" object actions (query, add, modify, remove,
// resurrect, delete) over LDAP.
package record

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
	"github.com/TheManticoreProject/adidns/common"
)

// QueryRecord prints the DNS records stored on a node.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings.
//	record (string): The record to query (FQDN or a name relative to the zone).
//
// Returns:
//
//	error: An error if setup or the LDAP search fails. A missing node is reported to the user
//	and returns nil.
func QueryRecord(opts *common.Options, record string) error {
	ctx, err := common.Setup(opts)
	if err != nil {
		return err
	}
	defer ctx.Close()

	target := common.RelativeTarget(record, ctx.Zone)
	entry, err := ctx.FindNode(target)
	if err != nil {
		return err
	}
	if entry == nil {
		logger.Warn(fmt.Sprintf("Record '%s' not found in zone '%s'.", record, ctx.Zone))
		return nil
	}

	name := entry.GetEqualFoldAttributeValue("name")
	if name == "" {
		name = target
	}
	raws := entry.GetEqualFoldRawAttributeValues("dnsRecord")

	logger.Print(fmt.Sprintf("[>] Record '%s' (\x1b[93m%d\x1b[0m):", name, len(raws)))
	logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m", entry.DN))
	if entry.GetEqualFoldAttributeValue("dNSTombstoned") == "TRUE" {
		logger.Print("      \x1b[91m[!] Node is tombstoned (inactive)\x1b[0m")
	}

	for _, raw := range raws {
		rec := &msdnsp.DNS_RECORD{}
		if _, err := rec.Unmarshal(raw); err != nil {
			logger.Warn(fmt.Sprintf("Skipping unparseable dnsRecord value: %s", err))
			continue
		}
		common.PrintRecord(rec, "      ")
	}

	return nil
}
