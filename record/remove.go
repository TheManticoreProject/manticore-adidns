package record

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
	"github.com/TheManticoreProject/adidns/common"
)

// RemoveRecord removes an A record from a node. If the node has more than one record, only the
// A record matching data is deleted; if it has a single record, the node is tombstoned.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings.
//	record (string): The record to remove (FQDN or a name relative to the zone).
//	data (string): The IPv4 address of the A record to remove.
//	rtype (string): The record type (only "A" is supported).
//
// Returns:
//
//	error: An error if a guard fails or the LDAP operation fails.
func RemoveRecord(opts *common.Options, record, data string, rtype string) error {
	if err := requireAType(rtype); err != nil {
		return err
	}
	wanted, err := parseIPv4(data)
	if err != nil {
		return fmt.Errorf("the remove action requires the IPv4 address to remove (--data): %w", err)
	}

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

	raws := entry.GetEqualFoldRawAttributeValues("dnsRecord")

	if len(raws) > 1 {
		// Delete the exact original bytes of the A record whose address matches, so the LDAP
		// value matches byte-for-byte.
		var match []byte
		for _, raw := range raws {
			rec := &msdnsp.DNS_RECORD{}
			if _, err := rec.Unmarshal(raw); err != nil || rec.Type != msdnsp.DNS_TYPE_A {
				continue
			}
			a := &msdnsp.DNS_RPC_RECORD_A{}
			if _, err := a.Unmarshal(rec.Data); err != nil {
				continue
			}
			if a.GetIPv4().Equal(wanted) {
				match = raw
				break
			}
		}
		if match == nil {
			logger.Warn(fmt.Sprintf("No A record with address %s found on '%s'.", data, record))
			return nil
		}
		req := ldap.NewModifyRequest(entry.DN)
		req.Delete("dnsRecord", []string{string(match)})
		if err := ctx.Session.Modify(req); err != nil {
			return fmt.Errorf("removing record from '%s': %w", entry.DN, err)
		}
		logger.Print(fmt.Sprintf("[-] Removed A record %s from \x1b[94m%s\x1b[0m.", data, entry.DN))
		return nil
	}

	// A single record remains: validate it matches the provided address before tombstoning.
	var hasMatchingRecord bool
	for _, raw := range raws {
		rec := &msdnsp.DNS_RECORD{}
		if _, err := rec.Unmarshal(raw); err != nil || rec.Type != msdnsp.DNS_TYPE_A {
			continue
		}
		a := &msdnsp.DNS_RPC_RECORD_A{}
		if _, err := a.Unmarshal(rec.Data); err != nil {
			continue
		}
		if a.GetIPv4().Equal(wanted) {
			hasMatchingRecord = true
			break
		}
	}
	if !hasMatchingRecord {
		return fmt.Errorf("no A record with address %s found on '%s'", data, record)
	}

	// Tombstone the node instead of deleting the last value.
	tombstone, err := newTombstoneRecord(ctx.NextSerial())
	if err != nil {
		return err
	}
	value, err := marshalValue(tombstone)
	if err != nil {
		return err
	}
	req := ldap.NewModifyRequest(entry.DN)
	req.Replace("dnsRecord", []string{value})
	req.Replace("dNSTombstoned", []string{"TRUE"})
	if err := ctx.Session.Modify(req); err != nil {
		return fmt.Errorf("tombstoning '%s': %w", entry.DN, err)
	}
	logger.Print(fmt.Sprintf("[-] Node had a single record; tombstoned \x1b[94m%s\x1b[0m.", entry.DN))
	return nil
}
