package record

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/adidns/common"
)

// ResurrectRecord clears the tombstone on a node by writing a fresh tombstone record and setting
// dNSTombstoned to FALSE. The node's address record must be re-added afterwards. A node with more
// than one record is refused, mirroring dnstool.py.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings.
//	record (string): The record to resurrect (FQDN or a name relative to the zone).
//
// Returns:
//
//	error: An error if setup or the LDAP operation fails.
func ResurrectRecord(opts *common.Options, record string) error {
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

	if entry.GetEqualFoldAttributeValue("dNSTombstoned") != "TRUE" {
		logger.Warn(fmt.Sprintf("Node '%s' is not tombstoned; nothing to do.", record))
		return nil
	}

	if len(entry.GetEqualFoldRawAttributeValues("dnsRecord")) > 1 {
		logger.Warn(fmt.Sprintf("Node '%s' has multiple records; refusing to resurrect.", record))
		return nil
	}

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
	req.Replace("dNSTombstoned", []string{"FALSE"})
	if err := ctx.Session.Modify(req); err != nil {
		return fmt.Errorf("resurrecting '%s': %w", entry.DN, err)
	}
	logger.Print(fmt.Sprintf("[+] Resurrected \x1b[94m%s\x1b[0m. Re-add the address with 'adidns record add'.", entry.DN))
	return nil
}
