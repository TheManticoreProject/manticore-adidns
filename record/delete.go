package record

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/adidns/common"
)

// DeleteRecord deletes a node from LDAP entirely (dnstool.py's ldapdelete). Unlike remove, this
// removes the dnsNode object rather than tombstoning it.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings.
//	record (string): The record to delete (FQDN or a name relative to the zone).
//
// Returns:
//
//	error: An error if setup or the LDAP delete fails.
func DeleteRecord(opts *common.Options, record string) error {
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

	if err := ctx.Session.Delete(entry.DN); err != nil {
		return fmt.Errorf("deleting '%s': %w", entry.DN, err)
	}
	logger.Print(fmt.Sprintf("[-] Deleted node \x1b[94m%s\x1b[0m.", entry.DN))
	return nil
}
