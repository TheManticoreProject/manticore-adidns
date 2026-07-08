package record

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
	"github.com/TheManticoreProject/adidns/common"
)

// ModifyRecord overwrites the address of a node's existing A record, preserving all of the
// node's other records. The node and an existing A record are required.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings.
//	record (string): The record to modify (FQDN or a name relative to the zone).
//	data (string): The new IPv4 address.
//	rtype (string): The record type (only "A" is supported).
//
// Returns:
//
//	error: An error if a guard fails or the LDAP operation fails.
func ModifyRecord(opts *common.Options, record, data string, rtype string) error {
	if err := requireAType(rtype); err != nil {
		return err
	}
	if data == "" {
		return fmt.Errorf("the modify action requires an IPv4 address (--data)")
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

	// Preserve every value except the first A record, which we rebuild in place.
	var values []string
	var firstA *msdnsp.DNS_RECORD
	for _, raw := range entry.GetEqualFoldRawAttributeValues("dnsRecord") {
		rec := &msdnsp.DNS_RECORD{}
		if _, err := rec.Unmarshal(raw); err != nil {
			values = append(values, string(raw)) // keep unparseable values untouched
			continue
		}
		if rec.Type == msdnsp.DNS_TYPE_A && firstA == nil {
			firstA = rec
			continue
		}
		values = append(values, string(raw))
	}
	if firstA == nil {
		return fmt.Errorf("no A record exists on '%s'; use the add action instead", record)
	}

	v4, err := parseIPv4(data)
	if err != nil {
		return err
	}
	payload := msdnsp.NewDNS_RPC_RECORD_A()
	if err := payload.SetIPv4(v4); err != nil {
		return err
	}
	// Reuse the existing record so its TTL and Rank are preserved; only bump the serial and
	// swap the address.
	firstA.Serial = ctx.NextSerial()
	if err := firstA.SetData(payload); err != nil {
		return err
	}
	value, err := marshalValue(firstA)
	if err != nil {
		return err
	}
	values = append(values, value)

	req := ldap.NewModifyRequest(entry.DN)
	req.Replace("dnsRecord", values)
	if err := ctx.Session.Modify(req); err != nil {
		return fmt.Errorf("modifying record on '%s': %w", entry.DN, err)
	}
	logger.Print(fmt.Sprintf("[~] Modified A record '%s' -> \x1b[94m%s\x1b[0m on \x1b[94m%s\x1b[0m.", record, data, entry.DN))
	return nil
}
