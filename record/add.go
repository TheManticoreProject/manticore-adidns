package record

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
	"github.com/TheManticoreProject/adidns/common"
)

// AddRecord adds an A record to a node, creating the node if it does not exist. If the node
// already has an A record, the add is refused unless allowMultiple is set.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings.
//	record (string): The record to add (FQDN or a name relative to the zone).
//	data (string): The IPv4 address for the A record.
//	ttl (int): The record TTL in seconds.
//	allowMultiple (bool): Allow adding an A record when one already exists.
//	rtype (string): The record type (only "A" is supported).
//
// Returns:
//
//	error: An error if a guard fails or the LDAP operation fails.
func AddRecord(opts *common.Options, record, data string, ttl int, allowMultiple bool, rtype string) error {
	if err := requireAType(rtype); err != nil {
		return err
	}
	if data == "" {
		return fmt.Errorf("the add action requires an IPv4 address (--data)")
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

	if entry != nil {
		if !allowMultiple {
			for _, raw := range entry.GetEqualFoldRawAttributeValues("dnsRecord") {
				existing := &msdnsp.DNS_RECORD{}
				if _, err := existing.Unmarshal(raw); err != nil {
					continue
				}
				if existing.Type != msdnsp.DNS_TYPE_A {
					continue
				}
				a := &msdnsp.DNS_RPC_RECORD_A{}
				if _, err := a.Unmarshal(existing.Data); err == nil {
					return fmt.Errorf("record '%s' already exists and points to %s (use 'modify' to overwrite, or --allow-multiple to add another)", record, a.GetIPv4())
				}
			}
		}

		rec, err := newARecord(ctx.NextSerial(), ttl, data)
		if err != nil {
			return err
		}
		value, err := marshalValue(rec)
		if err != nil {
			return err
		}
		req := ldap.NewModifyRequest(entry.DN)
		req.Add("dnsRecord", []string{value})
		if err := ctx.Session.Modify(req); err != nil {
			return fmt.Errorf("adding record to '%s': %w", entry.DN, err)
		}
		logger.Print(fmt.Sprintf("[+] Added A record '%s' -> \x1b[94m%s\x1b[0m on \x1b[94m%s\x1b[0m.", record, data, entry.DN))
		return nil
	}

	// The node does not exist: create it with the A record.
	rec, err := newARecord(ctx.NextSerial(), ttl, data)
	if err != nil {
		return err
	}
	value, err := marshalValue(rec)
	if err != nil {
		return err
	}
	dn := ctx.NodeDN(target)
	req := ldap.NewAddRequest(dn)
	req.Attribute("objectClass", []string{"top", "dnsNode"})
	req.Attribute("objectCategory", []string{fmt.Sprintf("CN=Dns-Node,%s", ctx.SchemaNC)})
	req.Attribute("dNSTombstoned", []string{"FALSE"})
	req.Attribute("dnsRecord", []string{value})
	if err := ctx.Session.Add(req); err != nil {
		return fmt.Errorf("creating node '%s': %w", dn, err)
	}
	logger.Print(fmt.Sprintf("[+] Created node and A record '%s' -> \x1b[94m%s\x1b[0m at \x1b[94m%s\x1b[0m.", record, data, dn))
	return nil
}
