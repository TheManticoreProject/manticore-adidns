package record

import (
	"fmt"
	"sort"

	"github.com/TheManticoreProject/Manticore/logger"
	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
	"github.com/TheManticoreProject/adidns/common"
)

// ListRecords prints every node in the zone together with the DNS records stored on it.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings.
//
// Returns:
//
//	error: An error if setup or the LDAP search fails. An empty zone is reported to the user and
//	returns nil.
func ListRecords(opts *common.Options) error {
	ctx, err := common.Setup(opts)
	if err != nil {
		return err
	}
	defer ctx.Close()

	entries, err := ctx.ListNodes()
	if err != nil {
		return err
	}

	// Stable, name-sorted output regardless of the server's return order.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].GetEqualFoldAttributeValue("name") < entries[j].GetEqualFoldAttributeValue("name")
	})

	logger.Print(fmt.Sprintf("[>] Records in zone '%s' (\x1b[93m%d\x1b[0m):", ctx.Zone, len(entries)))

	for i, entry := range entries {
		last := i == len(entries)-1
		glyph := "├──"
		childPrefix := "  │   "
		if last {
			glyph = "└──"
			childPrefix = "      "
		}

		name := entry.GetEqualFoldAttributeValue("name")
		if name == "" {
			name = "@"
		}
		line := fmt.Sprintf("  %s \x1b[94m%s\x1b[0m", glyph, name)
		if entry.GetEqualFoldAttributeValue("dNSTombstoned") == "TRUE" {
			line += " \x1b[91m(tombstoned)\x1b[0m"
		}
		logger.Print(line)

		recs := make([]*msdnsp.DNS_RECORD, 0)
		for _, raw := range entry.GetEqualFoldRawAttributeValues("dnsRecord") {
			rec := &msdnsp.DNS_RECORD{}
			if _, err := rec.Unmarshal(raw); err != nil {
				logger.Warn(fmt.Sprintf("Skipping unparseable dnsRecord value on node '%s': %s", name, err))
				continue
			}
			recs = append(recs, rec)
		}
		common.PrintRecords(recs, childPrefix)
	}

	return nil
}
