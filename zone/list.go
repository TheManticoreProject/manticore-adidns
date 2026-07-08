// Package zone implements the adidns "zone" object actions (list, info) over LDAP.
package zone

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/adidns/common"
)

// ListZones enumerates the DNS zones on the server. It lists the zones of the selected partition
// (DomainDnsZones by default, or the ForestDnsZones/System partition per the zone-selection
// flags) and, separately, always the forest-wide ForestDnsZones partition — mirroring
// dnstool.py's --print-zones.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings.
//	printDN (bool): Print each zone's distinguished name instead of its dc (name).
//
// Returns:
//
//	error: An error if setup fails. Per-partition search failures are reported as warnings and
//	do not abort the other partition.
func ListZones(opts *common.Options, printDN bool) error {
	ctx, err := common.Setup(opts)
	if err != nil {
		return err
	}
	defer ctx.Close()

	// Selected partition (DomainDnsZones by default).
	domainZones, err := queryZones(ctx.Session, ctx.DNSRoot, printDN)
	if err != nil {
		logger.Warn(fmt.Sprintf("Could not query partition '%s': %s", ctx.DNSRoot, err))
	}
	printZoneList("Domain DNS zones", domainZones)

	// Forest-wide partition (always queried).
	forestBase := fmt.Sprintf("CN=MicrosoftDNS,DC=ForestDnsZones,%s", ctx.ForestRoot)
	forestZones, err := queryZones(ctx.Session, forestBase, printDN)
	if err != nil {
		logger.Warn(fmt.Sprintf("Could not query partition '%s': %s", forestBase, err))
	}
	printZoneList("Forest DNS zones", forestZones)

	return nil
}

// queryZones returns the zones directly under base, as either dc names or distinguished names.
func queryZones(session *ldap.Session, base string, printDN bool) ([]string, error) {
	attr := "dc"
	if printDN {
		attr = "distinguishedName"
	}
	entries, err := session.QuerySingleLevel(base, "(objectClass=dnsZone)", []string{attr})
	if err != nil {
		return nil, err
	}
	zones := make([]string, 0, len(entries))
	for _, entry := range entries {
		if printDN {
			zones = append(zones, entry.DN)
		} else {
			zones = append(zones, entry.GetEqualFoldAttributeValue("dc"))
		}
	}
	return zones, nil
}

// printZoneList renders a titled, counted tree of zone names.
func printZoneList(title string, zones []string) {
	logger.Print(fmt.Sprintf("[>] %s (\x1b[93m%d\x1b[0m):", title, len(zones)))
	for i, z := range zones {
		glyph := "├──"
		if i == len(zones)-1 {
			glyph = "└──"
		}
		logger.Print(fmt.Sprintf("  %s \x1b[94m%s\x1b[0m", glyph, z))
	}
}
