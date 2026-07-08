package zone

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	msdnsp "github.com/TheManticoreProject/Manticore/windows/protocols/ms-dnsp"
	"github.com/TheManticoreProject/adidns/common"
	goldap "github.com/go-ldap/ldap/v3"
)

// ZoneInfo prints the properties of a DNS zone by decoding its dnsProperty attribute values.
//
// Parameters:
//
//	opts (*common.Options): The connection, credential, and zone-selection settings. The zone is
//	  taken from opts.Zone (or the authentication domain) within the selected partition.
//
// Returns:
//
//	error: An error if setup or the LDAP query fails. A missing zone is reported to the user and
//	returns nil.
func ZoneInfo(opts *common.Options) error {
	ctx, err := common.Setup(opts)
	if err != nil {
		return err
	}
	defer ctx.Close()

	entries, err := ctx.Session.QueryBaseObject(ctx.SearchBase, "(objectClass=dnsZone)", []string{"*"})
	if err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
			logger.Warn(fmt.Sprintf("Zone '%s' not found under %s (check --zone / --forest / --legacy).", ctx.Zone, ctx.DNSRoot))
			return nil
		}
		return fmt.Errorf("querying zone '%s': %w", ctx.Zone, err)
	}
	if len(entries) == 0 {
		logger.Warn(fmt.Sprintf("Zone '%s' not found under %s.", ctx.Zone, ctx.DNSRoot))
		return nil
	}
	entry := entries[0]

	props := entry.GetEqualFoldRawAttributeValues("dnsProperty")

	logger.Print(fmt.Sprintf("[>] Zone '%s':", ctx.Zone))
	logger.Print(fmt.Sprintf("  ├── DN: \x1b[94m%s\x1b[0m", entry.DN))
	logger.Print(fmt.Sprintf("  └── Properties (\x1b[93m%d\x1b[0m):", len(props)))

	for i, raw := range props {
		glyph := "├──"
		if i == len(props)-1 {
			glyph = "└──"
		}

		p := &msdnsp.DNS_PROPERTY{}
		if _, err := p.Unmarshal(raw); err != nil {
			logger.Print(fmt.Sprintf("      %s \x1b[91m(unparseable property: %s)\x1b[0m", glyph, err))
			continue
		}

		// Flag insecure dynamic updates: any host can create or overwrite records in the zone.
		if p.Id == msdnsp.DSPROPERTY_ZONE_ALLOW_UPDATE {
			if u, err := p.AsZoneUpdate(); err == nil && u == msdnsp.ZONE_UPDATE_UNSECURE {
				logger.Print(fmt.Sprintf("      %s \x1b[91m%s  [!] insecure dynamic updates allowed\x1b[0m", glyph, p.String()))
				continue
			}
		}

		logger.Print(fmt.Sprintf("      %s \x1b[94m%s\x1b[0m", glyph, p.String()))
	}

	return nil
}
