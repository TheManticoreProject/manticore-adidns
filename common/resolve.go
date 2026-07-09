package common

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	goldap "github.com/go-ldap/ldap/v3"
)

// dcComponent matches a ",DC=" component separator, case-insensitively.
var dcComponent = regexp.MustCompile(`(?i),DC=`)

// LDAPToDomain converts a distinguished name to a dotted DNS domain using its DC= components,
// e.g. "DC=domain,DC=local" -> "domain.local". It mirrors dnstool.py's ldap2domain.
//
// Parameters:
//
//	dn (string): The distinguished name.
//
// Returns:
//
//	string: The dotted domain, or "" if the DN has no DC= component.
func LDAPToDomain(dn string) string {
	idx := strings.Index(strings.ToUpper(dn), "DC=")
	if idx == -1 {
		return ""
	}
	// Take the DC=... tail, turn every ",DC=" into ".", then drop the leading "DC=".
	tail := dcComponent.ReplaceAllString(dn[idx:], ".")
	return tail[3:]
}

// DNSRoot returns the MicrosoftDNS partition root selected by the zone-selection flags.
//
// Parameters:
//
//	forest (bool): Use the ForestDnsZones partition.
//	legacy (bool): Use the legacy System partition.
//	domainRoot (string): The defaultNamingContext.
//	forestRoot (string): The rootDomainNamingContext.
//
// Returns:
//
//	string: The distinguished name of the MicrosoftDNS partition root. When both forest and
//	legacy are set, forest takes precedence.
func DNSRoot(forest, legacy bool, domainRoot, forestRoot string) string {
	switch {
	case forest:
		return fmt.Sprintf("CN=MicrosoftDNS,DC=ForestDnsZones,%s", forestRoot)
	case legacy:
		return fmt.Sprintf("CN=MicrosoftDNS,CN=System,%s", domainRoot)
	default:
		return fmt.Sprintf("CN=MicrosoftDNS,DC=DomainDnsZones,%s", domainRoot)
	}
}

// RelativeTarget strips a trailing ".<zone>" suffix from an FQDN record name so it can be used
// as a node name relative to the zone, mirroring dnstool.py. A name that does not end in the
// zone is returned unchanged.
//
// Parameters:
//
//	record (string): The record name (FQDN or already relative).
//	zone (string): The zone name.
//
// Returns:
//
//	string: The node name relative to the zone.
func RelativeTarget(record, zone string) string {
	if zone != "" && strings.HasSuffix(strings.ToLower(record), strings.ToLower(zone)) {
		cut := len(record) - len(zone) - 1
		if cut < 0 {
			cut = 0
		}
		return record[:cut]
	}
	return record
}

// FindNode looks up a dnsNode by its name relative to the current zone.
//
// Parameters:
//
//	target (string): The node name relative to the zone (see RelativeTarget).
//
// Returns:
//
//	*ldap.Entry: The matching entry (with dnsRecord, dNSTombstoned, and name), or nil if no
//	node with that name exists.
//	error: An error if the search fails.
func (ctx *Context) FindNode(target string) (*ldap.Entry, error) {
	filter := fmt.Sprintf("(&(objectClass=dnsNode)(name=%s))", goldap.EscapeFilter(target))
	entries, err := ctx.Session.QuerySingleLevel(ctx.SearchBase, filter, []string{"dnsRecord", "dNSTombstoned", "name"})
	if err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
			return nil, fmt.Errorf("zone '%s' not found under %s (check --zone / --forest / --legacy)", ctx.Zone, ctx.DNSRoot)
		}
		return nil, fmt.Errorf("searching for node %q: %w", target, err)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return entries[0], nil
}

// ListNodes returns every dnsNode directly under the current zone, each with its dnsRecord,
// dNSTombstoned, and name attributes.
//
// Returns:
//
//	[]*ldap.Entry: The zone's nodes (possibly empty).
//	error: An error if the search fails, including a helpful message when the zone does not exist.
func (ctx *Context) ListNodes() ([]*ldap.Entry, error) {
	entries, err := ctx.Session.QuerySingleLevel(ctx.SearchBase, "(objectClass=dnsNode)", []string{"dnsRecord", "dNSTombstoned", "name"})
	if err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
			return nil, fmt.Errorf("zone '%s' not found under %s (check --zone / --forest / --legacy)", ctx.Zone, ctx.DNSRoot)
		}
		return nil, fmt.Errorf("listing nodes in zone %q: %w", ctx.Zone, err)
	}
	return entries, nil
}
