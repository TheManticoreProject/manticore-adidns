// Package common holds the setup and helpers shared by every adidns object (record, zone).
//
// The entry point is Setup, which authenticates, opens an LDAP session, reads the RootDSE, and
// resolves the naming contexts, the MicrosoftDNS partition root, the target zone, and the zone
// search base into a Context. Each object's action functions take that Context and operate on
// it (see the record and zone packages).
package common

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Options carries everything Setup needs: the LDAP connection settings, the credentials, and
// the zone selection. main.go fills it from the parsed flags.
type Options struct {
	// LDAP connection settings
	DomainController string
	LDAPPort         int
	UseLDAPS         bool
	UseKerberos      bool

	// Credentials
	Domain   string
	Username string
	Password string
	Hashes   string

	// Zone selection
	Zone   string // empty => default to the authentication domain
	Forest bool   // use the ForestDnsZones partition
	Legacy bool   // use the legacy System partition
}

// Context is the resolved, connected state shared by every action.
type Context struct {
	// Session is the connected LDAP session.
	Session *ldap.Session

	// DomainRoot is the defaultNamingContext (e.g. "DC=domain,DC=local").
	DomainRoot string
	// ForestRoot is the rootDomainNamingContext.
	ForestRoot string
	// SchemaNC is the schemaNamingContext, used to build a dnsNode objectCategory.
	SchemaNC string

	// DNSRoot is the MicrosoftDNS partition root selected by the zone-selection flags.
	DNSRoot string
	// Zone is the DNS zone name (e.g. "domain.local").
	Zone string
	// SearchBase is "DC=<Zone>,<DNSRoot>", the base under which zone nodes live.
	SearchBase string
}

// Setup authenticates and resolves the Context from the provided options.
//
// Parameters:
//
//	opts (*Options): The LDAP connection settings, credentials, and zone selection.
//
// Returns:
//
//	*Context: The connected, resolved context. The caller must call Close when done.
//	error: An error if authentication, connection, or RootDSE resolution fails.
func Setup(opts *Options) (*Context, error) {
	creds, err := credentials.NewCredentials(opts.Domain, opts.Username, opts.Password, opts.Hashes)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	session, err := ldap.NewSession(opts.DomainController, opts.LDAPPort, creds, opts.UseLDAPS, opts.UseKerberos)
	if err != nil {
		return nil, fmt.Errorf("creating LDAP session: %w", err)
	}

	ok, err := session.Connect()
	if err != nil {
		return nil, fmt.Errorf("could not establish an LDAP session to %s:%d (check the DC address, credentials, and --use-ldaps): %w", opts.DomainController, opts.LDAPPort, err)
	}
	if !ok {
		return nil, fmt.Errorf("could not establish an LDAP session to %s:%d", opts.DomainController, opts.LDAPPort)
	}

	rootDSE, err := session.GetRootDSE()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("fetching RootDSE: %w", err)
	}

	ctx := &Context{
		Session:    session,
		DomainRoot: rootDSE.GetAttributeValue("defaultNamingContext"),
		ForestRoot: rootDSE.GetAttributeValue("rootDomainNamingContext"),
		SchemaNC:   rootDSE.GetAttributeValue("schemaNamingContext"),
	}
	if ctx.DomainRoot == "" {
		session.Close()
		return nil, fmt.Errorf("RootDSE did not return a defaultNamingContext")
	}

	ctx.DNSRoot = DNSRoot(opts.Forest, opts.Legacy, ctx.DomainRoot, ctx.ForestRoot)

	ctx.Zone = opts.Zone
	if ctx.Zone == "" {
		ctx.Zone = LDAPToDomain(ctx.DomainRoot)
	}

	ctx.SearchBase = fmt.Sprintf("DC=%s,%s", ctx.Zone, ctx.DNSRoot)

	return ctx, nil
}

// NodeDN returns the distinguished name of a node relative to the current zone, e.g.
// "DC=www,DC=domain.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=local".
//
// Parameters:
//
//	target (string): The node name relative to the zone (see RelativeTarget).
//
// Returns:
//
//	string: The node's distinguished name.
func (ctx *Context) NodeDN(target string) string {
	return fmt.Sprintf("DC=%s,%s", target, ctx.SearchBase)
}

// Close terminates the underlying LDAP session.
func (ctx *Context) Close() {
	if ctx != nil && ctx.Session != nil {
		ctx.Session.Close()
	}
}
