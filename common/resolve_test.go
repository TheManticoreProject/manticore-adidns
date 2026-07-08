package common_test

import (
	"testing"

	"github.com/TheManticoreProject/adidns/common"
)

func TestLDAPToDomain(t *testing.T) {
	cases := []struct {
		dn   string
		want string
	}{
		// LDAPToDomain is only ever called on a defaultNamingContext, which is a pure DC= chain.
		{"DC=domain,DC=local", "domain.local"},
		{"DC=corp,DC=example,DC=com", "corp.example.com"},
		{"dc=lower,dc=case", "lower.case"},
		{"CN=NoDomainComponent", ""},
	}
	for _, c := range cases {
		if got := common.LDAPToDomain(c.dn); got != c.want {
			t.Errorf("LDAPToDomain(%q) = %q; want %q", c.dn, got, c.want)
		}
	}
}

func TestDNSRoot(t *testing.T) {
	domainRoot := "DC=domain,DC=local"
	forestRoot := "DC=forest,DC=local"
	cases := []struct {
		name           string
		forest, legacy bool
		want           string
	}{
		{"default", false, false, "CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=local"},
		{"forest", true, false, "CN=MicrosoftDNS,DC=ForestDnsZones,DC=forest,DC=local"},
		{"legacy", false, true, "CN=MicrosoftDNS,CN=System,DC=domain,DC=local"},
		{"forest-wins-over-legacy", true, true, "CN=MicrosoftDNS,DC=ForestDnsZones,DC=forest,DC=local"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := common.DNSRoot(c.forest, c.legacy, domainRoot, forestRoot); got != c.want {
				t.Errorf("DNSRoot(%v,%v) = %q; want %q", c.forest, c.legacy, got, c.want)
			}
		})
	}
}

func TestRelativeTarget(t *testing.T) {
	cases := []struct {
		record, zone, want string
	}{
		{"www.domain.local", "domain.local", "www"},
		{"WWW.DOMAIN.LOCAL", "domain.local", "WWW"},
		{"host.sub.domain.local", "domain.local", "host.sub"},
		{"www", "domain.local", "www"},
		{"other.example.com", "domain.local", "other.example.com"},
		{"domain.local", "domain.local", ""}, // apex, matches dnstool.py behaviour
	}
	for _, c := range cases {
		if got := common.RelativeTarget(c.record, c.zone); got != c.want {
			t.Errorf("RelativeTarget(%q, %q) = %q; want %q", c.record, c.zone, got, c.want)
		}
	}
}
