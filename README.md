![](./.github/banner.png)

<p align="center">
      A tool to query, add, modify, remove, and resurrect Active Directory-integrated DNS records (A, AAAA, NS, CNAME, SOA, SRV) and to enumerate and inspect DNS zones on a domain controller over LDAP.
      <br>
      <a href="https://github.com/TheManticoreProject/adidns/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/adidns/actions/workflows/release.yaml/badge.svg"></a>
      <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TheManticoreProject/adidns">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/adidns">
      <br>
</p>

## Features

- [x] Query the DNS records of a node (`A`, `AAAA`, `NS`, `CNAME`, `SOA`, `SRV`, tombstone).
- [x] Add an `A` record, creating the `dnsNode` if it does not exist (`--allow-multiple` for several).
- [x] Modify, remove (tombstone), resurrect, and LDAP-delete records.
- [x] Enumerate DNS zones across the Domain, Forest, and legacy System partitions.
- [x] Inspect a zone's properties (`dnsProperty`: zone type, dynamic-update policy, aging/scavenging, intervals, server lists).
- [x] NTLM, Pass-the-Hash (`--hashes`), and Kerberos (`--use-kerberos`) authentication, over LDAP or LDAPS.

## Usage

The command grammar is two-level: `adidns <object> <action> [options]`. Running the tool with
no object prints the object list:

```
$ ./adidns
adidns - by TheManticoreProject - v1.0.0

Usage: adidns <record|zone>

   record  Operate on DNS records in a zone.
   zone    Operate on DNS zones.
```

Running an object with no action prints that object's actions:

```
$ ./adidns record
Usage: adidns record <add|delete|modify|query|remove|resurrect>

   add        Add an A record (creating the node if needed).
   delete     Delete a node from LDAP.
   modify     Overwrite the A record of a node.
   query      Show the records of a node.
   remove     Remove an A record, or tombstone the node.
   resurrect  Resurrect a tombstoned node.

$ ./adidns zone
Usage: adidns zone <info|list>

   info  Show the properties of a zone.
   list  List the DNS zones on the server.
```

Every action shares the `Configuration`, `LDAP Connection Settings`, and `Authentication`
option groups, plus the groups specific to that action:

```
$ ./adidns record add
Usage: adidns record add [--allow-multiple] --domain <string> --username <string> [--password <string>] [--hashes <string>] [--debug] --dc-ip <string> [--ldap-port <tcp port>] [--use-ldaps] [--use-kerberos] [--type <string>] [--data <string>] [--ttl <int>] --record <string> [--zone <string>] [--forest] [--legacy]

  Add options:
    --allow-multiple Allow multiple A records on the same node. (default: false)

  Authentication:
    -d, --domain <string>   Active Directory domain to authenticate to.
    -u, --username <string> User to authenticate as.
    -p, --password <string> Password to authenticate with. (default: "")
    -H, --hashes <string>   NT/LM hashes, format is LMhash:NThash. (default: "")

  Configuration:
    --debug         Debug mode. (default: false)

  LDAP Connection Settings:
    -dc, --dc-ip <string>       IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos.
    -lp, --ldap-port <tcp port> Port number to connect to LDAP server. (default: 389)
    -L, --use-ldaps             Use LDAPS instead of LDAP. (default: false)
    -k, --use-kerberos          Use Kerberos instead of NTLM. (default: false)

  Record data:
    -t, --type <string> Record type. Only A is supported for writes. (default: "A")
    -a, --data <string> Record data (an IPv4 address for an A record). (default: "")
    --ttl <int>         TTL, in seconds, for the record. (default: 180)

  Record target:
    -r, --record <string> Record to target (FQDN or name relative to the zone).

  Zone selection:
    -z, --zone <string> Zone to operate in (defaults to the authentication domain). (default: "")
    --forest            Use the ForestDnsZones partition instead of DomainDnsZones. (default: false)
    --legacy            Use the legacy System partition instead of DomainDnsZones. (default: false)
```

### Examples

List the DNS zones on a domain controller:

```
$ ./adidns zone list -dc 10.0.0.1 -d domain.local -u jdoe -p 'Passw0rd!'
[>] Domain DNS zones (2):
  ├── domain.local
  └── RootDNSServers
[>] Forest DNS zones (1):
  └── _msdcs.domain.local
```

Query a record, add one, and remove it (Pass-the-Hash shown for the add):

```
$ ./adidns record query -dc 10.0.0.1 -d domain.local -u jdoe -p 'Passw0rd!' -r dc01.domain.local
[>] Record 'dc01' (1):
  └── DC=dc01,DC=domain.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=local
      ├── Type: DNS_TYPE_A (Serial: 42)
      └── Address: 10.0.0.1

$ ./adidns record add   -dc 10.0.0.1 -d domain.local -u jdoe -H :d0e9a... -r evil.domain.local -a 10.0.0.66
$ ./adidns record remove -dc 10.0.0.1 -d domain.local -u jdoe -p 'Passw0rd!' -r evil.domain.local -a 10.0.0.66
```

Inspect a zone's properties (the dynamic-update policy is highlighted when it is insecure):

```
$ ./adidns zone info -dc 10.0.0.1 -d domain.local -u jdoe -p 'Passw0rd!'
[>] Zone 'domain.local':
  ├── DN: DC=domain.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=local
  └── Properties (9):
      ├── DSPROPERTY_ZONE_TYPE = DNS_ZONE_TYPE_PRIMARY
      ├── DSPROPERTY_ZONE_ALLOW_UPDATE = ZONE_UPDATE_SECURE
      └── ...
```

## Output format

Results are printed with a shared convention, using inline ANSI colours:

- A list of results starts with a `[>] <Title> (<count>):` header, the count highlighted in
  yellow, and the items rendered as a `├──`/`└──` tree.
- Object names, distinguished names, and record values are shown in blue; suspicious findings
  (for example an insecure dynamic-update policy) in red.
- Write results use `[+]` (created), `[~]` (updated), and `[-]` (removed/deleted).
- The tool exits with a non-zero status when an operation fails.

## Building

```
make          # fmt, vet, and build ./bin/adidns
make test     # run the unit tests
```

## Demonstration

<!-- TODO: Add a demonstration -->

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits

- [TheManticoreProject](https://github.com/TheManticoreProject) and the
  [Manticore](https://github.com/TheManticoreProject/Manticore) library it is built on.
- Inspired by [`dnstool.py`](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) from
  the [krbrelayx](https://github.com/dirkjanm/krbrelayx) toolkit by Dirk-jan Mollema
  ([@dirkjanm](https://github.com/dirkjanm)), which pioneered manipulating ADIDNS records over
  LDAP.
