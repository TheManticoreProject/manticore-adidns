package main

// adidns — query and modify Active Directory-integrated DNS (ADIDNS) over LDAP.
//
// The command grammar is two-level: "adidns <object> <action> [options]", where <object> is
// one of "record" or "zone". Running the tool with no object prints the object list; running
// an object with no action prints that object's action list.
//
// This file is responsible only for (1) declaring the flags, (2) parsing them via the two-level
// sub-parser, and (3) dispatching to the matching <object> function. The action logic
// lives in the <object> packages with shared helpers in common (see plan.md).

import (
	"fmt"
	"os"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/adidns/common"
	"github.com/TheManticoreProject/adidns/record"
	"github.com/TheManticoreProject/adidns/zone"
	"github.com/TheManticoreProject/goopts/parser"
)

// version is reported in the banner.
const version = "1.0.0"

var (
	// object is the first positional argument ("record" or "zone").
	object string
	// recordAction / zoneAction are the second positional argument for each object.
	recordAction string
	zoneAction   string

	// Configuration
	debug bool

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	// LDAP Connection Settings
	domainController string
	ldapPort         int
	useLdaps         bool
	useKerberos      bool

	// Zone selection (shared by record actions and zone actions)
	zoneName string
	forest   bool
	legacy   bool

	// Record target
	recordName string

	// Record data (add / modify / remove)
	recordType    string
	recordData    string
	ttl           int
	allowMultiple bool

	// zone list
	printDN bool
)

// addCommonGroups attaches the Configuration / LDAP / Authentication argument groups that every
// action shares. It works on any sub-parser returned by AddSubParser (all are
// *parser.ArgumentsParser).
func addCommonGroups(grp *parser.ArgumentsParser) {
	if config, err := grp.NewArgumentGroup("Configuration"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
	}

	if ldapSettings, err := grp.NewArgumentGroup("LDAP Connection Settings"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}

	if auth, err := grp.NewArgumentGroup("Authentication"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}
}

// addZoneSelectionGroup attaches the zone-selection flags shared by every record action and by
// the zone actions.
func addZoneSelectionGroup(grp *parser.ArgumentsParser) {
	if zoneSel, err := grp.NewArgumentGroup("Zone selection"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		zoneSel.NewStringArgument(&zoneName, "-z", "--zone", "", false, "Zone to operate in (defaults to the authentication domain).")
		zoneSel.NewBoolArgument(&forest, "", "--forest", false, "Use the ForestDnsZones partition instead of DomainDnsZones.")
		zoneSel.NewBoolArgument(&legacy, "", "--legacy", false, "Use the legacy System partition instead of DomainDnsZones.")
	}
}

// addTargetGroup attaches the record-target flag used by every record action.
func addTargetGroup(grp *parser.ArgumentsParser) {
	if target, err := grp.NewArgumentGroup("Record target"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		target.NewStringArgument(&recordName, "-r", "--record", "", true, "Record to target (FQDN or name relative to the zone).")
	}
}

// addRecordDataGroup attaches the record-data flags used by the add / modify / remove actions.
func addRecordDataGroup(grp *parser.ArgumentsParser) {
	if data, err := grp.NewArgumentGroup("Record data"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		data.NewStringArgument(&recordType, "-t", "--type", "A", false, "Record type. Only A is supported for writes.")
		data.NewStringArgument(&recordData, "-a", "--data", "", false, "Record data (an IPv4 address for an A record).")
		data.NewIntArgument(&ttl, "", "--ttl", 180, false, "TTL, in seconds, for the record.")
	}
}

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: fmt.Sprintf("adidns - by TheManticoreProject - v%s", version)}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	// First positional argument selects the object.
	ap.SetupSubParsing("object", &object, true)

	// --- record object -------------------------------------------------------
	recordParser := ap.AddSubParser("record", "Operate on DNS records in a zone.")
	recordParser.SetupSubParsing("action", &recordAction, true)

	recordQuery := recordParser.AddSubParser("query", "Show the records of a node.")
	addCommonGroups(recordQuery)
	addZoneSelectionGroup(recordQuery)
	addTargetGroup(recordQuery)

	recordAdd := recordParser.AddSubParser("add", "Add an A record (creating the node if needed).")
	addCommonGroups(recordAdd)
	addZoneSelectionGroup(recordAdd)
	addTargetGroup(recordAdd)
	addRecordDataGroup(recordAdd)
	if addOpts, err := recordAdd.NewArgumentGroup("Add options"); err == nil {
		addOpts.NewBoolArgument(&allowMultiple, "", "--allow-multiple", false, "Allow multiple A records on the same node.")
	}

	recordModify := recordParser.AddSubParser("modify", "Overwrite the A record of a node.")
	addCommonGroups(recordModify)
	addZoneSelectionGroup(recordModify)
	addTargetGroup(recordModify)
	addRecordDataGroup(recordModify)

	recordRemove := recordParser.AddSubParser("remove", "Remove an A record, or tombstone the node.")
	addCommonGroups(recordRemove)
	addZoneSelectionGroup(recordRemove)
	addTargetGroup(recordRemove)
	addRecordDataGroup(recordRemove)

	recordResurrect := recordParser.AddSubParser("resurrect", "Resurrect a tombstoned node.")
	addCommonGroups(recordResurrect)
	addZoneSelectionGroup(recordResurrect)
	addTargetGroup(recordResurrect)

	recordDelete := recordParser.AddSubParser("delete", "Delete a node from LDAP.")
	addCommonGroups(recordDelete)
	addZoneSelectionGroup(recordDelete)
	addTargetGroup(recordDelete)

	// --- zone object ---------------------------------------------------------
	zoneParser := ap.AddSubParser("zone", "Operate on DNS zones.")
	zoneParser.SetupSubParsing("action", &zoneAction, true)

	zoneList := zoneParser.AddSubParser("list", "List the DNS zones on the server.")
	addCommonGroups(zoneList)
	addZoneSelectionGroup(zoneList)
	if listOpts, err := zoneList.NewArgumentGroup("List options"); err == nil {
		listOpts.NewBoolArgument(&printDN, "", "--dn", false, "Print the distinguished name of each zone instead of its name.")
	}

	zoneInfo := zoneParser.AddSubParser("info", "Show the properties of a zone.")
	addCommonGroups(zoneInfo)
	addZoneSelectionGroup(zoneInfo)

	ap.Parse()
}

// buildOptions collects the parsed connection, credential, and zone-selection flags into a
// common.Options shared by every action.
func buildOptions() *common.Options {
	return &common.Options{
		DomainController: domainController,
		LDAPPort:         ldapPort,
		UseLDAPS:         useLdaps,
		UseKerberos:      useKerberos,
		Domain:           authDomain,
		Username:         authUsername,
		Password:         authPassword,
		Hashes:           authHashes,
		Zone:             zoneName,
		Forest:           forest,
		Legacy:           legacy,
	}
}

func dispatchRecord() error {
	switch recordAction {
	case "query":
		return record.QueryRecord(buildOptions(), recordName)
	case "add":
		return record.AddRecord(buildOptions(), recordName, recordData, ttl, allowMultiple, recordType)
	case "modify":
		return record.ModifyRecord(buildOptions(), recordName, recordData, recordType)
	case "remove":
		return record.RemoveRecord(buildOptions(), recordName, recordData, recordType)
	case "resurrect":
		return record.ResurrectRecord(buildOptions(), recordName)
	case "delete":
		return record.DeleteRecord(buildOptions(), recordName)
	default:
		return fmt.Errorf("invalid record action '%s'", recordAction)
	}
}

func dispatchZone() error {
	switch zoneAction {
	case "list":
		return zone.ListZones(buildOptions(), printDN)
	case "info":
		return zone.ZoneInfo(buildOptions())
	default:
		return fmt.Errorf("invalid zone action '%s'", zoneAction)
	}
}

func main() {
	parseArgs()

	if debug {
		logger.SetLevel(logger.LevelDebug)
		logger.Debug("Debug mode is enabled")
	} else {
		logger.SetLevel(logger.LevelInfo)
	}

	var err error
	switch object {
	case "record":
		err = dispatchRecord()
	case "zone":
		err = dispatchZone()
	default:
		err = fmt.Errorf("invalid object '%s'", object)
	}

	if err != nil {
		logger.Warn(fmt.Sprintf("Error: %s", err))
		os.Exit(1)
	}
}
