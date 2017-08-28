package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/empijei/nipty/importers"
)

type Row struct {
	IPAddress, NetBIOSName, FQDN, Severity, RiskFactor, ID, Port, Protocol, Service, Vulnerability, Plugin, CVE, CVSS_base, CVSS_vector, PatchDate string
}

func GetHeader() []string {
	return []string{"IP Address", "NetBIOS Name", "FQDN", "Severity", "Risk Factor", "ID", "Port", "Protocol", "Service", "Vulnerability", "Plugin", "CVE", "CVSS_base", "CVSS_vector", "Patch Date"}
}

func (r *Row) GetCsv() []string {
	return []string{r.IPAddress, r.NetBIOSName, r.FQDN, r.Severity, r.RiskFactor, r.ID, r.Port, r.Protocol, r.Service, r.Vulnerability, r.Plugin, r.CVE, r.CVSS_base, r.CVSS_vector, r.PatchDate}
}

func convert(in io.Reader, out io.Writer) (err error) {
	minseverity := 0
	csvout := csv.NewWriter(out)
	defer csvout.Flush()
	csvout.Comma = ','
	err = csvout.Write(GetHeader())
	if err != nil {
		return err
	}
	parsed, err := importers.ParseNessus(in)
	if err != nil {
		return err
	}
	for _, host := range parsed.Report.ReportHosts {
		for _, reportitem := range host.ReportItems {
			if reportitem.Severity >= minseverity {
				row := &Row{}
				for _, tag := range host.HostProperties.Tags {
					switch tag.Name {
					case "host-ip":
						row.IPAddress = tag.Data
					case "netbios-name":
						row.NetBIOSName = tag.Data
					case "host-fqdn":
						row.FQDN = tag.Data
					}
				}
				row.Plugin = reportitem.PluginName
				row.Service = reportitem.SvcName
				row.Protocol = reportitem.Protocol
				row.Severity = fmt.Sprintf("%d", reportitem.Severity)
				row.Port = fmt.Sprintf("%d", reportitem.Port)
				row.PatchDate = reportitem.PatchPublicationDate

				switch {
				case reportitem.CVSS3BaseScore != 0:
					row.CVSS_base = fmt.Sprintf("%.1f", reportitem.CVSS3BaseScore)
					row.CVSS_vector = reportitem.CVSS3Vector
				case reportitem.CVSSBaseScore != 0:
					row.CVSS_base = fmt.Sprintf("%.1f", reportitem.CVSSBaseScore)
					row.CVSS_vector = reportitem.CVSSVector
				}

				switch reportitem.Severity {
				case 0:
					row.RiskFactor = "Info"
				case 1:
					row.RiskFactor = "Low"
				case 2:
					row.RiskFactor = "Medium"
				case 3:
					row.RiskFactor = "High"
				case 4:
					row.RiskFactor = "Critical"
				}
				row.Plugin = computePlugin(&reportitem, row)

				err = csvout.Write(row.GetCsv())
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func computePlugin(reportitem *importers.ReportItem, row *Row) string {
	if reportitem.PluginName == "SSL Version 2 and 3 Protocol Detection" {
		switch {
		case !strings.Contains(reportitem.PluginOutput, "SSLv2"):
			reportitem.PluginName = "SSL Version 3 Protocol Detection"
		case !strings.Contains(reportitem.PluginOutput, "SSLv3"):
			reportitem.PluginName = "SSL Version 2 Protocol Detection"
		}
	}

	mustmatch := func(pattern string, s string) bool {
		m, e := regexp.MatchString(pattern, s)
		if e != nil {
			panic(e)
		}
		return m
	}

	switch {
	case mustmatch("MS[0-9]{2}-[0-9]{3}", reportitem.PluginName):
		row.Vulnerability = "Outdated and Vulnerable Windows Operating System"
	case strings.Contains(reportitem.PluginName, "TRACE"):
		row.Vulnerability = "HTTP TRACE Method Enabled"
	case mustmatch("(^SSL |^TLS |^SSL/TLS |^SSLv[0-9] |^Transport Layer)", reportitem.PluginName):
		row.Vulnerability = "SSL/TLS Multiple Issues"
	case strings.Contains(reportitem.PluginName, "<"):
		row.Vulnerability = "Outdated and Vulnerable Software Installation"
	case strings.Contains(reportitem.PluginName, "Microsoft Windows Server 2003 Unsupported"):
		row.Vulnerability = "Unsupported and Vulnerable Windows Operating System"
	case strings.Contains(reportitem.PluginName, "SMB"):
		row.Vulnerability = "Samba Multiple Issues"
	case mustmatch("(Terminal Services|Remote Desktop Protocol)", reportitem.PluginName):
		row.Vulnerability = "Remote Desktop Protocol Multiple Issues"
	case strings.Contains(reportitem.PluginName, "SSH"):
		row.Vulnerability = "SSH Cryptographic Issues"
	}
	row.CVE = strings.Join(reportitem.CVE, ",")

	return reportitem.PluginName
}
