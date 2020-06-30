// Copyright 2020 David Young
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use super::Error;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use roxmltree::Node;
use std::collections::HashMap;
use std::str::FromStr;

/// The Report format. The report is broken down into a list of hosts,
/// each of which has an associated list of findings.
#[derive(Debug, Default)]
pub struct Report {
    /// Name of the report
    pub name: String,
    /// Holds a Vec of [`ReportHost`]s
    pub hosts: ReportHosts,
}

impl Report {
    /// Builds a Report object from an XML node
    pub fn parse(node: &Node) -> Result<Self, Error> {
        let mut report: Report = Default::default();
        report.name = node
            .attribute("name")
            .ok_or_else(|| {
                Error::from("expected `name` attribute in `Report` node")
            })?
            .to_string();
        for child in node.children() {
            if child.tag_name().name() == "ReportHost" {
                report.hosts.push(ReportHost::parse(&child)?);
            }
        }

        Ok(report)
    }
}

/// Type alias for ReportHosts
pub type ReportHosts = Vec<ReportHost>;

/// Container for the properties and findings for a particular host
#[derive(Debug)]
pub struct ReportHost {
    /// Name of the host
    pub name: String,
    /// Metadata about the host
    pub properties: HostProperties,
    /// Findings for the host
    pub items: ReportItems,
}

impl ReportHost {
    /// Builds a ReportHost object from an XML node
    fn parse(node: &Node) -> Result<Self, Error> {
        let name = node
            .attribute("name")
            .ok_or_else(|| {
                Error::from("expected `name` attribute in `ReportHost` node")
            })?
            .to_string();

        // Properties should only occur once, with child tags for the
        // props. Items can occur any number of times
        let mut properties = Default::default();
        let mut items = ReportItems::new();

        for child in node.children() {
            match child.tag_name().name() {
                "HostProperties" => properties = HostProperties::parse(&child)?,
                "ReportItem" => items.push(ReportItem::parse(&child)?),
                _ => {}
            }
        }

        Ok(ReportHost {
            name,
            properties,
            items,
        })
    }
}

impl std::fmt::Display for ReportHost {
    fn fmt(
        &self,
        fmt: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        write!(fmt, "{}", self.name)
    }
}

impl PartialEq for ReportHost {
    fn eq(&self, rhs: &Self) -> bool {
        self.name.eq(&rhs.name)
    }
}

impl Eq for ReportHost {}

impl PartialOrd for ReportHost {
    fn partial_cmp(
        &self,
        rhs: &Self,
    ) -> std::option::Option<std::cmp::Ordering> {
        self.name.partial_cmp(&rhs.name)
    }
}

impl Ord for ReportHost {
    fn cmp(&self, rhs: &Self) -> std::cmp::Ordering {
        self.name.cmp(&rhs.name)
    }
}

/// Metadata about a host, stored as a hashmap
#[derive(Debug, Default)]
pub struct HostProperties(HashMap<String, String>);

/// Type alias for ReportItems
pub type ReportItems = Vec<ReportItem>;

impl HostProperties {
    /// Builds a HostProperties object from an XML node
    fn parse(node: &Node) -> Result<Self, Error> {
        let mut prop = HashMap::new();
        for child in node.children() {
            if child.tag_name().name() == "tag" {
                prop.insert(
                    child
                        .attribute("name")
                        .ok_or_else(|| {
                            Error::from(
                    "expected `name` attribute in `HostProperties tag` node")
                        })?
                        .to_string(),
                    child
                        .text()
                        .ok_or_else(|| {
                            Error::from(
                    "expected value for `tag` in `HostProperties tag` node")
                        })?
                        .to_string(),
                );
            }
        }

        Ok(HostProperties(prop))
    }
}

/// Struct for the data from a finding
#[derive(Debug, Default)]
pub struct ReportItem {
    /// Port number. May be zero if the finding does not relate to a
    /// port
    pub port: u16,
    /// Name of the service running on the port, if known. May also be
    /// a complete guess
    pub svc_name: String,
    /// The protocol (e.g. TCP, UDP, ICMP)
    pub protocol: Protocol,
    /// Severity of the finding
    pub severity: Severity,
    /// ID of the plugin that produced the finding
    pub plugin_id: usize,
    /// Name of the plugin, obtained from the XML tag attributes
    pub plugin_name_attr: String,
    /// The family that the plugin belongs to
    pub plugin_family: String,
    /// The filename of the plugin script
    pub fname: Option<String>,
    /// Last modification date of the plugin. No promises are made about
    /// the date format
    pub plugin_modification_date: Option<String>,
    /// Name of the plugin from the XML child nodes. May or may not
    /// match `plugin_name_attr`
    pub plugin_name: Option<String>,
    /// Publication date of the plugin
    pub plugin_publication_date: Option<String>,
    /// Type of plugin
    pub plugin_type: Option<String>,
    /// Risk factor associated with the plugin
    pub risk_factor: Option<String>,
    /// Version number of the plugin script
    pub script_version: Option<String>,
    /// Remediation information
    pub solution: Option<String>,
    /// Brief description of the vulnerability
    pub synopsis: Option<String>,
    /// Raw output from the plugin script
    pub plugin_output: Option<String>,
    /// Full text description of the vulnerability
    pub description: Option<String>,
    /// asset inventory
    pub asset_inventory: Option<bool>,
    /// Whether OS identification was performed
    pub os_identification: Option<bool>,
}

impl ReportItem {
    /// Builds a ReportItem object from an XML node
    fn parse(node: &Node) -> Result<Self, Error> {
        let mut item: ReportItem = Default::default();

        item.port = node
            .attribute("port")
            .ok_or_else(|| {
                Error::from("expected `port` attribute in `ReportItem` node")
            })
            .and_then(|s| {
                s.parse::<u16>()
                    .map_err(|_| Error::from("failed to parse `port`"))
            })?;

        item.svc_name = node
            .attribute("svc_name")
            .ok_or_else(|| {
                Error::from(
                    "expected `svc_name` attribute in `ReportItem` node",
                )
            })?
            .to_string();

        item.protocol = node
            .attribute("protocol")
            .ok_or_else(|| {
                Error::from(
                    "expected `protocol` attribute in `ReportItem` node",
                )
            })
            .and_then(|s| {
                s.parse::<Protocol>().map_err(|_| {
                    Error::from(&format!("failed to parse `protocol`: {}", s))
                })
            })?;

        item.severity = node
            .attribute("severity")
            .ok_or_else(|| {
                Error::from(
                    "expected `severity` attribute in `ReportItem` node",
                )
            })
            .and_then(|s| {
                s.parse::<usize>()
                    .map_err(|_| Error::from("failed to parse `severity`"))
            })
            .and_then(|s| {
                Severity::from_usize(s)
                    .ok_or_else(|| Error::from("failed to parse `severity`"))
            })?;

        item.plugin_id = node
            .attribute("pluginID")
            .ok_or_else(|| {
                Error::from(
                    "expected `pluginID` attribute in `ReportItem` node",
                )
            })
            .and_then(|s| {
                s.parse::<usize>()
                    .map_err(|_| Error::from("failed to parse `pluginID`"))
            })?;

        item.plugin_name_attr = node
            .attribute("pluginName")
            .ok_or_else(|| {
                Error::from(
                    "expected `pluginName` attribute in `ReportItem` node",
                )
            })?
            .to_string();

        item.plugin_family = node
            .attribute("pluginFamily")
            .ok_or_else(|| {
                Error::from(
                    "expected `pluginFamily` attribute in `ReportItem` node",
                )
            })?
            .to_string();

        for child in node.children() {
            match child.tag_name().name() {
                "fname" => item.fname = child.text().map(|s| s.to_string()),
                "plugin_modification_date" => {
                    item.plugin_modification_date =
                        child.text().map(|s| s.to_string())
                }
                "plugin_name" => {
                    item.plugin_name = child.text().map(|s| s.to_string())
                }
                "plugin_publication_date" => {
                    item.plugin_publication_date =
                        child.text().map(|s| s.to_string())
                }
                "plugin_type" => {
                    item.plugin_type = child.text().map(|s| s.to_string())
                }
                "risk_factor" => {
                    item.risk_factor = child.text().map(|s| s.to_string())
                }
                "script_version" => {
                    item.script_version = child.text().map(|s| s.to_string())
                }
                "solution" => {
                    item.solution = child.text().map(|s| s.to_string())
                }
                "synopsis" => {
                    item.synopsis = child.text().map(|s| s.to_string())
                }
                "plugin_output" => {
                    item.plugin_output = child.text().map(|s| s.to_string())
                }
                "description" => {
                    item.description = child.text().map(|s| s.to_string())
                }
                "asset_inventory" => {
                    item.asset_inventory = child
                        .text()
                        .map(|s| s.to_lowercase().parse::<bool>())
                        .transpose()
                        .map_err(|e| Error::from(&format!("{}", e)))?
                }
                "os_identification" => {
                    item.os_identification = child
                        .text()
                        .map(|s| s.to_lowercase().parse::<bool>())
                        .transpose()
                        .map_err(|e| Error::from(&format!("{}", e)))?
                }

                _ => {}
            }
        }

        Ok(item)
    }

    /// Returns a [`Port`] object corresponding to the current finding
    pub fn port(&self) -> Port {
        Port {
            id: self.port,
            protocol: self.protocol,
            service: self.svc_name.clone(),
        }
    }
}

/// The network protocols supported by Nessus
#[derive(Copy, Clone, Debug, Eq, PartialOrd, Ord, PartialEq)]
pub enum Protocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP
    Icmp,
    /// SCTP
    Sctp,
}

impl FromStr for Protocol {
    type Err = Error;
    fn from_str(protocol: &str) -> Result<Self, Self::Err> {
        use Protocol::*;
        match protocol {
            "tcp" => Ok(Tcp),
            "udp" => Ok(Udp),
            "icmp" => Ok(Icmp),
            "sctp" => Ok(Sctp),
            other => Err(Error::from(&format!("Invalid protocol: {}", other))),
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Tcp
    }
}

/// Severity ratings for findings
#[derive(Debug, FromPrimitive, PartialEq)]
pub enum Severity {
    /// Informational
    Informational = 0,
    /// Low severity
    Low = 1,
    /// Medium severity
    Medium = 2,
    /// High severity
    High = 3,
    /// Critical severity
    Critical = 4,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Informational
    }
}

/// Maps port number to protocol and service name
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Port {
    /// Port number
    pub id: u16,
    /// Protocol (TCP, UDP, etc.)
    pub protocol: Protocol,
    /// Service name
    pub service: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn test_report_host() {
        let xml = r#"
<ReportHost name="192.168.0.10">
    <HostProperties>
        <tag name="HOST_END">Wed Mar 09 22:55:00 2011</tag>
        <tag name="operating-system">MicrosoftWindowsXPProfessional(English)</tag>
        <tag name="mac-address">00:1e:8c:83:ad:5f</tag>
        <tag name="netbios-name">ZESTY</tag>
        <tag name="HOST_START">Wed Mar 09 22:48:10 2011</tag>
    </HostProperties>
    <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="0" pluginID="10394" pluginName="Microsoft Windows SMB Log In Possible" pluginFamily="Windows">
        <asset_inventory>True</asset_inventory>
        <description>The remote host is running a Microsoft Windows operating system or Samba, a CIFS/SMB server for Unix. It was possible to log into it using one of the following accounts :

- NULL session
- Guest account
- Supplied credentials</description>
        <fname>smb_login.nasl</fname>
        <plugin_modification_date>2020/03/09</plugin_modification_date>
        <plugin_name>Microsoft Windows SMB Log In Possible</plugin_name>
        <plugin_publication_date>2000/05/09</plugin_publication_date>
        <plugin_type>remote</plugin_type>
        <risk_factor>None</risk_factor>
        <script_version>1.160</script_version>
        <see_also>http://www.nessus.org/u?5c2589f6
https://support.microsoft.com/en-us/help/246261</see_also>
        <solution>n/a</solution>
        <synopsis>It was possible to log into the remote host.</synopsis>
        <plugin_output>- NULL sessions are enabled on the remote host.
</plugin_output>
    </ReportItem>
    <ReportItem port="139" svc_name="smb" protocol="tcp" severity="0" pluginID="11011" pluginName="Microsoft Windows SMB Service Detection" pluginFamily="Windows">
        <asset_inventory>True</asset_inventory>
        <description>The remote service understands the CIFS (Common Internet File System) or Server Message Block (SMB) protocol, used to provide shared access to files, printers, etc between nodes on a network.</description>
        <fname>cifs445.nasl</fname>
        <os_identification>True</os_identification>
        <plugin_modification_date>2020/01/22</plugin_modification_date>
        <plugin_name>Microsoft Windows SMB Service Detection</plugin_name>
        <plugin_publication_date>2002/06/05</plugin_publication_date>
        <plugin_type>remote</plugin_type>
        <risk_factor>None</risk_factor>
        <script_version>1.41</script_version>
        <solution>n/a</solution>
        <synopsis>A file / print sharing service is listening on the remote host.</synopsis>
        <plugin_output>
An SMB server is running on this port.
</plugin_output>
    </ReportItem>
</ReportHost>
        "#;

        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let _report_host = ReportHost::parse(&ele).unwrap();
    }

    #[test]
    fn test_report_item() {
        let xml = r#"
<ReportItem
    port="445"
    svc_name="cifs"
    protocol="tcp"
    severity="3"
    pluginID="49174"
    pluginName="Opera&lt;10.62PathSubversionArbitraryDLLInjectionCodeExecution"
    pluginFamily="Windows"
    >
    <exploitability_ease>Exploitsareavailable</exploitability_ease>
    <vuln_publication_date>2010/08/24</vuln_publication_date>
    <cvss_temporal_vector>CVSS2#E:F/RL:W/RC:ND</cvss_temporal_vector>
    <solution>UpgradetoOpera10.62orlater.</solution>
    <cvss_temporal_score>8.4</cvss_temporal_score>
    <risk_factor>High</risk_factor>
    <description>TheversionofOperainstalledontheremotehostisearlierthan10.62.SuchversionsinsecurelylookintheircurrentworkingdirectorywhenresolvingDLLdependencies,suchasfor&apos;dwmapi.dll&apos;[..]</description>
    <plugin_publication_date>2010/09/10</plugin_publication_date>
    <cvss_vector>CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C</cvss_vector>
    <synopsis>Theremotehostcontainsawebbrowserthatallowsarbitrarycodeexecution.</synopsis>
    <patch_publication_date>2010/09/09</patch_publication_date>
    <see_also>http://www.opera.com/docs/changelogs/windows/1062/</see_also>
    <see_also>http://www.opera.com/support/kb/view/970/</see_also>
    <exploit_available>true</exploit_available>
    <plugin_modification_date>2010/12/23</plugin_modification_date>
    <cvss_base_score>9.3</cvss_base_score>
    <bid>42663</bid>
    <xref>OSVDB:67498</xref>
    <xref>Secunia:41083</xref>
    <xref>EDB-ID:14732</xref>
    <plugin_output></plugin_output>
    <plugin_version>$Revision:1.3$</plugin_version>
</ReportItem>
        "#;

        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let report_item = ReportItem::parse(&ele).unwrap();

        assert_eq!(report_item.port, 445);
        assert_eq!(report_item.svc_name, "cifs");
        assert_eq!(report_item.protocol, Protocol::Tcp);
        assert_eq!(report_item.severity, Severity::High);
        assert_eq!(report_item.plugin_id, 49174);
        assert_eq!(
            report_item.plugin_name_attr,
            "Opera<10.62PathSubversionArbitraryDLLInjectionCodeExecution"
        );
        assert_eq!(report_item.plugin_family, "Windows");
    }

    #[test]
    fn test_another_report_item() {
        let xml = r#"
<ReportItem port="3456" svc_name="vat?" protocol="udp" severity="0" pluginID="14274" pluginName="Nessus SNMP Scanner" pluginFamily="Port scanners">
    <description>This plugin runs an SNMP scan against the remote machine to find open ports.

See the section &apos;plugins options&apos; to configure it.</description>
    <fname>snmpwalk_portscan.nasl</fname>
    <plugin_modification_date>2018/01/29</plugin_modification_date>
    <plugin_name>Nessus SNMP Scanner</plugin_name>
    <plugin_publication_date>2004/08/15</plugin_publication_date>
    <plugin_type>remote</plugin_type>
    <risk_factor>None</risk_factor>
    <script_version>$Revision: 1.31 $</script_version>
    <solution>n/a</solution>
    <synopsis>SNMP information is enumerated to learn about other open ports.</synopsis>
    <plugin_output>Port 3456/udp was found to be open</plugin_output>
</ReportItem>
        "#;

        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let report_item = ReportItem::parse(&ele).unwrap();

        assert_eq!(report_item.port, 3456);
        assert_eq!(report_item.svc_name, "vat?");
        assert_eq!(report_item.protocol, Protocol::Udp);
        assert_eq!(report_item.severity, Severity::Informational);
        assert_eq!(report_item.plugin_id, 14274);
        assert_eq!(report_item.plugin_name_attr, "Nessus SNMP Scanner");
        assert_eq!(report_item.plugin_family, "Port scanners");

        assert_eq!(report_item.fname.unwrap(), "snmpwalk_portscan.nasl");
        assert_eq!(report_item.plugin_modification_date.unwrap(), "2018/01/29");
        assert_eq!(report_item.plugin_name.unwrap(), "Nessus SNMP Scanner");
        assert_eq!(report_item.plugin_publication_date.unwrap(), "2004/08/15");
        assert_eq!(report_item.plugin_type.unwrap(), "remote");
        assert_eq!(report_item.risk_factor.unwrap(), "None");
        assert_eq!(report_item.script_version.unwrap(), "$Revision: 1.31 $");
        assert_eq!(report_item.solution.unwrap(), "n/a");
        assert_eq!(
            report_item.synopsis.unwrap(),
            "SNMP information is enumerated to learn about other open ports."
        );
        assert_eq!(
            report_item.plugin_output.unwrap(),
            "Port 3456/udp was found to be open"
        );
    }

    /*#[test]
        fn test_report_item_with_compliance() {
            let xml = r#"
    <ReportItem
        port="0"
        svc_name="general"
        protocol="tcp"
        severity="3"
        pluginID="21157"
        pluginName="UnixComplianceChecks"
        pluginFamily="PolicyCompliance"
        >
        <fname>unix_compliance_check.nbin</fname>
        <plugin_modification_date>2012/06/20</plugin_modification_date>
        <plugin_name>UnixComplianceChecks</plugin_name>
        <plugin_publication_date>2006/03/27</plugin_publication_date>
        <plugin_type>local</plugin_type>
        <risk_factor>None</risk_factor>
        <cm:compliance-info>LocalandremotestorageofApacheerrorlogsiscrit-icaltosuccessfulbreak-ininvestigationandshouldbeconfiguredviathesyslogfacility.ref.CIS_Apache_Benchmark_v2.1.pdf,ch.1,pp44-46.CheckingthatyouryourApacheconfigurationfilecontainsthepropersys-logentry.</cm:compliance-info>
        <cm:compliance-result>FAILED</cm:compliance-result>
        <cm:compliance-actual-value>Thefile&quot;/us-r/local/apache2/conf/httpd.conf&quot;couldnotbefound</cm:compliance-actual-value>
        <cm:compliance-check-id>0380a6f83735bfd70235e8da91821049</cm:compliance-check-id>
        <cm:compliance-audit-file>CIS_Apache_v2_1.audit</cm:compliance-audit-file>
        <cm:compliance-check-name>2.5SyslogLogging.(ErrorLog)</cm:compliance-check-name>
        <description>&quot;2.5SyslogLogging.(ErrorLog)&quot;:[FAILED]LocalandremotestorageofApacheerrorlogsiscriticaltosuccessfulbreak-ininvestigationandshouldbeconfiguredviathesyslogfacility.ref.CIS_Apache_Benchmark_v2.1.pdf,ch.1,pp44-46.CheckingthatyouryourApacheconfigurationfilecontainsthepropersys-logentry.-errormessage:Thefile&quot;/usr/local/apache2/conf/httpd.conf&quot;couldnotbefound</description>
    </ReportItem>
            "#;

            let doc = Document::parse(&xml).unwrap();
            let ele = doc.root_element();
            let _report_item = ReportItem::parse(&ele).unwrap();
        }*/

    #[test]
    fn host_properties() {
        let xml = r#"
<HostProperties>
    <tag name="HOST_END">Wed Mar 09 22:55:00 2011</tag>
    <tag name="operating-system">MicrosoftWindowsXPProfessional(English)</tag>
    <tag name="mac-address">00:1e:8c:83:ad:5f</tag>
    <tag name="netbios-name">ZESTY</tag>
    <tag name="HOST_START">Wed Mar 09 22:48:10 2011</tag>
</HostProperties>
        "#;

        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let host_properties = HostProperties::parse(&ele).unwrap();

        let test_values = vec![
            ("HOST_END", "Wed Mar 09 22:55:00 2011"),
            (
                "operating-system",
                "MicrosoftWindowsXPProfessional(English)",
            ),
            ("mac-address", "00:1e:8c:83:ad:5f"),
            ("netbios-name", "ZESTY"),
            ("HOST_START", "Wed Mar 09 22:48:10 2011"),
        ];

        for (k, v) in test_values {
            assert_eq!(host_properties.0.get(k).unwrap(), v);
        }
    }

    #[test]
    fn report() {
        let xml = r#"
<Report name="Router-Uncredentialed">
    <ReportHost name="10.129.121.252">
        <HostProperties>
            <tag name="cpe-3">cpe:/a:mysql:mysql:5.5.9 -&gt; MySQL 5.5.9</tag>
            <tag name="cpe-2">cpe:/a:mysql:mysql:5.5.9 -&gt; MySQL 5.5.9</tag>
            <tag name="netbios-name">ECLIPSE</tag>
            <tag name="cpe-1">cpe:/o:microsoft:windows_xp</tag>
            <tag name="cpe-0">cpe:/o:microsoft:windows_2000</tag>
            <tag name="HOST_END_TIMESTAMP">1593441583</tag>
            <tag name="HOST_END">Mon Jun 29 14:39:43 2020</tag>
            <tag name="host-ip">10.129.121.252</tag>
            <tag name="HOST_START_TIMESTAMP">1593441445</tag>
            <tag name="HOST_START">Mon Jun 29 14:37:25 2020</tag>
        </HostProperties>
        <ReportItem
            port="445"
            svc_name="cifs"
            protocol="tcp"
            severity="0"
            pluginID="11011"
            pluginName="Microsoft Windows SMB Service Detection"
            pluginFamily="Windows"
            >
            <asset_inventory>True</asset_inventory>
            <description>
                The remote service understands the CIFS (Common Internet File
                System) or Server Message Block (SMB) protocol, used to provide
                shared access to files, printers, etc between nodes on a network.
            </description>
            <fname>cifs445.nasl</fname>
            <os_identification>True</os_identification>
            <plugin_modification_date>2020/01/22</plugin_modification_date>
            <plugin_name>Microsoft Windows SMB Service Detection</plugin_name>
            <plugin_publication_date>2002/06/05</plugin_publication_date>
            <plugin_type>remote</plugin_type>
            <risk_factor>None</risk_factor>
            <script_version>1.41</script_version>
            <solution>n/a</solution>
            <synopsis>
                A file / print sharing service is listening on the remote host.
            </synopsis>
            <plugin_output>
                A CIFS server is running on this port.
            </plugin_output>
        </ReportItem>
    </ReportHost>
</Report>
        "#;

        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let report = Report::parse(&ele).unwrap();

        assert_eq!(report.name, "Router-Uncredentialed");

        // there's only one host in this report, so grab it
        assert_eq!(report.hosts.len(), 1);
        let h = report.hosts.first().unwrap();

        let test_values = vec![
            ("cpe-3", "cpe:/a:mysql:mysql:5.5.9 -> MySQL 5.5.9"),
            ("cpe-2", "cpe:/a:mysql:mysql:5.5.9 -> MySQL 5.5.9"),
            ("netbios-name", "ECLIPSE"),
            ("cpe-1", "cpe:/o:microsoft:windows_xp"),
            ("cpe-0", "cpe:/o:microsoft:windows_2000"),
            ("HOST_END_TIMESTAMP", "1593441583"),
            ("HOST_END", "Mon Jun 29 14:39:43 2020"),
            ("host-ip", "10.129.121.252"),
            ("HOST_START_TIMESTAMP", "1593441445"),
            ("HOST_START", "Mon Jun 29 14:37:25 2020"),
        ];

        for (k, v) in test_values {
            assert_eq!(h.properties.0.get(k).unwrap(), v);
        }

        // one report item for this host
        assert_eq!(h.items.len(), 1);
        let r = &h.items.first().unwrap();
        assert_eq!(r.svc_name, "cifs");
        assert_eq!(r.protocol, Protocol::Tcp);
        assert_eq!(r.severity, Severity::Informational);
        assert_eq!(r.plugin_id, 11011);
        assert_eq!(
            r.plugin_name_attr,
            "Microsoft Windows SMB Service Detection"
        );
        assert_eq!(r.plugin_family, "Windows");
        assert_eq!(r.asset_inventory.unwrap(), true);
        assert_eq!(
            r.description.as_ref().unwrap(),
            r#"
                The remote service understands the CIFS (Common Internet File
                System) or Server Message Block (SMB) protocol, used to provide
                shared access to files, printers, etc between nodes on a network.
            "#
        );
        assert_eq!(r.fname.as_ref().unwrap(), "cifs445.nasl");
        assert_eq!(r.os_identification.unwrap(), true);
        assert_eq!(r.plugin_modification_date.as_ref().unwrap(), "2020/01/22");
        assert_eq!(
            r.plugin_name.as_ref().unwrap(),
            "Microsoft Windows SMB Service Detection"
        );
        assert_eq!(r.plugin_publication_date.as_ref().unwrap(), "2002/06/05");
        assert_eq!(r.plugin_type.as_ref().unwrap(), "remote");
        assert_eq!(r.risk_factor.as_ref().unwrap(), "None");
        assert_eq!(r.script_version.as_ref().unwrap(), "1.41");
        assert_eq!(r.solution.as_ref().unwrap(), "n/a");
        assert_eq!(
            r.synopsis.as_ref().unwrap(),
            r#"
                A file / print sharing service is listening on the remote host.
            "#
        );
        assert_eq!(
            r.plugin_output.as_ref().unwrap(),
            r#"
                A CIFS server is running on this port.
            "#
        );
    }
}
