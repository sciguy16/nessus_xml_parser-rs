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
use std::str::FromStr;

#[derive(Debug)]
pub struct Report {
    description: String,
    hosts: ReportHosts,
}

impl Report {
    pub fn from(_report_xml: Node) -> Result<Self, Error> {
        Err(Error::from("hi"))
    }
}

pub type ReportHosts = Vec<ReportHost>;

#[derive(Debug)]
pub struct ReportHost {
    name: String,
    properties: HostProperties,
    items: ReportItems,
}

pub type HostProperties = Vec<HostProperty>;
pub type ReportItems = Vec<ReportItem>;

//TODO maybe this should be a hashmap
#[derive(Debug)]
pub struct HostProperty {
    name: String,
    value: String,
}

#[derive(Debug, Default)]
pub struct ReportItem {
    port: u16,
    svc_name: String,
    protocol: Protocol,
    severity: Severity,
    plugin_id: usize,
    plugin_name_attr: String,
    plugin_family: String,
    fname: Option<String>,
    plugin_modification_date: Option<String>,
    plugin_name: Option<String>,
    plugin_publication_date: Option<String>,
    plugin_type: Option<String>,
    risk_factor: Option<String>,
    script_version: Option<String>,
    solution: Option<String>,
    synopsis: Option<String>,
    plugin_output: Option<String>,
}

impl ReportItem {
    fn parse(node: &Node) -> Result<Self, Error> {
        let mut item: ReportItem = Default::default();

        item.port = node
            .attribute("port")
            .ok_or_else(|| {
                Error::from("expected `port` attribute in `ReportItem` node")
            })
            .and_then(|s| {
                s.parse::<u16>()
                    .or_else(|_| Err(Error::from("failed to parse `port`")))
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
                s.parse::<Protocol>()
                    .or_else(|_| Err(Error::from("failed to parse `protocol`")))
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
                    .or_else(|_| Err(Error::from("failed to parse `severity`")))
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
                    .or_else(|_| Err(Error::from("failed to parse `pluginID`")))
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
                _ => {}
            }
        }

        Ok(item)
    }
}

#[derive(Debug, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

impl FromStr for Protocol {
    type Err = Error;
    fn from_str(protocol: &str) -> Result<Self, Self::Err> {
        use Protocol::*;
        match protocol {
            "tcp" => Ok(Tcp),
            "udp" => Ok(Udp),
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

#[derive(Debug, FromPrimitive, PartialEq)]
pub enum Severity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Informational
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn test_report_host() {}

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
            let _report_item = ReportItem::parse(&ele);
        }*/
}
