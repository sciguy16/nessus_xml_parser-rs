// Copyright 2020 David Young
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

pub use crate::report::ReportHost;
use policy::Policy;
use report::Report;
use roxmltree::Document;

mod policy;
mod report;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error parsing file as XML document")]
    XmlError(#[from] roxmltree::Error),
    #[error("error parsing Nessus XML output: {0}")]
    InvalidNessusOutput(String),
}

/// Provide From<&str> to allow static strings
impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::InvalidNessusOutput(s.to_string())
    }
}

/// Provide From<&String> to allow format!()
impl From<&String> for Error {
    fn from(s: &String) -> Self {
        Self::InvalidNessusOutput(s.to_string())
    }
}

#[derive(Debug)]
pub struct NessusScan {
    policy: Policy,
    report: Option<Report>,
}

impl NessusScan {
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn report(&self) -> &Option<Report> {
        &self.report
    }

    pub fn parse(nessus_xml_str: &str) -> Result<Self, Error> {
        // Parse the input as XML
        let doc = Document::parse(&nessus_xml_str)?;
        let root_element = doc.root_element();
        if root_element.tag_name().name() != "NessusClientData_v2" {
            return Err(Error::from("expected `NessusClientData_v2` root tag"));
        }

        let mut policy: Option<Policy> = None;
        let mut report: Option<Report> = None;

        for child in root_element.children() {
            match child.tag_name().name() {
                "Policy" => {
                    if policy.is_some() {
                        // there may only be one Policy section
                        return Err(Error::from("Too many Policy sections"));
                    } else {
                        policy = Some(Policy::from(child)?);
                    }
                }
                "Report" => {
                    if report.is_some() {
                        // there may only be one Report section
                        return Err(Error::from("Too many Report sections"));
                    } else {
                        report = Some(Report::parse(&child)?);
                    }
                }
                _ => {}
            }
        }

        let policy =
            policy.ok_or_else(|| Error::from("expected Policy section"))?;

        Ok(NessusScan { policy, report })
    }

    /// Returns an interator over the hosts in the scan
    pub fn hosts(&self) -> std::slice::Iter<ReportHost> {
        if let Some(rep) = &self.report {
            return rep.hosts.iter();
        }
        [].iter()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn load_xml_format_without_report() {
        let xml = r#"<?xml version="1.0" ?>
<NessusClientData_v2>
    <Policy>
        <policyName>MyExamplePolicy</policyName>
        <policyComments>Thisisanexamplepolicy</policyComments>
        <Preferences>
            <ServerPreferences>
                <preference>
                    <name>max_hosts</name>
                    <value>30</value>
                </preference>
                <preference>
                    <name>plugin_set</name>
                    <value>123634;108478;84316;36080;126581;61117;46758;42271;65403;56011;</value>
                </preference>
            </ServerPreferences>
            <PluginsPreferences>
                <item>
                    <pluginName>WebApplicationTestsSettings</pluginName>
                    <pluginId>39471</pluginId>
                    <fullName>WebApplicationTestsSettings[checkbox]:Enablewebapplic-ationstests</fullName>
                    <preferenceName>Enablewebapplicationstests</preferenceName>
                    <preferenceType>checkbox</preferenceType>
                    <preferenceValues>no</preferenceValues>
                    <selectedValue>no</selectedValue>
                </item>
            </PluginsPreferences>
        </Preferences>
        <FamilySelection>
            <FamilyItem>
                <FamilyName>WebServers</FamilyName>
                <Status>disabled</Status>
            </FamilyItem>
        </FamilySelection>
        <IndividualPluginSelection>
            <PluginItem>
                <PluginId>34220</PluginId>
                <PluginName>netstatportscanner(WMI)</PluginName>
                <Family>Portscanners</Family>
                <Status>enabled</Status>
            </PluginItem>
        </IndividualPluginSelection>
    </Policy>
</NessusClientData_v2>
        "#;

        let nessus = NessusScan::parse(&xml).unwrap();

        assert_eq!(nessus.policy().policy_name, "MyExamplePolicy");

        // This report has no report section, so the hosts iterator
        // must therefore be empty (and immediately return None)
        let mut hosts = nessus.hosts();
        assert!(hosts.next().is_none());
    }

    #[test]
    fn load_xml_format_with_report() {
        let xml = r#"<?xml version="1.0" ?>
<NessusClientData_v2>
    <Policy>
        <policyName>MyExamplePolicy</policyName>
        <policyComments>Thisisanexamplepolicy</policyComments>
        <Preferences>
            <ServerPreferences>
                <preference>
                    <name>max_hosts</name>
                    <value>30</value>
                </preference>
                <preference>
                    <name>plugin_set</name>
                    <value>123634;108478;84316;36080;126581;61117;46758;42271;65403;56011;</value>
                </preference>
            </ServerPreferences>
            <PluginsPreferences>
                <item>
                    <pluginName>WebApplicationTestsSettings</pluginName>
                    <pluginId>39471</pluginId>
                    <fullName>WebApplicationTestsSettings[checkbox]:Enablewebapplic-ationstests</fullName>
                    <preferenceName>Enablewebapplicationstests</preferenceName>
                    <preferenceType>checkbox</preferenceType>
                    <preferenceValues>no</preferenceValues>
                    <selectedValue>no</selectedValue>
                </item>
            </PluginsPreferences>
        </Preferences>
        <FamilySelection>
            <FamilyItem>
                <FamilyName>WebServers</FamilyName>
                <Status>disabled</Status>
            </FamilyItem>
        </FamilySelection>
        <IndividualPluginSelection>
            <PluginItem>
                <PluginId>34220</PluginId>
                <PluginName>netstatportscanner(WMI)</PluginName>
                <Family>Portscanners</Family>
                <Status>enabled</Status>
            </PluginItem>
        </IndividualPluginSelection>
    </Policy>
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
</Report>
</NessusClientData_v2>
        "#;

        let nessus = NessusScan::parse(&xml).unwrap();

        assert_eq!(nessus.policy().policy_name, "MyExamplePolicy");

        let mut hosts = nessus.hosts();

        assert_eq!(hosts.next().unwrap().name, "10.129.121.252");
        assert_eq!(hosts.next().unwrap().name, "192.168.0.10");
        assert!(hosts.next().is_none());
    }
}
