// Copyright 2020 David Young
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn load_full_xml_format() {
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
    }
}
