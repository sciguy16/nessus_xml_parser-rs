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
                        // there may only be one Policy section
                        return Err(Error::from("Too many Report sections"));
                    } else {
                        report = Some(Report::from(child)?);
                    }
                }
                other => {
                    // There may not be any other nodes in the document
                    return Err(Error::from(&format!(
                        "Invalid node: {}",
                        other
                    )));
                }
            }
        }

        let policy =
            policy.ok_or_else(|| Error::from("expected Policy section"))?;

        Ok(NessusScan { policy, report })
    }
}
