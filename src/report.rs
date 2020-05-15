// Copyright 2020 David Young
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use super::Error;
use roxmltree::Node;

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

#[derive(Debug)]
pub struct ReportItem {}
