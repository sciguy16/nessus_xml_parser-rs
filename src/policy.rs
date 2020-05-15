// Copyright 2020 David Young
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#![allow(dead_code)]


use super::Error;
use roxmltree::Node;
use std::str::FromStr;

#[derive(Debug)]
pub struct Policy {
    policy_name: String,
    policy_comments: String,
    server_preferences: ServerPreferences,
    plugins_preferences: PluginsPreferences,
    family_selection: FamilySelection,
}

impl Policy {
    pub fn from(policy_xml: Node) -> Result<Self, Error> {
        Err(Error::from("hi"))
    }
}

#[derive(Debug)]
pub struct ServerPreferences {}

pub type PluginsPreferences = Vec<PluginsPreferencesItem>;

#[derive(Debug)]
pub struct PluginItem {
    id: u32,
    name: String,
    family: PluginFamily,
    status: PluginStatus,
}

#[derive(Debug)]
pub struct PluginsPreferencesItem {
    plugin_name: String,
    id: u32,
    full_name: String,
    preference_name: String,
    preference_type: PreferenceType,
    values: String,
    selected_value: String,
}

#[derive(Debug, PartialEq)]
enum PreferenceType {
    Entry,
    Radio,
    Checkbox,
    File,
    Password,
}

impl FromStr for PreferenceType {
    type Err = Error;

    fn from_str(preference_type: &str) -> Result<Self, Self::Err> {
        use PreferenceType::*;
        match preference_type {
            "entry" => Ok(Entry),
            "radio" => Ok(Radio),
            "checkbox" => Ok(Checkbox),
            "file" => Ok(File),
            "password" => Ok(Password),
            other => {
                Err(Error::from(&format!("Invalid preference type: {}", other)))
            }
        }
    }
}

impl PluginsPreferencesItem {
    fn parse<'a>(node: &'a Node) -> Result<PluginsPreferencesItem, Error> {
        if node.tag_name().name() != "item" {
            Err(Error::from("No"))
        } else {
            let mut plugin_name: Option<&str> = None;
            let mut id: Option<u32> = None;
            let mut full_name: Option<&str> = None;
            let mut preference_name: Option<&str> = None;
            let mut preference_type: Option<PreferenceType> = None;
            let mut values: Option<&str> = None;
            let mut selected_value: Option<&str> = None;

            for child in node.children() {
                eprintln!("child: {:?}", child);
                match child.tag_name().name() {
                    "pluginName" => {
                        plugin_name = child.text();
                    }
                    "pluginId" => {
                        id = Some(
                            child
                                .text()
                                .ok_or_else(|| {
                                    Error::from("expected value for pluginId")
                                })
                                .and_then(|s| {
                                    s.parse::<u32>().or_else(|_| {
                                        Err(Error::from(
                                            "failed to parse pluginId",
                                        ))
                                    })
                                })?,
                        );
                    }
                    "fullName" => {
                        full_name = child.text();
                    }
                    "preferenceName" => {
                        preference_name = child.text();
                    }
                    "preferenceType" => {
                        preference_type = Some(
                            child
                                .text()
                                .ok_or_else(|| {
                                    Error::from("expected value for pluginId")
                                })
                                .and_then(|s| {
                                    s.parse::<PreferenceType>().or_else(|_| {
                                        Err(Error::from(
                                            "failed to parse pluginId",
                                        ))
                                    })
                                })?,
                        );
                    }
                    "preferenceValues" => {
                        values = child.text();
                    }
                    "selectedValue" => {
                        selected_value = child.text();
                    }
                    _ => {} // This captures Text from whitespace padding
                }
            }
            let plugin_name = plugin_name
                .ok_or_else(|| Error::from("expected plugin_name section"))?;
            let id = id.ok_or_else(|| Error::from("expected id section"))?;
            let full_name = full_name
                .ok_or_else(|| Error::from("expected full_name section"))?;
            let preference_name = preference_name.ok_or_else(|| {
                Error::from("expected preference_name section")
            })?;
            let preference_type = preference_type.ok_or_else(|| {
                Error::from("expected preference_type section")
            })?;
            let values =
                values.ok_or_else(|| Error::from("expected values section"))?;
            let selected_value = selected_value.ok_or_else(|| {
                Error::from("expected selected_value section")
            })?;

            Ok(PluginsPreferencesItem {
                plugin_name: plugin_name.to_string(),
                id,
                full_name: full_name.to_string(),
                preference_name: preference_name.to_string(),
                preference_type,
                values: values.to_string(),
                selected_value: selected_value.to_string(),
            })
        }
    }
}

#[derive(Debug)]
pub enum PluginStatus {
    Enabled,
    Disabled,
}

#[derive(Debug)]
pub enum PluginFamily {
    PortScanners,
}

pub type FamilySelection = Vec<FamilyItem>;

#[derive(Debug)]
pub struct FamilyItem {
    name: String,
    status: FamilyStatus,
}

#[derive(Debug)]
enum FamilyStatus {
    Enabled,
    Disabled,
    Partial,
}

#[cfg(test)]
mod test {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn plugin_item() {
        let xml = r#"
<item>
	<pluginName>Pingtheremotehost</pluginName>
	<pluginId>10180</pluginId>
	<fullName>Pingtheremotehost[entry]:TCPpingdestinationport(s):</fullName>
	<preferenceName>TCPpingdestinationport(s):</preferenceName>
	<preferenceType>entry</preferenceType>
	<preferenceValues>built-in</preferenceValues>
	<selectedValue>built-in</selectedValue>
</item>
		"#;
        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        eprintln!("ele: {:?}", ele);
        let item = PluginsPreferencesItem::parse(&ele).unwrap();

        assert_eq!(item.plugin_name, "Pingtheremotehost");
        assert_eq!(item.id, 10180);
        assert_eq!(
            item.full_name,
            "Pingtheremotehost[entry]:TCPpingdestinationport(s):"
        );
        assert_eq!(item.preference_name, "TCPpingdestinationport(s):");
        assert_eq!(item.preference_type, PreferenceType::Entry);
        assert_eq!(item.values, "built-in");
        assert_eq!(item.selected_value, "built-in");
    }
}
