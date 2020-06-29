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

#[derive(Debug, Default)]
pub struct Policy {
    policy_name: String,
    policy_comments: String,
    server_preferences: ServerPreferences,
    plugins_preferences: PluginsPreferences,
    family_selection: FamilySelection,
}

impl Policy {
    pub fn from(policy_xml: Node) -> Result<Self, Error> {
        let mut policy: Self = Default::default();
        for child in policy_xml.children() {
            eprintln!("child: {}", child.tag_name().name());
            match child.tag_name().name() {
                "policyName" => {
                    policy.policy_name = child
                        .text()
                        .ok_or_else(|| {
                            Error::from("expected value for policyName")
                        })?
                        .to_string()
                }
                "policyComments" => {
                    policy.policy_comments = child
                        .text()
                        .ok_or_else(|| {
                            Error::from("expected value for policyComments")
                        })?
                        .to_string()
                }
                "Preferences" => {
                    let preferences = Preferences::parse(&child)?;
                    policy.server_preferences = preferences.server_preferences;
                    policy.plugins_preferences =
                        preferences.plugins_preferences;
                }
                "FamilySelection" => {
                    policy.family_selection = FamilySelection::parse(&child)?
                }
                "" => {}
                other => {
                    return Err(Error::from(&format!(
                        "Invalid XML tag: {}",
                        other
                    )))
                }
            }
        }

        Ok(policy)
    }
}

#[derive(Debug, Default)]
pub struct Preferences {
    server_preferences: ServerPreferences,
    plugins_preferences: PluginsPreferences,
}

impl Preferences {
    fn parse(node: &Node) -> Result<Self, Error> {
        let mut server_preferences = Default::default();
        let mut plugins_preferences = Default::default();

        for child in node.children() {
            match child.tag_name().name() {
                "ServerPreferences" => {
                    server_preferences = ServerPreferences::parse(&child)?;
                }
                "PluginsPreferences" => {
                    plugins_preferences = PluginsPreferences::parse(&child)?;
                }
                "" => {}
                other => {
                    return Err(Error::from(&format!(
                        "Invalid preferences tag: {}",
                        other
                    )))
                }
            }
        }

        Ok(Self {
            server_preferences,
            plugins_preferences,
        })
    }
}

#[derive(Debug, PartialEq, Default)]
pub struct ServerPreferences(Vec<ServerPreference>);

impl ServerPreferences {
    fn parse(node: &Node) -> Result<ServerPreferences, Error> {
        match node.tag_name().name() {
            "ServerPreferences" => {
                let mut prefs = Vec::new();
                for child in node.children() {
                    if child.tag_name().name() == "preference" {
                        // the only type of child for ServerPreferences
                        // is preference
                        prefs.push(ServerPreference::parse(&child)?);
                    }
                }

                Ok(Self(prefs))
            }
            other => Err(Error::from(&format!(
                "Invalid tag name `{}` for server preferences",
                other
            ))),
        }
    }
}

#[derive(Debug, PartialEq, Default)]
pub struct ServerPreference {
    name: String,
    value: String,
}

impl ServerPreference {
    fn parse(node: &Node) -> Result<ServerPreference, Error> {
        match node.tag_name().name() {
            "preference" => {
                let mut name: Option<&str> = None;
                let mut value: Option<&str> = None;

                for child in node.children() {
                    match child.tag_name().name() {
                        "name" => {
                            name = child.text();
                        }
                        "value" => {
                            value = child.text();
                        }
                        _ => {}
                    }
                }

                let name =
                    name.ok_or_else(|| Error::from("expected name section"))?;
                let value = value
                    .ok_or_else(|| Error::from("expected value section"))?;

                Ok(ServerPreference {
                    name: name.to_string(),
                    value: value.to_string(),
                })
            }
            other => Err(Error::from(&format!(
                "Invalid tag name `{}` for server preferences",
                other
            ))),
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct PluginsPreferences(Vec<PluginsPreferencesItem>);

impl PluginsPreferences {
    fn parse(node: &Node) -> Result<Self, Error> {
        let mut prefs = Vec::new();
        for child in node.children() {
            if child.tag_name().name() == "item" {
                // the only type of child for ServerPreferences
                // is preference
                prefs.push(PluginsPreferencesItem::parse(&child)?);
            }
        }

        Ok(Self(prefs))
    }
}

#[derive(Debug)]
pub struct PluginItem {
    id: u32,
    name: String,
    family: PluginFamily,
    status: PluginStatus,
}

#[derive(Debug, PartialEq)]
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
    fn parse(node: &Node) -> Result<PluginsPreferencesItem, Error> {
        match node.tag_name().name() {
            "item" => {
                let mut plugin_name: Option<&str> = None;
                let mut id: Option<u32> = None;
                let mut full_name: Option<&str> = None;
                let mut preference_name: Option<&str> = None;
                let mut preference_type: Option<PreferenceType> = None;
                let mut values: Option<&str> = None;
                let mut selected_value: Option<&str> = None;

                for child in node.children() {
                    match child.tag_name().name() {
                        "pluginName" => {
                            plugin_name = child.text();
                        }
                        "pluginId" => {
                            id = Some(
                                child
                                    .text()
                                    .ok_or_else(|| {
                                        Error::from(
                                            "expected value for pluginId",
                                        )
                                    })
                                    .and_then(|s| {
                                        s.parse::<u32>().map_err(|_| {
                                            Error::from(
                                                "failed to parse pluginId",
                                            )
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
                                        Error::from(
                                            "expected value for pluginId",
                                        )
                                    })
                                    .and_then(|s| {
                                        s.parse::<PreferenceType>().map_err(
                                            |_| {
                                                Error::from(
                                                    "failed to parse pluginId",
                                                )
                                            },
                                        )
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
                let plugin_name = plugin_name.ok_or_else(|| {
                    Error::from("expected plugin_name section")
                })?;
                let id =
                    id.ok_or_else(|| Error::from("expected id section"))?;
                let full_name = full_name
                    .ok_or_else(|| Error::from("expected full_name section"))?;
                let preference_name = preference_name.ok_or_else(|| {
                    Error::from("expected preference_name section")
                })?;
                let preference_type = preference_type.ok_or_else(|| {
                    Error::from("expected preference_type section")
                })?;
                let values = values
                    .ok_or_else(|| Error::from("expected values section"))?;
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
            other => Err(Error::from(&format!(
                "Invalid tag name `{}` for plugin preferences",
                other
            ))),
        }
    }
}

#[derive(Debug)]
pub enum PluginStatus {
    Enabled,
    Disabled,
}

#[derive(Debug, PartialEq)]
pub enum PluginFamily {
    PortScanners,
}

impl FromStr for PluginFamily {
    type Err = Error;

    fn from_str(family: &str) -> Result<Self, Self::Err> {
        use PluginFamily::*;
        match family {
            "portscanners" => Ok(PortScanners),
            other => {
                Err(Error::from(&format!("Invalid plugin family: {}", other)))
            }
        }
    }
}

#[derive(Debug, PartialEq, Default)]
pub struct FamilySelection(Vec<FamilyItem>);

impl FamilySelection {
    fn parse(node: &Node) -> Result<FamilySelection, Error> {
        let mut family = Vec::new();
        for child in node.children() {
            if child.tag_name().name() == "FamilyItem" {
                family.push(FamilyItem::parse(&child)?);
            }
        }

        Ok(FamilySelection(family))
    }
}

#[derive(Debug, PartialEq)]
pub struct FamilyItem {
    name: String,
    status: FamilyStatus,
}

impl FamilyItem {
    fn parse(node: &Node) -> Result<FamilyItem, Error> {
        let mut name: Option<&str> = None;
        let mut status: Option<FamilyStatus> = None;

        for child in node.children() {
            match child.tag_name().name() {
                "FamilyName" => {
                    name = child.text();
                }
                "Status" => {
                    status = Some(
                        child
                            .text()
                            .ok_or_else(|| {
                                Error::from("expected value for status")
                            })
                            .and_then(|s| {
                                s.parse::<FamilyStatus>().map_err(|_| {
                                    Error::from(
                                        "failed to parse FamilyItem status",
                                    )
                                })
                            })?,
                    );
                }
                _ => {}
            }
        }

        let name =
            name.ok_or_else(|| Error::from("expected family name section"))?;
        let status = status
            .ok_or_else(|| Error::from("expected family status section"))?;
        Ok(FamilyItem {
            name: name.to_string(),
            status,
        })
    }
}

#[derive(Debug, PartialEq)]
enum FamilyStatus {
    Enabled,
    Disabled,
    Partial,
}

impl FromStr for FamilyStatus {
    type Err = Error;

    fn from_str(family_status: &str) -> Result<Self, Self::Err> {
        use FamilyStatus::*;
        match family_status {
            "enabled" => Ok(Enabled),
            "disabled" => Ok(Disabled),
            "partial" => Ok(Partial),
            other => {
                Err(Error::from(&format!("Invalid family status: {}", other)))
            }
        }
    }
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

    #[test]
    fn server_preferences() {
        let xml = r#"
<ServerPreferences>
	<preference>
		<name>max_hosts</name>
		<value>10</value>
	</preference>
	<preference>
		<name>max_checks</name>
		<value>3</value>
	</preference>
</ServerPreferences>
"#;
        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        eprintln!("ele: {:?}", ele);
        let server_prefs = ServerPreferences::parse(&ele).unwrap();

        let correct = ServerPreferences(vec![
            ServerPreference {
                name: "max_hosts".to_string(),
                value: "10".to_string(),
            },
            ServerPreference {
                name: "max_checks".to_string(),
                value: "3".to_string(),
            },
        ]);

        assert_eq!(server_prefs, correct);
    }

    #[test]
    fn family_item() {
        let xml = r#"
<FamilySelection>
	<FamilyItem>
		<FamilyName>FTP</FamilyName>
		<Status>enabled</Status>
	</FamilyItem>
</FamilySelection>
    	"#;
        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        eprintln!("ele: {:?}", ele);
        let family = FamilySelection::parse(&ele).unwrap();

        let correct = FamilySelection(vec![FamilyItem {
            name: "FTP".to_string(),
            status: FamilyStatus::Enabled,
        }]);

        assert_eq!(family, correct);
    }

    #[test]
    fn full_policy_section() {
        let xml = r#"
<Policy>
    <policyName>MyName</policyName>
    <policyComments>MyComment</policyComments>
    <Preferences>
        <ServerPreferences>
            <preference>
                <name>max_simult_tcp_sessions</name>
                <value>unlimited</value>
            </preference>
        </ServerPreferences>
        <PluginsPreferences>
            <item>
                <pluginName>WebApplicationTestsSettings</pluginName>
                <pluginId>39471</pluginId>
                <fullName>WebApplicationTestsSettings[checkbox]:Enablewebapplicationstests</fullName>
                <preferenceName>Enablewebapplicationstests</preferenceName>
                <preferenceType>checkbox</preferenceType>
                <preferenceValues>no</preferenceValues>
                <selectedValue>no</selectedValue>
            </item>
        </PluginsPreferences>
    </Preferences>
    <FamilySelection>
        <FamilyItem>
            <FamilyName>MacOSXLocalSecurityChecks</FamilyName>
            <Status>disabled</Status>
        </FamilyItem>
    </FamilySelection>
</Policy>
        "#;

        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let p = Policy::from(ele).unwrap();

        assert_eq!(p.policy_name, "MyName");
        assert_eq!(p.policy_comments, "MyComment");
        assert_eq!(
            p.server_preferences,
            ServerPreferences(vec![ServerPreference {
                name: "max_simult_tcp_sessions".to_string(),
                value: "unlimited".to_string(),
            }])
        );
        assert_eq!(
            p.plugins_preferences,
            PluginsPreferences(vec![PluginsPreferencesItem {
                plugin_name: "WebApplicationTestsSettings".to_string(),
                id: 39471,
                full_name: "WebApplicationTestsSettings[checkbox]:Enablewebapplicationstests"
                    .to_string(),
                preference_name: "Enablewebapplicationstests".to_string(),
                preference_type: PreferenceType::Checkbox,
                values: "no".to_string(),
                selected_value: "no".to_string()
            }])
        );
        assert_eq!(
            p.family_selection,
            FamilySelection(vec![FamilyItem {
                name: "MacOSXLocalSecurityChecks".to_string(),
                status: FamilyStatus::Disabled
            }])
        );
    }
}
