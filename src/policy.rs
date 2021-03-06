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

/// The policy used for the scan
#[derive(Debug, Default)]
pub struct Policy {
    /// Name of the policy
    pub policy_name: String,
    /// Any comments saved with the policy, may be empty
    pub policy_comments: String,
    /// A [`ServerPreferences`] item, which is a Vec of key-value pairs
    pub server_preferences: ServerPreferences,
    /// A [`PluginsPreferences`] item, which is a Vec of
    /// [`PluginsPreferencesItem`]s
    pub plugins_preferences: PluginsPreferences,
    /// A list of selected plugin families, as a Vec of [`FamilyItem`]s
    pub family_selection: FamilySelection,
    /// A list of individually-selected plugins, as a Vec of [`PluginItem`]s
    pub individual_plugin_selection: IndividualPluginSelection,
}

impl Policy {
    /// Build a Policy from an XML node
    pub fn from(policy_xml: Node) -> Result<Self, Error> {
        let mut policy: Self = Default::default();
        for child in policy_xml.children() {
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
                "IndividualPluginSelection" => {
                    policy.individual_plugin_selection =
                        IndividualPluginSelection::parse(&child)?
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

/// Preferences struct, holding the ['ServerPreferences`] and
/// [`PluginsPreferences`] for a scan run
#[derive(Debug, Default)]
pub struct Preferences {
    server_preferences: ServerPreferences,
    plugins_preferences: PluginsPreferences,
}

impl Preferences {
    /// Build a Preferences object from an XML node
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

/// Holds a Vec of [`ServerPreference`] key-value pairs
#[derive(Debug, PartialEq, Default)]
pub struct ServerPreferences(Vec<ServerPreference>);

impl ServerPreferences {
    /// Build a ServerPreferences item from an XML node
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

/// Key-value pair for [`ServerPreferences`]
#[derive(Debug, PartialEq, Default)]
pub struct ServerPreference {
    name: String,
    value: String,
}

impl ServerPreference {
    /// Build a ServerPreference object from an XML node
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
                    .unwrap_or("");

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

/// Holds a Vec of [`PluginsPreferencesItem`]s
#[derive(Debug, Default, PartialEq)]
pub struct PluginsPreferences(Vec<PluginsPreferencesItem>);

impl PluginsPreferences {
    /// Builds a PluginsPreferences object from an XML node
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

/// Holds metadata about a particular plugin
#[derive(Debug, PartialEq)]
pub struct PluginItem {
    id: u32,
    name: String,
    family: String,
    status: PluginStatus,
}

impl PluginItem {
    /// Builds a PluginItem object from an XML node
    fn parse(node: &Node) -> Result<Self, Error> {
        let mut id = 0_u32;
        let mut name = String::new();
        let mut family = String::new();
        let mut status: Option<PluginStatus> = None;

        for child in node.children() {
            match child.tag_name().name() {
                "PluginId" => {
                    id = child
                        .text()
                        .ok_or_else(|| {
                            Error::from("expected value for id in PluginItem")
                        })
                        .and_then(|s| {
                            s.parse::<u32>()
                                .map_err(|_| Error::from("failed to parse id"))
                        })?
                }
                "PluginName" => {
                    name = child
                        .text()
                        .ok_or_else(|| {
                            Error::from("Expected value for PluginItem name")
                        })?
                        .to_string()
                }
                "Family" => {
                    family = child
                        .text()
                        .ok_or_else(|| {
                            Error::from("Expected value for PluginItem family")
                        })?
                        .to_string()
                }
                "Status" => status = Some(PluginStatus::parse(&child)?),
                _ => {}
            }
        }

        let status =
            status.ok_or_else(|| Error::from("Missing PluginStatus"))?;

        Ok(Self {
            id,
            name,
            family,
            status,
        })
    }
}

/// Holds a Vec of [`PluginItem`]s to specify which plugins are selected
#[derive(Debug, Default, PartialEq)]
pub struct IndividualPluginSelection(Vec<PluginItem>);

impl IndividualPluginSelection {
    /// Builds an IndividualPluginSelection object from an XML node
    fn parse(node: &Node) -> Result<Self, Error> {
        let mut items = Vec::new();
        for child in node.children() {
            if child.tag_name().name() == "PluginItem" {
                items.push(PluginItem::parse(&child)?)
            }
        }
        Ok(Self(items))
    }
}

/// Stores the value of a plugin preference
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

/// The possible data types for a preference entry
#[derive(Debug, PartialEq)]
pub enum PreferenceType {
    /// Preference is a regular text entry
    Entry,
    /// Preference came from a radio button
    Radio,
    /// Preference came from a checkbox
    Checkbox,
    /// Preference came from a file
    File,
    /// Preference is a password
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
    /// Builds a PluginsPreferencesItem from an XML node
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
                let values = values.unwrap_or("");
                let selected_value = selected_value.unwrap_or("");

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

/// Possible status values for a plugin
#[derive(Debug, PartialEq)]
pub enum PluginStatus {
    /// Plugin is enabled
    Enabled,
    /// Plugin is disabled
    Disabled,
}

impl PluginStatus {
    /// Builds a PluginStatus object from an XML node
    fn parse(node: &Node) -> Result<Self, Error> {
        use PluginStatus::*;
        let status = node
            .text()
            .ok_or_else(|| Error::from("Expected value for PluginStatus"))?;
        match status {
            "enabled" => Ok(Enabled),
            "disabled" => Ok(Disabled),
            other => {
                Err(Error::from(&format!("Invalid plugin status: {}", other)))
            }
        }
    }
}

/// Holds a Vec of [`FamilyItem`]s to record which plugin families are
/// selected
#[derive(Debug, PartialEq, Default)]
pub struct FamilySelection(Vec<FamilyItem>);

impl FamilySelection {
    /// Builds a FamilySelection object from an XML node
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

/// Holds the name and status information about a plugin family
#[derive(Debug, PartialEq)]
pub struct FamilyItem {
    name: String,
    status: FamilyStatus,
}

impl FamilyItem {
    /// Builds a FamilyItem object from an XML node
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
                                    Error::from(&format!(
                                        "failed to parse FamilyItem status: {}",
                                        s
                                    ))
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

/// The possible statuses for a plugin family
#[derive(Debug, PartialEq)]
enum FamilyStatus {
    Enabled,
    Disabled,
    Partial,
    Mixed,
}

impl FromStr for FamilyStatus {
    type Err = Error;

    fn from_str(family_status: &str) -> Result<Self, Self::Err> {
        use FamilyStatus::*;
        match family_status {
            "enabled" => Ok(Enabled),
            "disabled" => Ok(Disabled),
            "partial" => Ok(Partial),
            "mixed" => Ok(Mixed),
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
        <preference>
            <name>scan_description</name>
            <value></value>
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
            ServerPreference {
                name: "scan_description".to_string(),
                value: "".to_string(),
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
    fn policy_section() {
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

    #[test]
    fn full_policy_section() {
        let xml = r#"
<Policy>
    <policyName>MyExamplePolicy</policyName>
    <policyComments>Thisisanexamplepolicy</policyComments>
    <Preferences>
        <ServerPreferences>
            <preference>
                <name>max_hosts</name>
                <value>30</value>
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
        "#;

        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let p = Policy::from(ele).unwrap();

        assert_eq!(p.policy_name, "MyExamplePolicy");
        assert_eq!(p.policy_comments, "Thisisanexamplepolicy");
        assert_eq!(
            p.server_preferences,
            ServerPreferences(vec![ServerPreference {
                name: "max_hosts".to_string(),
                value: "30".to_string()
            }])
        );
        assert_eq!(
            p.plugins_preferences,
            PluginsPreferences(vec![PluginsPreferencesItem {
                plugin_name: "WebApplicationTestsSettings".to_string(),
                id: 39471,
                full_name: "WebApplicationTestsSettings[checkbox]:Enablewebapplic-ationstests"
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
                name: "WebServers".to_string(),
                status: FamilyStatus::Disabled
            }])
        );
        assert_eq!(
            p.individual_plugin_selection,
            IndividualPluginSelection(vec![PluginItem {
                id: 34220,
                name: "netstatportscanner(WMI)".to_string(),
                family: "Portscanners".to_string(),
                status: PluginStatus::Enabled
            }])
        )
    }
}
