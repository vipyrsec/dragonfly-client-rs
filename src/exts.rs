use yara::{MetadataValue, Rule};

use crate::scanner::RuleScore;

pub trait RuleExt<'a> {
    /// Get the value of a metadata by key. `None` if that key/value pair doesn't exist
    fn get_metadata_value(&'a self, key: &str) -> Option<&'a MetadataValue>;

    /// Get the weight of this rule. `0` if no weight is defined.
    fn get_rule_weight(&'a self) -> i64;

    /// Get a vector over the `filetype` metadata value. An empty Vec if not defined.
    fn get_filetypes(&'a self) -> Vec<&'a str>;
}

impl RuleExt<'_> for Rule<'_> {
    fn get_metadata_value(&self, key: &str) -> Option<&'_ MetadataValue> {
        self.metadatas
            .iter()
            .find(|metadata| metadata.identifier == key)
            .map(|metadata| &metadata.value)
    }

    fn get_filetypes(&'_ self) -> Vec<&'_ str> {
        if let Some(MetadataValue::String(string)) = self.get_metadata_value("filetype") {
            string.split(' ').collect()
        } else {
            Vec::new()
        }
    }

    fn get_rule_weight(&self) -> i64 {
        if let Some(MetadataValue::Integer(integer)) = self.get_metadata_value("weight") {
            *integer
        } else {
            0
        }
    }
}

impl From<Rule<'_>> for RuleScore {
    fn from(rule: Rule) -> Self {
        Self {
            name: rule.identifier.to_owned(),
            score: rule.get_rule_weight(),
        }
    }
}
