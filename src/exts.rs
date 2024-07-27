use yara_x::{MetaValue, Rule};

use crate::scanner::RuleScore;

pub trait RuleExt<'a> {
    /// Get the value of a metadata by key. `None` if that key/value pair doesn't exist
    fn get_metadata_value(&'a self, key: &str) -> Option<MetaValue>;

    /// Get the weight of this rule. `0` if no weight is defined.
    fn get_rule_weight(&'a self) -> i64 {
        if let Some(MetaValue::Integer(integer)) = self.get_metadata_value("weight") {
            integer
        } else {
            0
        }
    }

    /// Get a vector over the `filetype` metadata value. An empty Vec if not defined.
    fn get_filetypes(&'a self) -> Vec<&'a str> {
        if let Some(MetaValue::String(string)) = self.get_metadata_value("filetype") {
            string.split(' ').collect()
        } else {
            Vec::new()
        }
    }
}

impl<'a, 'r> RuleExt<'_> for yara_x::Rule<'a, 'r> {
    fn get_metadata_value(&self, key: &str) -> Option<MetaValue> {
        self.metadata()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    }
}

impl<'a, 'r> From<Rule<'a, 'r>> for RuleScore {
    fn from(rule: Rule) -> Self {
        Self {
            name: rule.identifier().to_owned(),
            score: rule.get_rule_weight(),
        }
    }
}
