use yara::{MetadataValue, Rule};

pub trait RuleExt<'a> {
    /// Get the value of a metadata by key. `None` if that key/value pair doesn't exist
    fn get_metadata_value(&'a self, key: &str) -> Option<&'a MetadataValue>;

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
}
