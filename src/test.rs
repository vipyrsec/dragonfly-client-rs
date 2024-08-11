//! # test
//! Holds utility functions that are beneficial for testing

use crate::client::{FileScanResult, MetadataValue, RuleMatch};
use std::collections::HashMap;

/// Constructs a [`FileScanResult`] for testing
///
/// Each [`RuleMatch`] is created with an empty vec of patterns.
/// # Examples
/// ```rs
/// let fsr = make_file_scan_result("~/rem.tar.gz", &[("rule_1", 100), ("rule_2", 4)]);
/// assert_eq!(104, fsr.calculate_score())
/// ```
pub(crate) fn make_file_scan_result(path: &str, id_weight: &[(&str, i64)]) -> FileScanResult {
    let mut rule_matches = Vec::with_capacity(id_weight.len());

    for &(id, weight) in id_weight {
        let metadata = vec![("weight".into(), MetadataValue::Integer(weight))]
            .into_iter()
            .collect::<HashMap<String, MetadataValue>>();
        rule_matches.push(RuleMatch {
            identifier: id.to_string(),
            patterns: Vec::new(),
            metadata,
        });
    }

    FileScanResult {
        path: path.into(),
        matches: rule_matches,
    }
}
