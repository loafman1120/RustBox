//! Leaf-level configuration validation.
//!
//! Cross-reference and runtime capability checks intentionally remain in
//! `rustbox-config`; this module only owns constraints local to one document
//! value.

use rustbox_observability::LevelFilter;

pub(crate) fn observability_level(value: &Option<String>, _: &()) -> garde::Result {
    let Some(value) = value.as_deref() else {
        return Ok(());
    };
    LevelFilter::parse(value).map(|_| ()).ok_or_else(|| {
        garde::Error::new(
            "invalid observability level; expected trace, debug, info, warn, error, or off",
        )
    })
}
