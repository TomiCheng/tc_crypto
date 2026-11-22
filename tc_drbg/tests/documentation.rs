//! Every function outside the tests states whether it is constant or variable
//! time, as the timing contract of the crate requires.

/// Each function's doc comment, collected across attributes, must name exactly
/// one of the two timing classes.
fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut count = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        if line == "mod tests {" {
            break;
        }
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment.trim());
            docs.push(' ');
            continue;
        }
        if line.starts_with("#[") || line.is_empty() || line.starts_with("//") {
            continue;
        }
        let declaration = [
            "pub fn ",
            "pub(crate) fn ",
            "fn ",
            "pub const fn ",
            "pub(crate) const fn ",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix));
        if declaration {
            count += 1;
            let docs = docs.to_ascii_lowercase();
            if docs.contains("constant time") == docs.contains("variable time") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (count, missing)
}

#[test]
fn every_function_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        ("ctr_drbg.rs", include_str!("../src/ctr_drbg.rs"), 12),
        ("derivation.rs", include_str!("../src/derivation.rs"), 9),
        ("drbg.rs", include_str!("../src/drbg.rs"), 8),
        ("errors.rs", include_str!("../src/errors.rs"), 1),
        ("hash_drbg.rs", include_str!("../src/hash_drbg.rs"), 11),
        ("hmac_drbg.rs", include_str!("../src/hmac_drbg.rs"), 11),
        ("traits.rs", include_str!("../src/traits.rs"), 2),
    ] {
        let (count, missing) = missing_timing_docs(source);
        assert!(count >= minimum, "only {count} functions scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
