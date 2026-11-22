const METHODS: [&str; 17] = [
    "new",
    "reset_state",
    "allocate",
    "buffers",
    "block_size",
    "update_output_len",
    "output_len",
    "process_bytes",
    "do_final",
    "reset",
    "init",
    "process_mode",
    "ecb",
    "cbc",
    "fmt",
    "update_output_len",
    "output_len",
];

fn checked(line: &str) -> bool {
    if line.starts_with("pub fn ") || line.starts_with("pub(crate) fn ") {
        return true;
    }
    line.strip_prefix("fn ")
        .and_then(|rest| rest.split(['(', '<']).next())
        .is_some_and(|name| METHODS.contains(&name))
}

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut count = 0;
    let mut missing = Vec::new();
    let mut in_tests = false;
    for line in source.lines().map(str::trim) {
        if line == "mod tests {" {
            in_tests = true;
        }
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment.trim());
            docs.push(' ');
            continue;
        }
        if line.starts_with("#[") || attribute_depth > 0 {
            attribute_depth += line.chars().filter(|&c| c == '[').count() as i32;
            attribute_depth -= line.chars().filter(|&c| c == ']').count() as i32;
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if !in_tests && checked(line) {
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
fn every_public_method_and_helper_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        (
            "fixed_cts_block_cipher.rs",
            include_str!("../src/fixed_cts_block_cipher.rs"),
            14,
        ),
        (
            "cts_block_cipher.rs",
            include_str!("../src/cts_block_cipher.rs"),
            14,
        ),
        ("shared.rs", include_str!("../src/shared.rs"), 5),
    ] {
        let (count, missing) = missing_timing_docs(source);
        assert!(count >= minimum, "only {count} methods scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
