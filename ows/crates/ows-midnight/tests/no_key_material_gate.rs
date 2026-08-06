//! Milestone gate: ows-midnight holds NO key material.
//!
//! After the seed-free refactor, every ows-midnight entry point takes a `&MidnightCryptoProvider`
//! (built once in ows-lib, which owns the credential) rather than a raw `&SecretBytes`. All
//! key/seed derivation lives in ows-signer's `MidnightCryptoProvider`; ows-midnight only ever
//! borrows the already-built provider and receives public outputs.
//!
//! This test fails if any credential/key-derivation marker reappears in ows-midnight's *production*
//! source (`src`, outside `#[cfg(test)]` blocks). It is a regression tripwire, not a proof — but a
//! reintroduced `SecretBytes` param or a seed-decoding helper will trip it.
//!
//! Implementation invariant: the `#[cfg(test)]`-stripping brace-counts from each attribute to
//! end-of-file, so it relies on every test module being the file's last top-level item (all
//! currently are). If a file ever places production code after a test module, revisit this.
//!
//! Scope note on `[u8; 32]`: it is deliberately **not** a gate marker. Production ows-midnight has
//! legitimate non-secret 32-byte arrays — a `TokenType::Custom([u8; 32])` token id and a decoded
//! bech32m address payload (`UserAddress`), both public. The gate targets key/credential markers,
//! not every 32-byte buffer; a secret would arrive as `SecretBytes` (which IS gated), never as a
//! bare array.

use std::fs;
use std::path::{Path, PathBuf};

/// Key/credential markers that must not appear in ows-midnight production code. Each names either a
/// raw credential type (`SecretBytes`), a seed/key-decoding helper (`decode_keys`,
/// `derive_secret_key`, `zswap_secret_keys_from_seed`, `shielded_keys_for`), or a secret-bearing key
/// type (`MidnightRoleSeeds`, `ZswapSecretKeys`, `DustSecretKey`). All of these now live only in
/// ows-signer.
const FORBIDDEN_MARKERS: &[&str] = &[
    "SecretBytes",
    "decode_keys",
    "derive_secret_key",
    "zswap_secret_keys_from_seed",
    "MidnightRoleSeeds",
    "ZswapSecretKeys",
    "DustSecretKey",
    "shielded_keys_for",
];

/// Recursively collect every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Strip every `#[cfg(test)]`-gated item (module or fn) from `source`, returning only the production
/// lines paired with their 1-based line numbers. When a `#[cfg(test)]` attribute is seen, the
/// following braced item is skipped in its entirety by brace counting — so inline `mod tests { … }`
/// and any `#[cfg(test)] fn …` are excluded, along with everything they contain.
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut lines = source.lines().enumerate().peekable();

    while let Some((idx, line)) = lines.next() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            // Consume up to and including the first `{`, then balance braces to the matching `}`.
            let mut depth: i32 = 0;
            let mut opened = false;
            // The attribute line itself carries no brace; scan forward from the next line.
            for (_, item_line) in lines.by_ref() {
                for ch in item_line.chars() {
                    match ch {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if opened && depth <= 0 {
                    break;
                }
            }
            continue;
        }
        out.push((idx + 1, line));
    }
    out
}

/// Drop the `//`-comment tail of a line, respecting neither strings nor block comments — a marker in
/// a `//` doc/line comment is not code, so it must not trip the gate. (Block comments `/* … */` are
/// not used to hold these markers in this crate; if that changes, extend this.)
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

#[test]
fn ows_midnight_production_holds_no_key_material() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(!files.is_empty(), "found no source files under {src:?}");

    let mut violations: Vec<String> = Vec::new();

    for file in &files {
        let source = fs::read_to_string(file).expect("read source file");
        for (lineno, line) in production_lines(&source) {
            let code = strip_line_comment(line);
            for marker in FORBIDDEN_MARKERS {
                if code.contains(marker) {
                    violations.push(format!(
                        "{}:{lineno}: forbidden key-material marker `{marker}` in production code:\n    {}",
                        file.display(),
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "ows-midnight production code must hold no key material — the crypto provider is built in \
         ows-lib and only `&MidnightCryptoProvider` crosses into ows-midnight. Found:\n{}",
        violations.join("\n")
    );
}
