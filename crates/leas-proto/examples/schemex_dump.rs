//! Dump the schema/chunk split of an input file via `SchemeX::slice_input`.
//!
//! Usage: `cargo run -p leas-proto --example schemex_dump -- <path>`

fn main() {
    let path = std::env::args().nth(1).expect("usage: schemex_dump <path>");

    let input =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));

    let chunks = leas_proto::SchemeX::slice_input(&input);
    for (schema, c) in &chunks {
        let c = c.lines().collect::<Vec<_>>().join("");
        eprintln!("{schema:>15}| {c}");
    }
    eprintln!("Total: {}", chunks.len());
}
