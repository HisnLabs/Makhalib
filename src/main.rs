//! Makhalib CLI entrypoint. Subcommands (`plan`, `scan`, `list`) land in later
//! phases; for now it reports version and a one-line authorization reminder.

fn main() {
    println!("makhalib {} — authorized LLM red-teaming only", env!("CARGO_PKG_VERSION"));
}
