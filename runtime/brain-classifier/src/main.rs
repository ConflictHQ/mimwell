//! Compatibility command over the same embeddable classifier implementation.
use brain_classifier::{INPUT_CAP, Result, classify_json, read_cap};
use std::{
    io::{self, Write},
    path::Path,
};

fn main() {
    // Only this standalone command owns its process-wide panic hook. A library
    // must not replace its embedding application's hook.
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| -> Result<()> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() != 3 {
            return Err("usage: brain-classifier CANONICAL_BUNDLE_PATH SHA256");
        }
        let raw = read_cap(io::stdin().lock(), INPUT_CAP)?;
        let mut output = classify_json(Path::new(&args[1]), &args[2], &raw)?;
        output.push(b'\n');
        io::stdout()
            .lock()
            .write_all(&output)
            .map_err(|_| "output-write-failed")
    })
    .unwrap_or(Err("model-execution-failed"));
    if let Err(category) = result {
        eprintln!("brain-classifier: {category}");
        std::process::exit(1);
    }
}
