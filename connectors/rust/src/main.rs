use mimwell_connector_sdk::{plan, validate_jsonl, HostClient, MAX_EXPORT};
use serde_json::json;
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    process,
    time::Duration,
};

fn get(args: &[String], key: &str) -> Result<String, String> {
    args.windows(2)
        .find(|pair| pair[0] == key)
        .map(|pair| pair[1].clone())
        .ok_or_else(|| format!("missing operator option {key}"))
}
fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let command = args
        .get(1)
        .ok_or("command required: validate, plan, submit, resume, status, replay")?;
    let stdin = args.iter().any(|arg| arg == "--stdin");
    if stdin && command != "submit" && command != "resume" {
        return Err("--stdin requires submit or resume".into());
    }
    if command == "validate" || command == "plan" {
        let path = get(&args, "--file")?;
        let mut raw = Vec::new();
        File::open(path)
            .map_err(|e| e.to_string())?
            .take((MAX_EXPORT + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        let result = if command == "validate" {
            let rows = validate_jsonl(&raw)?;
            json!({"format":"connector-client-validation/v1","events":rows.len(),"valid":true})
        } else {
            plan(&raw)?
        };
        return io::stdout()
            .write_all(
                serde_json::to_vec(&result)
                    .map_err(|e| e.to_string())?
                    .as_slice(),
            )
            .and_then(|_| io::stdout().write_all(b"\n"))
            .map_err(|e| e.to_string());
    }
    let client = HostClient {
        python: get(&args, "--python")?,
        host_script: get(&args, "--host-script")?,
        root: get(&args, "--root")?,
        host_config: get(&args, "--host-config")?,
        authority: get(&args, "--authority")?,
        namespace: args
            .windows(2)
            .find(|pair| pair[0] == "--namespace")
            .map(|pair| pair[1].clone())
            .unwrap_or_default(),
        export: args
            .windows(2)
            .find(|pair| pair[0] == "--export")
            .map(|pair| pair[1].clone())
            .unwrap_or_default(),
        timeout: {
            let ms = args
                .windows(2)
                .find(|pair| pair[0] == "--timeout-ms")
                .map(|pair| pair[1].parse::<u64>())
                .transpose()
                .map_err(|_| "invalid timeout")?
                .unwrap_or(10000);
            if ms == 0 || ms > 300000 {
                return Err("timeout must be between 1 and 300000 ms".into());
            }
            Duration::from_millis(ms)
        },
    };
    let receipt = match command.as_str() {
        "submit" | "resume" if stdin => client.submit_stdin(),
        "submit" | "resume" => client.resume(),
        "status" => client.status(),
        "replay" => client.replay(
            get(&args, "--line")?
                .parse()
                .map_err(|_| "invalid replay line")?,
        ),
        _ => Err("unknown command".into()),
    }?;
    io::stdout().write_all(&receipt).map_err(|e| e.to_string())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("connector-sdk: {error}");
        process::exit(2);
    }
}
