use base64::{engine::general_purpose::STANDARD, Engine};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_LINE: usize = 1_048_576;
pub const MAX_EXPORT: usize = 16 * 1024 * 1024;
pub const MAX_RECEIPT: usize = 1024 * 1024;
pub const HOST_TIMEOUT: Duration = Duration::from_secs(10);

struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(
                    serde_json::Number::from_f64(v)
                        .ok_or_else(|| E::custom("non-finite number"))?,
                )))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                UniqueValue::deserialize(d)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                let mut keys = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key {key}"
                        )));
                    }
                    let UniqueValue(v) = map.next_value()?;
                    values.insert(key, v);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn bounded(value: &str, maximum: usize, nonempty: bool) -> bool {
    value.chars().count() <= maximum && (!nonempty || !value.trim().is_empty())
}
fn optional_string(value: &Value, key: &str, maximum: usize) -> Result<(), String> {
    match &value[key] {
        Value::Null => Ok(()),
        Value::String(s) if bounded(s, maximum, false) => Ok(()),
        _ => Err("invalid optional event metadata".into()),
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub value: Value,
    pub bytes: Vec<u8>,
    pub payload: Vec<u8>,
}

pub fn validate_jsonl(raw: &[u8]) -> Result<Vec<Event>, String> {
    if raw.len() > MAX_EXPORT {
        return Err("export exceeds the 16 MiB client bound".into());
    }
    let mut events = Vec::new();
    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        if line.len() > MAX_LINE || !line.ends_with(b"\n") || line.ends_with(b"\r\n") {
            return Err("events must be bounded LF-terminated JSONL lines".into());
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&line[..line.len() - 1]);
        let UniqueValue(value) = UniqueValue::deserialize(&mut deserializer)
            .map_err(|_| "invalid JSON event or duplicate key")?;
        deserializer.end().map_err(|_| "trailing event data")?;
        let object = value.as_object().ok_or("event must be an object")?;
        let expected = [
            "format",
            "namespace",
            "objectId",
            "eventId",
            "revision",
            "order",
            "operation",
            "actor",
            "thread",
            "eventTime",
            "observedAt",
            "language",
            "text",
            "attachments",
            "locator",
            "visibility",
            "payload",
        ];
        if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
            return Err("event fields differ from connector-event/v1".into());
        }
        if value["format"] != "connector-event/v1" {
            return Err("unsupported connector event".into());
        }
        for (key, max) in [
            ("namespace", 256),
            ("objectId", 1024),
            ("eventId", 1024),
            ("revision", 256),
            ("locator", 4096),
        ] {
            let field = value[key]
                .as_str()
                .ok_or("invalid event identity or locator")?;
            if !bounded(field, max, true) {
                return Err("invalid event identity or locator".into());
            }
        }
        let order = value["order"]
            .as_str()
            .ok_or("order must be a decimal string")?;
        if order.is_empty()
            || order.len() > 128
            || (order != "0"
                && (!order.bytes().all(|b| b.is_ascii_digit()) || order.starts_with('0')))
        {
            return Err("order must be a bounded decimal string".into());
        }
        let operation = value["operation"].as_str().ok_or("invalid operation")?;
        if !["upsert", "edit", "delete", "access-change"].contains(&operation) {
            return Err("invalid operation".into());
        }
        for (key, max) in [
            ("actor", 1024),
            ("thread", 1024),
            ("eventTime", 128),
            ("observedAt", 128),
            ("language", 64),
            ("visibility", 256),
        ] {
            optional_string(&value, key, max)?;
        }
        if let Some(text) = value["text"].as_str() {
            if !bounded(text, 65536, false) {
                return Err("invalid event text".into());
            }
        }
        let payload = value["payload"]
            .as_object()
            .ok_or("invalid payload envelope")?;
        let pkeys = ["encoding", "mediaType", "byteLength", "sha256", "data"];
        if payload.len() != pkeys.len()
            || pkeys.iter().any(|key| !payload.contains_key(*key))
            || payload["encoding"] != "base64"
        {
            return Err("invalid payload envelope".into());
        }
        if !bounded(
            payload["mediaType"]
                .as_str()
                .ok_or("invalid payload media type")?,
            256,
            true,
        ) || payload["data"]
            .as_str()
            .ok_or("invalid payload data")?
            .len()
            > 87384
        {
            return Err("invalid payload metadata".into());
        }
        let content = STANDARD
            .decode(payload["data"].as_str().ok_or("invalid payload data")?)
            .map_err(|_| "invalid base64 payload")?;
        let text = std::str::from_utf8(&content).map_err(|_| "payload must be UTF-8")?;
        if content.len() > 65_536 || payload["byteLength"].as_u64() != Some(content.len() as u64) {
            return Err("invalid payload length".into());
        }
        let sha = format!("{:x}", Sha256::digest(&content));
        if payload["sha256"].as_str() != Some(sha.as_str())
            || STANDARD.encode(&content) != payload["data"]
        {
            return Err("payload bytes do not match their declared digest".into());
        }
        if ["upsert", "edit"].contains(&operation) && value["text"].as_str() != Some(text) {
            return Err("text differs from exact payload bytes".into());
        }
        if ["delete", "access-change"].contains(&operation)
            && (!content.is_empty()
                || !value["text"].is_null()
                || !value["attachments"]
                    .as_array()
                    .ok_or("invalid attachments")?
                    .is_empty())
        {
            return Err("control events cannot carry replacement content".into());
        }
        if value["attachments"]
            .as_array()
            .ok_or("invalid attachments")?
            .len()
            > 64
        {
            return Err("too many attachments".into());
        }
        for attachment in value["attachments"]
            .as_array()
            .ok_or("invalid attachments")?
        {
            let fields = attachment.as_object().ok_or("invalid attachment")?;
            if fields.len() != 3
                || !fields.contains_key("id")
                || !fields.contains_key("locator")
                || !fields.contains_key("mediaType")
            {
                return Err("invalid attachment metadata".into());
            }
            if !bounded(
                attachment["id"].as_str().ok_or("invalid attachment id")?,
                1024,
                true,
            ) || !bounded(
                attachment["locator"]
                    .as_str()
                    .ok_or("invalid attachment locator")?,
                4096,
                false,
            ) || !bounded(
                attachment["mediaType"]
                    .as_str()
                    .ok_or("invalid attachment type")?,
                256,
                true,
            ) {
                return Err("invalid attachment metadata".into());
            }
        }
        events.push(Event {
            value,
            bytes: line.to_vec(),
            payload: content,
        });
        if events.len() > 1000 {
            return Err("export exceeds the 1000 event bound".into());
        }
    }
    Ok(events)
}

pub fn plan(raw: &[u8]) -> Result<Value, String> {
    let events = validate_jsonl(raw)?;
    let mut operations = serde_json::Map::new();
    for key in ["upsert", "edit", "delete", "access-change"] {
        operations.insert(key.into(), 0.into());
    }
    for event in &events {
        let operation = event.value["operation"].as_str().unwrap();
        let count = operations[operation].as_u64().unwrap_or(0) + 1;
        operations.insert(operation.into(), count.into());
    }
    let hash = format!("{:x}", Sha256::digest(raw));
    Ok(
        serde_json::json!({"format":"connector-client-plan/v1","events":events.len(),
        "operations":operations,"exportSha256":hash,"authority":"host-review-required"}),
    )
}

pub struct HostClient {
    pub python: String,
    pub host_script: String,
    pub root: String,
    pub host_config: String,
    pub authority: String,
    pub namespace: String,
    pub export: String,
    pub timeout: Duration,
}
impl HostClient {
    fn call(&self, extra: &[&str]) -> Result<Vec<u8>, String> {
        let mut command = Command::new(&self.python);
        #[cfg(unix)]
        command.process_group(0);
        command.arg(&self.host_script).args([
            "--root",
            &self.root,
            "--host-config",
            &self.host_config,
            "--authority",
            &self.authority,
        ]);
        command.args(extra);
        let mut child = command
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or("connector host stdout unavailable")?;
        let stderr = child
            .stderr
            .take()
            .ok_or("connector host stderr unavailable")?;
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        let out_reader = thread::spawn(move || {
            let _ = out_tx.send(read_bounded(stdout));
        });
        let err_reader = thread::spawn(move || {
            let _ = err_tx.send(read_bounded(stderr));
        });
        let start = Instant::now();
        let mut status = None;
        let mut output = None;
        let mut errors = None;
        loop {
            if status.is_none() {
                status = child.try_wait().map_err(|e| e.to_string())?;
            }
            if output.is_none() {
                output = out_rx.try_recv().ok();
            }
            if errors.is_none() {
                errors = err_rx.try_recv().ok();
            }
            if status.is_some() && output.is_some() && errors.is_some() {
                break;
            }
            if start.elapsed() >= self.timeout {
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                #[cfg(not(unix))]
                {
                    let _ = child.kill();
                }
                let _ = child.wait();
                drop(child.stdout.take());
                drop(child.stderr.take());
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err("connector host timed out".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let (stdout, out_overflow, out_error) = output.unwrap();
        let (_stderr, err_overflow, err_error) = errors.unwrap();
        let _ = out_reader.join();
        let _ = err_reader.join();
        if out_overflow || err_overflow {
            return Err("connector host output exceeds 1 MiB receipt bound".into());
        }
        if out_error || err_error {
            return Err("connector host output could not be read completely".into());
        }
        if !status.unwrap().success() {
            return Err("connector host failed".into());
        }
        Ok(stdout) // Preserve native receipt bytes exactly.
    }
    pub fn submit(&self) -> Result<Vec<u8>, String> {
        self.call(&["--namespace", &self.namespace, "--export", &self.export])
    }
    /// Inherit process stdin; the host admits only exact registered export bytes.
    pub fn submit_stdin(&self) -> Result<Vec<u8>, String> {
        self.call(&[
            "--namespace",
            &self.namespace,
            "--export",
            &self.export,
            "--stdin",
        ])
    }
    pub fn resume(&self) -> Result<Vec<u8>, String> {
        self.submit()
    }
    pub fn status(&self) -> Result<Vec<u8>, String> {
        self.call(&["--dead-letters"])
    }
    pub fn replay(&self, line: u64) -> Result<Vec<u8>, String> {
        if line == 0 {
            return Err("replay line must be positive".into());
        }
        let line = line.to_string();
        self.call(&[
            "--namespace",
            &self.namespace,
            "--export",
            &self.export,
            "--replay-line",
            &line,
        ])
    }
}

fn read_bounded<R: Read>(mut reader: R) -> (Vec<u8>, bool, bool) {
    let mut output = Vec::with_capacity(MAX_RECEIPT + 1);
    let mut buffer = [0u8; 65536];
    let mut overflow = false;
    let mut read_error = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Err(_) => {
                read_error = true;
                break;
            }
            Ok(n) => {
                let room = MAX_RECEIPT + 1 - output.len();
                if room > 0 {
                    output.extend_from_slice(&buffer[..n.min(room)]);
                }
                if output.len() > MAX_RECEIPT || n > room {
                    overflow = true;
                }
            }
        }
    }
    (output, overflow, read_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_fixtures_preserve_large_decimal_order_and_utf8_payload() {
        let raw = include_bytes!("../../fixtures/events.jsonl");
        let events = validate_jsonl(raw).unwrap();
        assert_eq!(events[0].value["order"], "9007199254740993");
        assert_eq!(
            std::str::from_utf8(&events[0].payload).unwrap(),
            "Hola, mundo 🌎"
        );
        assert_eq!(
            events[0].bytes,
            raw.split_inclusive(|b| *b == b'\n').next().unwrap()
        );
        assert_eq!(events[1].value["order"], "9007199254740994");
        assert_eq!(plan(raw).unwrap()["events"], 2);
    }
    #[test]
    fn rejects_numeric_order_and_corrupted_payload() {
        let raw = include_bytes!("../../fixtures/events.jsonl");
        let numeric = String::from_utf8_lossy(raw).replace(
            "\"order\":\"9007199254740993\"",
            "\"order\":9007199254740993",
        );
        assert!(validate_jsonl(numeric.as_bytes()).is_err());
        let corrupted = String::from_utf8_lossy(raw).replace("2fb57883", "0fb57883");
        assert!(validate_jsonl(corrupted.as_bytes()).is_err());
    }
}
