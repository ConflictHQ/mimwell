//! Trusted-operator local classifier. The caller authorizes sources before admission.
//! A score is never an authorization or destination-write grant.
//! Embedders must supply source authorization, admission accounting and review.
//! This library neither changes process panic hooks nor provides hard cancellation.

pub mod ffi;
use model2vec_rs::model::StaticModel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Component, Path},
    time::Instant,
};

pub const INPUT_CAP: usize = 1_048_576;
const MANIFEST_CAP: usize = 4_194_304;
const MODEL_CAP: usize = 134_217_728;
pub const OUTPUT_CAP: usize = 2_097_152;
const ITEM_CAP: usize = 64;
const TEXT_CAP: usize = 16_384;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Artifact {
    file: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Embedding {
    revision: String,
    license: String,
    dimensions: usize,
    normalize: bool,
    max_tokens: usize,
    tokenizer: Artifact,
    model: Artifact,
    config: Artifact,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Calibration {
    method: String,
    temperature: f64,
    #[serde(deserialize_with = "Option::deserialize")]
    evidence_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Head {
    labels: Vec<String>,
    weights: Vec<Vec<f64>>,
    bias: Vec<f64>,
    training_sha256: String,
    license: String,
    calibration: Calibration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    format: String,
    taxonomy_sha256: String,
    embedding: Embedding,
    head: Head,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    id: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    protocol_version: String,
    items: Vec<Item>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Prediction {
    id: String,
    label: Option<String>,
    probabilities: Vec<f64>,
    confidence: Option<f64>,
    requires_review: bool,
    gaps: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Usage {
    embedding_calls: usize,
    classified_items: usize,
    hosted_calls: usize,
    input_bytes: usize,
    max_tokens_per_item: usize,
    elapsed_micros: u128,
    threads: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    protocol_version: &'static str,
    bundle_sha256: String,
    taxonomy_sha256: String,
    input_sha256: String,
    labels: Vec<String>,
    calibration: Calibration,
    results: Vec<Prediction>,
    usage: Usage,
}

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn identity(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
}
pub fn read_cap(reader: impl Read, cap: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    reader
        .take(cap as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "read-failed")?;
    if raw.len() > cap {
        return Err("byte-budget-exceeded");
    }
    Ok(raw)
}
fn regular(path: &Path, cap: usize) -> Result<Vec<u8>> {
    // Resolve no symlink component. Pinned hashes remain authoritative over bytes.
    let absolute = path.canonicalize().map_err(|_| "artifact-unavailable")?;
    let given = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "artifact-unavailable")?
            .join(path)
    };
    // macOS /tmp is a system symlink; callers must provide canonical absolute paths.
    if given != absolute {
        return Err("artifact-path-must-be-canonical");
    }
    if !fs::symlink_metadata(&absolute)
        .map_err(|_| "artifact-unavailable")?
        .is_file()
    {
        return Err("artifact-not-regular");
    }
    read_cap(
        fs::File::open(absolute).map_err(|_| "artifact-unavailable")?,
        cap,
    )
}
fn artifact(root: &Path, a: &Artifact, cap: usize) -> Result<Vec<u8>> {
    if !hash(&a.sha256)
        || a.file.contains('\\')
        || a.file.len() > 128
        || Path::new(&a.file).components().count() != 1
        || !matches!(
            Path::new(&a.file).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err("invalid-artifact-reference");
    }
    let raw = regular(&root.join(&a.file), cap)?;
    if digest(&raw) != a.sha256 {
        return Err("artifact-pin-changed");
    }
    Ok(raw)
}
fn validate(bundle: &Bundle) -> Result<()> {
    let e = &bundle.embedding;
    let h = &bundle.head;
    let count = h.labels.len();
    let c = &h.calibration;
    if bundle.format != "brain-classifier/v1"
        || !hash(&bundle.taxonomy_sha256)
        || e.revision.is_empty()
        || e.revision.len() > 256
        || e.license.is_empty()
        || h.license.is_empty()
        || e.license.len() > 128
        || h.license.len() > 128
        || !(1..=1024).contains(&e.dimensions)
        || !(1..=512).contains(&e.max_tokens)
        || !(2..=32).contains(&count)
        || h.labels.iter().any(|s| !identity(s))
        || h.labels.iter().collect::<HashSet<_>>().len() != count
        || h.weights.len() != count
        || h.bias.len() != count
        || !hash(&h.training_sha256)
        || h.weights
            .iter()
            .any(|row| row.len() != e.dimensions || row.iter().any(|v| !v.is_finite()))
        || h.bias.iter().any(|v| !v.is_finite())
        || !c.temperature.is_finite()
        || !(0.01..=100.0).contains(&c.temperature)
        || !match c.method.as_str() {
            "none" => c.temperature == 1.0 && c.evidence_sha256.is_none(),
            "temperature" => c.evidence_sha256.as_ref().is_some_and(|s| hash(s)),
            _ => false,
        }
    {
        return Err("invalid-classifier-bundle");
    }
    Ok(())
}
fn validate_request(request: &Request) -> Result<()> {
    if request.protocol_version != "1.0"
        || request.items.len() > ITEM_CAP
        || request
            .items
            .iter()
            .any(|i| !identity(&i.id) || i.text.len() > TEXT_CAP)
        || request
            .items
            .iter()
            .map(|i| &i.id)
            .collect::<HashSet<_>>()
            .len()
            != request.items.len()
    {
        return Err("invalid-or-over-budget-request");
    }
    Ok(())
}
fn predict(id: String, embedding: &[f32], head: &Head) -> Result<Prediction> {
    if embedding.len() != head.weights[0].len() || embedding.iter().any(|v| !v.is_finite()) {
        return Err("invalid-embedding");
    }
    if embedding.iter().all(|v| *v == 0.0) {
        return Ok(Prediction {
            id,
            label: None,
            probabilities: vec![],
            confidence: None,
            requires_review: true,
            gaps: vec!["empty-embedding"],
        });
    }
    let logits: Vec<f64> = head
        .weights
        .iter()
        .zip(&head.bias)
        .map(|(row, bias)| {
            (row.iter()
                .zip(embedding)
                .map(|(w, x)| w * f64::from(*x))
                .sum::<f64>()
                + bias)
                / head.calibration.temperature
        })
        .collect();
    if logits.iter().any(|v| !v.is_finite()) {
        return Err("nonfinite-classifier-score");
    }
    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let mut probabilities: Vec<f64> = logits.iter().map(|v| (v - max).exp()).collect();
    let sum: f64 = probabilities.iter().sum();
    for p in &mut probabilities {
        *p /= sum;
    }
    let selected =
        probabilities.iter().enumerate().fold(
            0,
            |best, (i, v)| if *v > probabilities[best] { i } else { best },
        );
    let calibrated = head.calibration.method != "none";
    Ok(Prediction {
        id,
        label: Some(head.labels[selected].clone()),
        confidence: if calibrated {
            Some(probabilities[selected])
        } else {
            None
        },
        probabilities,
        requires_review: true,
        gaps: if calibrated {
            vec![]
        } else {
            vec!["uncalibrated"]
        },
    })
}
fn run(path: &Path, expected: &str, raw: &[u8]) -> Result<Response> {
    let started = Instant::now();
    if !hash(expected) || raw.len() > INPUT_CAP {
        return Err("invalid-pin-or-input-budget");
    }
    let request: Request = serde_json::from_slice(raw).map_err(|_| "invalid-request")?;
    validate_request(&request)?;
    let bytes = regular(path, MANIFEST_CAP)?;
    if digest(&bytes) != expected {
        return Err("bundle-pin-changed");
    }
    let bundle: Bundle = serde_json::from_slice(&bytes).map_err(|_| "invalid-bundle")?;
    validate(&bundle)?;
    let root = path.parent().ok_or("invalid-bundle-path")?;
    let e = &bundle.embedding;
    let tokenizer = artifact(root, &e.tokenizer, 16_777_216)?;
    let weights = artifact(root, &e.model, MODEL_CAP)?;
    let config = artifact(root, &e.config, 65_536)?;
    let model = StaticModel::from_bytes(&tokenizer, &weights, &config, Some(e.normalize))
        .map_err(|_| "model-load-failed")?;
    let count = request.items.len();
    let texts: Vec<String> = request.items.iter().map(|i| i.text.clone()).collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .map_err(|_| "worker-unavailable")?;
    let embeddings = if count == 0 {
        vec![]
    } else {
        pool.install(|| model.encode_with_args(&texts, Some(e.max_tokens), ITEM_CAP))
    };
    if embeddings.len() != count {
        return Err("embedding-count-mismatch");
    }
    let results = request
        .items
        .into_iter()
        .zip(embeddings)
        .map(|(i, embedding)| predict(i.id, &embedding, &bundle.head))
        .collect::<Result<Vec<_>>>()?;
    Ok(Response {
        protocol_version: "1.0",
        bundle_sha256: expected.to_string(),
        taxonomy_sha256: bundle.taxonomy_sha256,
        input_sha256: digest(raw),
        labels: bundle.head.labels,
        calibration: bundle.head.calibration,
        results,
        usage: Usage {
            embedding_calls: usize::from(count != 0),
            classified_items: count,
            hosted_calls: 0,
            input_bytes: raw.len(),
            max_tokens_per_item: e.max_tokens,
            elapsed_micros: started.elapsed().as_micros(),
            threads: 1,
        },
    })
}

/// Classify an already authorized, bounded request using pinned local artifacts.
///
/// This synchronous call performs no network or subprocess I/O. It is not the
/// intake planner or governed writer; scores remain mandatory-review proposals.
/// The host owns cancellation/isolation and must account for admission before
/// calling. The returned JSON is the same protocol as the command (no newline).
pub fn classify_json(path: &Path, expected: &str, raw: &[u8]) -> Result<Vec<u8>> {
    let result = run(path, expected, raw)?;
    let output = serde_json::to_vec(&result).map_err(|_| "response-encoding-failed")?;
    if output.len() + 1 > OUTPUT_CAP {
        return Err("output-budget-exceeded");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn head() -> Head {
        Head {
            labels: vec!["keep".into(), "skip".into()],
            weights: vec![vec![1., 0.], vec![0., 1.]],
            bias: vec![0., 0.],
            training_sha256: "a".repeat(64),
            license: "test-fixture".into(),
            calibration: Calibration {
                method: "none".into(),
                temperature: 1.,
                evidence_sha256: None,
            },
        }
    }
    #[test]
    fn score_is_not_calibrated_confidence_or_permission() {
        let p = predict("one".into(), &[1., 0.], &head()).unwrap();
        assert_eq!(p.label.as_deref(), Some("keep"));
        assert!(p.requires_review);
        assert_eq!(p.confidence, None);
        assert!((p.probabilities[0] - 0.7310585786300049).abs() < 1e-12);
    }
    #[test]
    fn empty_unknown_and_invalid_embeddings_do_not_invent_labels() {
        assert!(
            predict("x".into(), &[0., 0.], &head())
                .unwrap()
                .label
                .is_none()
        );
        assert!(predict("x".into(), &[f32::NAN, 0.], &head()).is_err());
        assert!(predict("x".into(), &[1.], &head()).is_err());
    }
    #[test]
    fn temperature_uses_stable_softmax_and_still_requires_review() {
        let mut h = head();
        h.calibration.method = "temperature".into();
        h.calibration.temperature = 2.;
        h.calibration.evidence_sha256 = Some("b".repeat(64));
        h.bias = vec![1000., 1000.];
        let p = predict("x".into(), &[1., 0.], &h).unwrap();
        assert!((p.confidence.unwrap() - 0.6224593312018546).abs() < 1e-12);
        assert!(p.requires_review);
    }
    #[test]
    fn input_admission_is_closed_and_bounded() {
        assert!(
            serde_json::from_str::<Request>(
                r#"{"protocolVersion":"1.0","items":[],"command":"oops"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Request>(
                r#"{"protocolVersion":"1.0","protocolVersion":"1.0","items":[]}"#
            )
            .is_err()
        );
        let mut r = Request {
            protocol_version: "1.0".into(),
            items: vec![],
        };
        assert!(validate_request(&r).is_ok());
        r.items.push(Item {
            id: "x".into(),
            text: "a".repeat(TEXT_CAP + 1),
        });
        assert!(validate_request(&r).is_err());
        assert!(read_cap(&b"12345"[..], 4).is_err());
    }
}
