# oatf

Rust SDK for the [Open Agent Threat Format (OATF)](https://oatf.io).

OATF is a YAML-based format for describing security threats against AI agent
communication protocols (MCP, A2A, AG-UI). This crate provides parsing,
validation, normalization, serialization, and evaluation of OATF documents.

## Quick Start

```rust
use oatf::{load, parse, validate, normalize, serialize};

// Parse → validate → normalize in one step
let result = load(yaml_str).expect("valid OATF document");
println!("{:?}", result.document.attack.name);

// Or use individual entry points
let doc = parse(yaml_str).unwrap();
let validation = validate(&doc);
assert!(validation.is_valid());
let normalized = normalize(doc);
let yaml_out = serialize(&normalized).unwrap();
```

## Feature Flags

| Feature    | Default | Description |
|------------|---------|-------------|
| `cel-eval` | yes     | CEL expression evaluation via the [`cel`](https://crates.io/crates/cel) crate. Enables `DefaultCelEvaluator`. |

To disable CEL evaluation (reduces dependencies):

```toml
[dependencies]
oatf = { version = "0.1", default-features = false }
```

## Pipeline

```text
parse(yaml) → Document → validate(doc) → ValidationResult
                       → normalize(doc) → Document → serialize(doc) → yaml
```

- **parse** — YAML → `Document`. Rejects anchors, aliases, merge keys, multi-document streams.
- **validate** — 45 conformance rules (V-001–V-045) returning all errors and warnings.
- **normalize** — 8 idempotent steps converting to canonical multi-actor form.
- **serialize** — `Document` → YAML.
- **load** — Convenience: parse → validate → normalize.
- **evaluate** — Pattern, CEL expression, and semantic indicator evaluation with verdict computation.
- **primitives** — 12 execution primitives (path resolution, duration parsing, condition evaluation, etc.).

## Conformance

This crate passes the full [OATF conformance suite](https://github.com/oatf-spec/spec/tree/main/conformance)
(314 test cases across parse, validate, normalize, evaluate, verdict, roundtrip, and primitives).

## Minimum Supported Rust Version

The MSRV is **1.85.0** (edition 2024). It is tested in CI and will be bumped
as a minor version change.

## License

Apache-2.0
