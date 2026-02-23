# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2025-06-15

Initial release of the OATF Rust SDK.

### Added

- **parse** — Two-step YAML deserialization (YAML → serde_json::Value → Document) with strict input validation. Rejects YAML anchors, aliases, merge keys, multi-document streams, and unknown top-level keys.
- **validate** — 45 conformance rules (V-001–V-045) and 5 warnings (W-001–W-005) returning all diagnostics, not just the first. Full RFC 9535 JSONPath validation, CEL expression validation, regex validation, and duration parsing.
- **normalize** — 8 idempotent normalization steps converting single-phase and multi-phase execution forms into canonical multi-actor form.
- **serialize** — Document to YAML serialization via serde-saphyr.
- **load** — Convenience entry point composing parse → validate → normalize.
- **evaluate** — Pattern matching, CEL expression evaluation (behind `cel-eval` feature flag), semantic evaluation traits, and verdict computation with `any`/`all` correlation logic.
- **primitives** — 12 execution primitives per SDK spec: `resolve_simple_path`, `resolve_wildcard_path`, `parse_duration`, `evaluate_condition`, `evaluate_predicate`, `interpolate_template`, `evaluate_extractor`, `select_response`, `evaluate_trigger`, `parse_event_qualifier`, `extract_protocol`, `compute_effective_state`.
- Full conformance test suite coverage (314 test cases).
- Property-based tests for primitives invariants.
- Fuzz targets for parse, normalize, roundtrip, path resolution, duration parsing, and condition evaluation.

[0.1.0]: https://github.com/oatf-spec/oatf-rs/releases/tag/v0.1.0
