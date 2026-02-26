# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-02-26

### Changed

- **resolve_event_qualifier** — accepts `protocol` parameter; keys registry by (protocol, base_event); converts number/boolean qualifiers to canonical strings.
- **evaluate_trigger** — accepts `protocol` parameter; qualifier resolution follows §5.8 order (event.qualifier first, then content-based).
- **compute_verdict** — returns Error when all indicators are skipped (§4.5).
- **evaluate_extractor** — reads `direction` from conformance fixtures.

### Added

- **event_registry** — protocol-aware event qualifier resolution registry (§7).
- **interpolate_value** — recursive value interpolation for nested structures.
- Conformance fixture runners for `resolve_event_qualifier`, `evaluate_trigger`, and `interpolate_value` (39 new test cases).
- Mutation testing exclusions (`.cargo/mutants.toml`) to suppress ~300 low-value mutants.

### Fixed

- Qualifier resolution order now matches §5.8 step 2c-i.
- All-skipped verdict now returns Error instead of NotExploited per §4.5.

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

[0.2.0]: https://github.com/oatf-spec/oatf-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/oatf-spec/oatf-rs/releases/tag/v0.1.0
