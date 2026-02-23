# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                          # Build library
cargo test                           # Run all tests (conformance + extra)
cargo test --test conformance        # Run only conformance tests
cargo test --test validate_extra     # Run only extra validation tests
cargo test conformance::validate     # Run a specific conformance module
cargo test v021_rejects_numeric      # Run a single test by name
cargo check                          # Type-check without building
cargo test --no-default-features     # Test without CEL evaluation
cargo test --all-features            # Test with all features
cargo clippy -- -D warnings          # Lint
cargo fmt --check                    # Check formatting
cargo machete                        # Detect unused dependencies
cargo deny check                     # Advisory/license/ban checks
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps  # Build docs (warnings = errors)
```

Conformance fixtures live in `spec/conformance/` (git submodule). Override with `OATF_CONFORMANCE_DIR` env var.

## Architecture

The crate implements four entry points that form a pipeline:

```
parse(yaml) → Document → validate(doc) → ValidationResult
                       → normalize(doc) → Document → serialize(doc) → yaml
```

**load()** is a convenience that runs parse → validate → normalize in sequence.

### Parse (parse.rs)
Two-step deserialization: YAML → `serde_json::Value` → `Document`. Pre-parse rejects YAML anchors/aliases/merge keys, multi-document streams, and unknown top-level keys. Post-parse rejects non-`x-` prefixed extension fields.

### Validate (validate.rs)
45 rules (V-001–V-045) that return **all** errors, not just the first. Uses `collect_actors()` helper to uniformly iterate phases across all three execution forms. Single-phase form (`execution.state`) is handled separately in V-033/V-034/V-035 since `collect_actors()` returns empty for it.

### Normalize (normalize.rs)
8 idempotent steps. N-006/N-007 run first to convert single-phase and multi-phase forms into multi-actor form. All subsequent steps operate on the `actors` array.

### Serialize (serialize.rs)
Document → `serde_json::Value` → YAML via serde-saphyr.

### Primitives (primitives.rs)
12 execution primitives per SDK spec §5.1–§5.11: `resolve_simple_path`, `resolve_wildcard_path`, `parse_duration`, `evaluate_condition`, `evaluate_predicate`, `interpolate_template`, `evaluate_extractor`, `select_response`, `evaluate_trigger`, `parse_event_qualifier`, `extract_protocol` (re-exported), `compute_effective_state`. Used by evaluation and runtime tools.

### Evaluate (evaluate.rs)
Traits: `CelEvaluator`, `SemanticEvaluator`, `GenerationProvider`. Functions: `evaluate_pattern`, `evaluate_expression`, `evaluate_indicator`, `compute_verdict`. `DefaultCelEvaluator` is behind the `cel-eval` feature flag.

## Public API

Top-level re-exports: `parse`, `validate`, `normalize`, `serialize`, `load`.
Public modules: `enums`, `error`, `types`, `evaluate`, `primitives`, `parse`, `validate`, `normalize`, `serialize`.
Internal modules (pub(crate)): `surface`, `event_registry`.

## Key Design Decisions

**Three execution forms** are mutually exclusive in input but always normalize to multi-actor:
- `execution.state` → single phase, single actor
- `execution.phases` → multiple phases, single actor
- `execution.actors` → canonical multi-actor form

**Severity** is a union type: accepts scalar `"high"` or object `{level: high, confidence: 50}`. Custom serde in types.rs. After normalization, always object form.

**Action** is a tagged union with custom serde: the single non-`x-` key determines the variant (`log`, `send_notification`, `send_elicitation`, or catch-all `BindingSpecific`).

**PatternMatch** has standard form (`target` + `condition`) and shorthand form (operator keys directly on pattern). N-005 normalizes shorthand → standard.

**Extension fields** use `#[serde(flatten)] HashMap<String, Value>` on Attack, Execution, Actor, Phase, Indicator. Only `x-`-prefixed keys are allowed; others cause parse errors.

**Open enums** (mode, protocol) are strings validated by regex pattern. **Closed enums** (SeverityLevel, Status, etc.) are validated by serde deserialization.

## Spec Submodule

`spec/` is a git submodule from `https://github.com/oatf-spec/spec.git` containing:
- `spec/format.md` — Normative format specification
- `spec/sdk.md` — SDK API contract (entry points, types, rules)
- `schemas/v0.1.json` — JSON Schema
- `conformance/` — Test fixtures organized by entry point (parse, validate, normalize, evaluate, verdict, roundtrip, primitives)

## Test Organization

- `tests/conformance.rs` — Module root including parse, validate, normalize, roundtrip, primitives, evaluate, verdict
- `tests/validate_extra.rs` — 26 targeted edge-case tests for specific V-rules
- Conformance tests use `values_structurally_equal()` for deep comparison that treats missing optional fields as equivalent to null
- Tests skip gracefully if fixture files are missing (prints warning, returns)
- V-014 CEL tests are skipped when `cel-eval` feature is disabled

## Spec References

The normative specification and SDK contract are in the spec submodule:
- `spec/spec/format.md` — OATF format specification (document structure, conformance rules §11.1, normalization rules §11.2)
- `spec/spec/sdk.md` — SDK API contract (entry points, types, validation/normalization rules, evaluation functions, primitives)

## Registries

**Surface registry** (surface.rs): 38 entries mapping surface names to protocol + default target path. Used by V-005 (surface validation) and N-004 (target resolution).

**Event-mode registry** (event_registry.rs): 45+ entries mapping event names to valid modes. Used by V-029 (event-mode validity checking).

## CI

GitHub Actions workflow at `.github/workflows/ci.yml`:
- **Lint job**: fmt, clippy, machete, doc, deny, semver-checks (stable only)
- **Test matrix**: 3 toolchains (stable, nightly, MSRV 1.85.0) × 3 feature sets (default, no-default-features, all-features)
- MSRV is 1.85.0 (edition 2024 minimum)

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/): `type: description`. Common types: `feat`, `fix`, `test`, `refactor`, `build`, `chore`, `docs`. Scope is optional. Body should explain *why*, not *what*.
