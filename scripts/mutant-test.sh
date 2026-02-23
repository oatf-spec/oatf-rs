#!/bin/bash
set -e
cargo mutants --timeout 300 -- --all-targets
