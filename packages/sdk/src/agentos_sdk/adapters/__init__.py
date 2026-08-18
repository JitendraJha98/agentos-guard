"""Framework adapters. Each contributes normalization + a framework entry point ONLY — enforcement
always goes through `agentos_sdk.enforce.governed_call`, so every adapter inherits the same outcome
map and cannot drift. Submodules import their framework lazily so the base SDK never requires it."""
