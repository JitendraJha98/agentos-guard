# Deferred Items — Phase 01 (walking-skeleton)

Out-of-scope discoveries logged during execution. NOT fixed in the plan that found them.

| Found in | Item | Type | Disposition |
|----------|------|------|-------------|
| 01-05 | `opa-wasmtime` registers an `atexit` benchmark hook that raises a harmless `ValueError: min() iterable argument is empty` to stderr at interpreter shutdown (site-packages `opa_wasmtime/benchmark.py`). All test suites pass; it is pure shutdown noise, not a test failure, and originates in the third-party dependency (01-04's policy stack), not in agentos code. | Dependency-side quirk / CI log noise | Carry forward — consider a CI stderr filter or an upstream issue; revisit when the `opa-wasmtime <0.2` pin is re-evaluated (01-04 owns the dependency). |
