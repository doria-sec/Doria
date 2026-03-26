# doria-types

Shared types and JSON schema for the Doria scanner pipeline.

This crate is the **contract** between the Rust scanning engine and the Python agent (`doria-engine`).
Both sides depend on this schema. Do not change it without updating both sides.

---

## Structs

### `ScanResult`
The top-level output of a scan. One `ScanResult` is written per package as a single JSON line to stdout by `doria-scanner`.

| Field | Type | Description |
|-------|------|-------------|
| `package_name` | `String` | Name of the scanned package |
| `package_version` | `String` | Version of the scanned package |
| `ecosystem` | `Ecosystem` | `npm` or `pip` |
| `status` | `ScanStatus` | Whether the scan completed successfully |
| `error` | `Option<String>` | Error message if status is `failed` |
| `risk_score` | `f32` | Aggregate risk score from 0.0 to 1.0, computed by `doria-core` |
| `findings` | `Vec<Finding>` | List of individual findings |
| `scanned_at` | `String` | ISO 8601 timestamp |

---

### `Finding`
A single detected threat or suspicious pattern within a package.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | Unique finding ID e.g. `doria-001` |
| `kind` | `FindingKind` | Category of the finding |
| `severity` | `Severity` | How dangerous this finding is |
| `package_name` | `String` | Package this finding belongs to |
| `package_version` | `String` | Version this finding belongs to |
| `description` | `String` | Human-readable explanation |
| `location` | `Option<Location>` | File, line, and column. `None` for metadata-level findings |
| `evidence` | `Option<String>` | The raw code snippet that triggered this finding. Fed directly to the LLM reasoning layer |
| `confidence` | `f32` | Detector confidence from 0.0 to 1.0 |
| `slopsquatting` | `Option<SlopsquattingDetail>` | Extra detail for slopsquatting findings only |

---

### `Location`
Points to the exact position in source code where a finding was detected.

| Field | Type | Description |
|-------|------|-------------|
| `file` | `String` | Relative path to the file |
| `line` | `u32` | Line number |
| `column` | `u32` | Column number |

---

### `SlopsquattingDetail`
Additional metadata attached to `Slopsquatting` findings. Captures the signals that confirm a package name matches a known AI hallucination pattern.

| Field | Type | Description |
|-------|------|-------------|
| `similar_to` | `String` | The real package this name is mimicking |
| `edit_distance` | `u32` | Levenshtein distance to the real package name |
| `hallucination_confirmed` | `bool` | Whether this name appears in the Spracklen et al. dataset |
| `package_age_days` | `u32` | How old the package is in days |
| `stars` | `u32` | GitHub stars |
| `contributors` | `u32` | Number of contributors |
| `has_readme` | `bool` | Whether the package has a README |

---

## Enums

### `Severity`
```
Critical | High | Medium | Low | Info
```

### `FindingKind`
| Variant | Description |
|---------|-------------|
| `NetworkCall` | Unexpected outbound network connection |
| `ShellExecution` | Shell command execution (`child_process.exec`, `os.system`) |
| `DynamicCodeExecution` | `eval` or `exec` on non-literal arguments |
| `CredentialAccess` | Reading `~/.ssh`, `~/.aws`, environment variables matching secret patterns |
| `ObfuscatedCode` | Base64 decode followed by execution |
| `InstallHook` | `postinstall` or `preinstall` scripts executing arbitrary code |
| `Slopsquatting` | Package name matches a known AI hallucination pattern |
| `Typosquat` | Package name is suspiciously close to a popular legitimate package |

### `ScanStatus`
| Variant | Description |
|---------|-------------|
| `Complete` | Scan finished successfully |
| `Partial` | Scan ran but hit an error mid-way |
| `Failed` | Scanner could not parse the package at all |

### `Ecosystem`
```
npm | pip
```

---

## Example Output

A `ScanResult` serialised to JSON as written to stdout by `doria-scanner`:
```json
{
  "package_name": "co1ors",
  "package_version": "1.0.0",
  "ecosystem": "npm",
  "status": "complete",
  "error": null,
  "risk_score": 0.97,
  "scanned_at": "2026-03-26T10:23:01Z",
  "findings": [
    {
      "id": "doria-001",
      "kind": "shell_execution",
      "severity": "critical",
      "package_name": "co1ors",
      "package_version": "1.0.0",
      "description": "child_process.exec() called with dynamic argument in postinstall hook",
      "location": {
        "file": "scripts/install.js",
        "line": 15,
        "column": 2
      },
      "evidence": "exec(Buffer.from('cm0gLXJmIC8=', 'base64').toString())",
      "confidence": 0.99,
      "slopsquatting": null
    },
    {
      "id": "doria-002",
      "kind": "slopsquatting",
      "severity": "high",
      "package_name": "huggingface-cli",
      "package_version": "0.0.1",
      "description": "Package name matches documented AI hallucination pattern. Registered 12 days after first observed hallucination.",
      "location": null,
      "evidence": null,
      "confidence": 0.94,
      "slopsquatting": {
        "similar_to": "huggingface_hub",
        "edit_distance": 3,
        "hallucination_confirmed": true,
        "package_age_days": 12,
        "stars": 0,
        "contributors": 1,
        "has_readme": false
      }
    }
  ]
}
```

---

## Usage

Add to any crate in the workspace:
```toml
# Cargo.toml
[dependencies]
doria-types = { path = "../doria-types" }
```
```rust
use doria_types::{ScanResult, Finding, Severity, FindingKind};
```

---

## Notes
- `confidence` thresholds: autonomous action fires above `0.95`. Between `0.70` and `0.95` Doria alerts and recommends human review.
- `evidence` is fed directly to the LLM reasoning layer in `doria-engine`. Always populate it when available.
- `location` is `None` for metadata-level findings like typosquatting and slopsquatting where there is no specific line of code to point to.
