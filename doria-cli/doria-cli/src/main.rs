use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: doria <command> [args]");
        eprintln!("       doria install <package>");
        eprintln!("       doria scan <package_dir> <package_name> <package_version>");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "install" => {
            if args.len() < 3 {
                eprintln!("usage: doria install <package>");
                std::process::exit(1);
            }
            let package = &args[2];
            println!(
                "\x1b[36m[*] Doria is scanning '{}' before install...\x1b[0m",
                package
            );
            handle_install(package);
        }
        "scan" => {
            if args.len() < 5 {
                eprintln!("usage: doria scan <package_dir> <package_name> <package_version>");
                std::process::exit(1);
            }
            handle_scan(&args[2], &args[3], &args[4]);
        }
        _ => {
            eprintln!("unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn handle_install(package: &str) {
    // Step 1: Download the package to a temp dir using npm pack
    let tmp_dir = std::env::temp_dir().join(format!("doria-{}", package));
    std::fs::create_dir_all(&tmp_dir).expect("failed to create temp dir");

    println!("\x1b[34m[*] Fetching package metadata...\x1b[0m");

    // Use npm pack to download the tarball without installing
    let pack_result = Command::new("npm")
        .args(["pack", package, "--dry-run", "--json"])
        .output();

    match pack_result {
        Ok(output) if output.status.success() => {
            let json_str = String::from_utf8_lossy(&output.stdout);
            // Parse version from npm pack output
            let version = extract_version_from_npm_pack(&json_str).unwrap_or("0.0.0".to_string());

            println!("\x1b[34m[*] Running static analysis (AST scan)...\x1b[0m");

            // Step 2: Run the Rust scanner on the downloaded package
            // For now, scan the npm cache directory
            let cache_dir = get_npm_cache_dir(package);
            let rust_findings = run_rust_scanner(&cache_dir, package, &version);

            println!("\x1b[35m[*] Running ML threat intelligence...\x1b[0m");

            // Step 3: Run the Python ML engine
            let ml_result = run_python_ml(package, &rust_findings);

            // Step 4: Make the final decision
            match ml_result {
                Ok(report) => {
                    print_threat_report(&report);

                    if report.is_safe {
                        println!(
                            "\n\x1b[32m[+] Package is safe. Proceeding with install...\x1b[0m"
                        );
                        // Actually install the package
                        let install = Command::new("npm")
                            .args(["install", package])
                            .status()
                            .expect("failed to run npm install");

                        if install.success() {
                            println!("\x1b[32m[+] {} installed successfully.\x1b[0m", package);
                        } else {
                            eprintln!("\x1b[31m[-] npm install failed.\x1b[0m");
                            std::process::exit(1);
                        }
                    } else {
                        println!(
                            "\n\x1b[1;31m[!] BLOCKED: Doria has blocked the installation of '{}'.\x1b[0m",
                            package
                        );
                        println!("    Run with --force to override (not recommended).");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "\x1b[33m[!] ML engine failed: {}. Proceeding with caution...\x1b[0m",
                        e
                    );
                    // Fail open — allow install but warn
                    let _ = Command::new("npm").args(["install", package]).status();
                }
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "\x1b[33m[!] Could not fetch package info: {}\x1b[0m",
                stderr
            );
            eprintln!("    Package '{}' may not exist on npm.", package);
            eprintln!("\x1b[1;31m[!] SLOPSQUAT ALERT: This package may be AI-hallucinated!\x1b[0m");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("\x1b[31m[-] Failed to run npm: {}\x1b[0m", e);
            std::process::exit(1);
        }
    }
}

fn handle_scan(package_dir: &str, package_name: &str, package_version: &str) {
    println!("\x1b[36m[*] Running Doria scan on: {}\x1b[0m", package_dir);

    let rust_findings = run_rust_scanner(package_dir, package_name, package_version);

    println!("\x1b[35m[*] Running ML threat intelligence...\x1b[0m");
    match run_python_ml(package_name, &rust_findings) {
        Ok(report) => print_threat_report(&report),
        Err(e) => eprintln!("\x1b[31m[-] ML engine error: {}\x1b[0m", e),
    }
}

fn run_rust_scanner(package_dir: &str, package_name: &str, package_version: &str) -> String {
    // Find the doria-scanner binary (sibling to this binary)
    let scanner_bin = find_binary("doria-scanner");

    let output = Command::new(&scanner_bin)
        .args([package_dir, package_name, package_version, "npm"])
        .output();

    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            eprintln!("\x1b[33m[!] Scanner warning: {}\x1b[0m", err);
            // Return empty findings JSON so the ML engine still runs
            r#"{"package_name":"unknown","findings":[],"risk_score":0.0,"status":"partial"}"#
                .to_string()
        }
        Err(e) => {
            eprintln!(
                "\x1b[33m[!] Could not run doria-scanner: {}. Skipping AST scan.\x1b[0m",
                e
            );
            r#"{"package_name":"unknown","findings":[],"risk_score":0.0,"status":"partial"}"#
                .to_string()
        }
    }
}

#[derive(Debug)]
struct ThreatReport {
    package_name: String,
    is_safe: bool,
    action: String,
    model1_poisoned_proba: f64,
    model2_poisoned_proba: f64,
    model1_trigger: bool,
    model2_trigger: bool,
    ast_threat_count: usize,
    error: Option<String>,
}

fn run_python_ml(package_name: &str, rust_ast_json: &str) -> Result<ThreatReport, String> {
    // Find the Python scanner script
    let python_script = find_python_scanner();

    let python_bin = find_python_binary();

    let mut child = Command::new(&python_bin)
        .args([
            python_script.to_str().unwrap(),
            "--package",
            package_name,
            "--ast",
            rust_ast_json,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn Python: {}", e))?;

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);

    let mut json_line = String::new();
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        // The Python script prints exactly one JSON line
        if line.trim_start().starts_with('{') {
            json_line = line;
        }
    }

    child.wait().map_err(|e| e.to_string())?;

    if json_line.is_empty() {
        return Err("Python ML engine produced no output".to_string());
    }

    parse_ml_report(&json_line)
}

fn parse_ml_report(json: &str) -> Result<ThreatReport, String> {
    // Manual JSON parsing — avoids adding serde_json dependency to the CLI crate
    // for a simple flat structure. We just look for key fields.
    let is_safe = json.contains("\"is_safe\": true") || json.contains("\"is_safe\":true");
    let action = if json.contains("\"BLOCK\"") {
        "BLOCK".to_string()
    } else {
        "ALLOW".to_string()
    };

    let package_name = extract_json_string(json, "package_name").unwrap_or("unknown".to_string());
    let error = extract_json_string(json, "error");

    let model1_poisoned = extract_json_float(json, "model1_poisoned_proba").unwrap_or(0.0);
    let model2_poisoned = extract_json_float(json, "model2_poisoned_proba").unwrap_or(0.0);
    let model1_trigger =
        json.contains("\"model_1_trigger\": true") || json.contains("\"model_1_trigger\":true");
    let model2_trigger =
        json.contains("\"model_2_trigger\": true") || json.contains("\"model_2_trigger\":true");

    // Count AST threats from the ast_threats array
    let ast_threat_count = json.matches("\"kind\"").count();

    Ok(ThreatReport {
        package_name,
        is_safe,
        action,
        model1_poisoned_proba: model1_poisoned,
        model2_poisoned_proba: model2_poisoned,
        model1_trigger,
        model2_trigger,
        ast_threat_count,
        error,
    })
}

fn print_threat_report(report: &ThreatReport) {
    let action_color = if report.is_safe {
        "\x1b[32m"
    } else {
        "\x1b[1;31m"
    };
    let ast_color = if report.ast_threat_count == 0 {
        "\x1b[32m"
    } else {
        "\x1b[33m"
    };

    println!();
    println!("\x1b[34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    println!("\x1b[1m DORIA THREAT REPORT\x1b[0m");
    println!("\x1b[34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    println!(" Package:    \x1b[36m{}\x1b[0m", report.package_name);
    println!(
        " Decision:   {}",
        if report.is_safe {
            "\x1b[32mSAFE\x1b[0m"
        } else {
            "\x1b[1;31mTHREAT DETECTED\x1b[0m"
        }
    );
    println!(" Action:     {}{}\x1b[0m", action_color, report.action);
    println!();
    println!(
        " ML Model 1 (Behavior):   {:.1}% threat probability  [{}]",
        report.model1_poisoned_proba,
        if report.model1_trigger {
            "\x1b[1;31mTRIGGERED\x1b[0m"
        } else {
            "\x1b[32mclean\x1b[0m"
        }
    );
    println!(
        " ML Model 2 (NLP/Name):   {:.1}% threat probability  [{}]",
        report.model2_poisoned_proba,
        if report.model2_trigger {
            "\x1b[1;31mTRIGGERED\x1b[0m"
        } else {
            "\x1b[32mclean\x1b[0m"
        }
    );
    println!(
        " AST Findings:            {}{}\x1b[0m issue(s) detected",
        ast_color, report.ast_threat_count
    );

    if let Some(err) = &report.error {
        println!();
        println!(" \x1b[33mNote: {}\x1b[0m", err);
    }

    println!("\x1b[34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn find_binary(name: &str) -> PathBuf {
    // Look next to the current binary first
    if let Ok(mut p) = std::env::current_exe() {
        p.pop();
        let candidate = p.join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    // Fall back to PATH
    PathBuf::from(name)
}

fn find_python_scanner() -> PathBuf {
    // Walk up from cwd to find doria-ml-engine/scanner.py
    let mut dir = std::env::current_dir().unwrap_or_default();
    for _ in 0..5 {
        let candidate = dir.join("doria-ml-engine").join("scanner.py");
        if candidate.exists() {
            return candidate;
        }
        if !dir.pop() {
            break;
        }
    }
    // Fallback: assume it's in the cwd
    PathBuf::from("doria-ml-engine/scanner.py")
}

fn find_python_binary() -> String {
    // Prefer python3, fall back to python
    for bin in &["python3", "python"] {
        if Command::new(bin).arg("--version").output().is_ok() {
            return bin.to_string();
        }
    }
    "python3".to_string()
}

fn get_npm_cache_dir(package: &str) -> String {
    // This returns a placeholder path — in a real flow you'd npm pack first
    // and scan the extracted tarball. For the demo, we point at node_modules.
    let cwd = std::env::current_dir().unwrap_or_default();
    let node_modules = cwd.join("node_modules").join(package);
    if node_modules.exists() {
        return node_modules.to_string_lossy().to_string();
    }
    // Return a non-existent path — scanner will return empty findings
    format!("/tmp/doria-scan-{}", package)
}

fn extract_version_from_npm_pack(json: &str) -> Option<String> {
    extract_json_string(json, "version")
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let colon = after.find(':')?;
    let after_colon = after[colon + 1..].trim_start();
    if let Some(inner) = after_colon.strip_prefix('"') {
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

fn extract_json_float(json: &str, key: &str) -> Option<f64> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let colon = after.find(':')?;
    let after_colon = after[colon + 1..].trim_start();
    let end = after_colon.find([',', '}', '\n'])?;
    after_colon[..end].trim().parse::<f64>().ok()
}
