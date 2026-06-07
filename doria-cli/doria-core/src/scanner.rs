use std::fs;
use std::path::Path;

use std::rc::Rc;
use swc_core::common::{FileName, SourceMap};
use swc_core::ecma::parser::{lexer::Lexer, Parser, StringInput, Syntax};
use swc_core::ecma::visit::Visit;

use crate::detect::credentials::CredentialsDetector;
use crate::detect::hooks::HooksDetector;
use crate::detect::network::NetworkDetector;
use crate::detect::obfuscation::ObfuscationDetector;
use crate::detect::shell::ShellDetector;
use doria_types::{Ecosystem, Finding, ScanResult, ScanStatus};

/// Scan a single JS file and return all findings from all detectors
fn scan_js_file(path: &str, code: &str, package_name: &str, package_version: &str) -> Vec<Finding> {
    let cm = Rc::new(SourceMap::default());
    let fm = cm.new_source_file(FileName::Anon, code.to_string());
    let lexer = Lexer::new(
        Syntax::Es(Default::default()),
        Default::default(),
        StringInput::from(&*fm),
        None,
    );
    let mut parser = Parser::new_from(lexer);

    let module = match parser.parse_module() {
        Ok(m) => m,
        Err(_) => return vec![], // unparseable file — skip silently
    };

    let mut findings = Vec::new();

    // Run all detectors
    let mut shell = ShellDetector::new(
        path.to_string(),
        package_name.to_string(),
        package_version.to_string(),
    );
    shell.visit_module(&module);
    findings.extend(shell.findings);

    let mut network = NetworkDetector::new(
        path.to_string(),
        package_name.to_string(),
        package_version.to_string(),
    );
    network.visit_module(&module);
    findings.extend(network.findings);

    let mut obfuscation = ObfuscationDetector::new(
        path.to_string(),
        package_name.to_string(),
        package_version.to_string(),
    );

    obfuscation.visit_module(&module);
    findings.extend(obfuscation.findings);

    let mut credentials = CredentialsDetector::new(
        path.to_string(),
        package_name.to_string(),
        package_version.to_string(),
    );
    credentials.visit_module(&module);
    findings.extend(credentials.findings);

    let mut hooks = HooksDetector::new(
        path.to_string(),
        package_name.to_string(),
        package_version.to_string(),
    );
    hooks.visit_module(&module);
    findings.extend(hooks.findings);

    findings
}

/// Compute an aggregate risk score from a list of findings
/// Returns a value between 0.0 and 1.0
fn compute_risk_score(findings: &[Finding]) -> f32 {
    if findings.is_empty() {
        return 0.0;
    }

    let max_score: f32 = findings
        .iter()
        .map(|f| {
            let severity_weight = match f.severity {
                doria_types::Severity::Critical => 1.0,
                doria_types::Severity::High => 0.75,
                doria_types::Severity::Medium => 0.50,
                doria_types::Severity::Low => 0.25,
                doria_types::Severity::Info => 0.10,
            };
            severity_weight * f.confidence
        })
        .fold(0.0_f32, f32::max);

    max_score
}

/// Scan an entire package directory and return a ScanResult
pub fn scan_package(
    package_dir: &str,
    package_name: &str,
    package_version: &str,
    ecosystem: Ecosystem,
) -> ScanResult {
    let dir = Path::new(package_dir);

    if !dir.exists() {
        return ScanResult {
            package_name: package_name.to_string(),
            package_version: package_version.to_string(),
            ecosystem,
            status: ScanStatus::Failed,
            error: Some(format!(
                "Package directory '{}' does not exist",
                package_dir
            )),
            risk_score: 0.0,
            findings: vec![],
            scanned_at: chrono::Utc::now().to_rfc3339(),
        };
    }

    let mut all_findings = Vec::new();
    let mut had_error = false;

    // Walk the directory recursively
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        // Only scan JS files for now
        let is_js = path
            .extension()
            .map(|e| e == "js" || e == "mjs" || e == "cjs")
            .unwrap_or(false);

        if !is_js {
            continue;
        }

        let code = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                had_error = true;
                continue;
            }
        };

        let path_str = path.to_string_lossy().to_string();
        let findings = scan_js_file(&path_str, &code, package_name, package_version);
        all_findings.extend(findings);
    }

    let risk_score = compute_risk_score(&all_findings);
    let status = if had_error {
        ScanStatus::Partial
    } else {
        ScanStatus::Complete
    };

    ScanResult {
        package_name: package_name.to_string(),
        package_version: package_version.to_string(),
        ecosystem,
        status,
        error: None,
        risk_score,
        findings: all_findings,

        scanned_at: chrono::Utc::now().to_rfc3339(),
    }
}
