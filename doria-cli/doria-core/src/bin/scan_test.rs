use doria_core::scanner::scan_package;
use doria_types::Ecosystem;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: scan_test <package_dir>");
    let name = std::env::args().nth(2).unwrap_or("unknown".to_string());
    let version = std::env::args().nth(3).unwrap_or("0.0.0".to_string());

    // ANSI colors
    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[33m";
    const CYAN: &str = "\x1b[36m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";

    let result = scan_package(&path, &name, &version, Ecosystem::Npm);

    println!();
    println!("{BOLD}DORIA SCAN RESULT{RESET}");
    println!(
        "{CYAN}package:{RESET}   {}@{}",
        result.package_name, result.package_version
    );
    println!("{CYAN}status:{RESET}    {:?}", result.status);
    println!("{CYAN}risk:{RESET}      {:.2}", result.risk_score);
    println!("{CYAN}scanned:{RESET}   {}", result.scanned_at);
    println!();

    if result.findings.is_empty() {
        println!("{GREEN}{BOLD}CLEAN{RESET} — no findings detected");
    } else {
        println!(
            "{RED}{BOLD}FINDINGS{RESET} — {} issue(s) detected\n",
            result.findings.len()
        );
        for f in &result.findings {
            println!(
                "  {BOLD}[{:?}]{RESET} {YELLOW}{:?}{RESET} — confidence: {:.2}",
                f.severity, f.kind, f.confidence
            );
            println!("  {}", f.description);
            if let Some(loc) = &f.location {
                println!("  {CYAN}{}:{}{RESET}", loc.file, loc.line);
            }
            if let Some(evidence) = &f.evidence {
                println!("  evidence: {}", evidence);
            }
            println!();
        }
    }
}
