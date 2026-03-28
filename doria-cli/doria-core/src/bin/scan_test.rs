use std::fs;
use doria_core::detect::shell::ShellDetector;
use swc_core::ecma::parser::{lexer::Lexer, Parser, StringInput, Syntax};
use swc_core::common::{SourceMap, FileName};
use swc_core::ecma::visit::Visit;
use std::rc::Rc;

fn main() {
    let path = std::env::args().nth(1).expect("pass a js file as argument");
    let code = fs::read_to_string(&path).expect("could not read file");

    let cm = Rc::new(SourceMap::default());
    let fm = cm.new_source_file(FileName::Anon, code);
    let lexer = Lexer::new(
        Syntax::Es(Default::default()),
        Default::default(),
        StringInput::from(&*fm),
        None,
    );
    let mut parser = Parser::new_from(lexer);
    let module = parser.parse_module().expect("failed to parse");

    let mut detector = ShellDetector::new(
        path.clone(),
        "test-pkg".to_string(),
        "1.0.0".to_string(),
    );
    detector.visit_module(&module);

    // ANSI color codes
    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[33m";
    const CYAN: &str = "\x1b[36m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";

    if detector.findings.is_empty() {
        println!("{GREEN}{BOLD}CLEAN{RESET} — no findings detected in {path}");
    } else {
        println!(
            "{RED}{BOLD}FINDINGS{RESET} — {} issue(s) detected in {CYAN}{path}{RESET}\n",
            detector.findings.len()
        );
        for f in &detector.findings {
            println!(
                "  {BOLD}[{:?}]{RESET} {YELLOW}{:?}{RESET}",
                f.severity, f.kind
            );
            println!("  {}", f.description);
            if let Some(loc) = &f.location {
                println!("  {CYAN}{}:{}{RESET}", loc.file, loc.line);
            }
            println!();
        }
    }
}