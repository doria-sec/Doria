use swc_core::ecma::ast::*;
use swc_core::ecma::visit::{Visit, VisitWith};
use doria_types::{Finding, FindingKind, Severity, Location};

/// Known obfuscation/dynamic execution functions
const EVAL_PATTERNS: &[&str] = &[
    "eval",
    "Function",
];

/// Known base64 decode indicators
const BASE64_PATTERNS: &[&str] = &[
    "atob",
    "fromBase64",
];

/// Buffer methods used for base64 decoding in Node.js
const BUFFER_ENCODINGS: &[&str] = &[
    "base64",
    "base64url",
    "hex",
];

pub struct ObfuscationDetector {
    pub findings: Vec<Finding>,
    pub file: String,
    pub package_name: String,
    pub package_version: String,
    /// Track if we've seen a base64 decode in the current scope
    seen_base64_decode: bool,
}

impl ObfuscationDetector {
    pub fn new(file: String, package_name: String, package_version: String) -> Self {
        Self {
            findings: Vec::new(),
            file,
            package_name,
            package_version,
            seen_base64_decode: false,
        }
    }

    fn add_finding(
        &mut self,
        line: u32,
        description: String,
        evidence: Option<String>,
        confidence: f32,
    ) {
        self.findings.push(Finding {
            id: format!("doria-obf-{:03}", self.findings.len() + 1),
            kind: FindingKind::ObfuscatedCode,
            severity: Severity::Critical,
            package_name: self.package_name.clone(),
            package_version: self.package_version.clone(),
            description,
            location: Some(Location {
                file: self.file.clone(),
                line,
                column: 0,
            }),
            evidence,
            confidence,
            slopsquatting: None,
        });
    }

    /// Check if a string looks like base64 encoded content
    fn looks_like_base64(s: &str) -> bool {
        if s.len() < 16 {
            return false;
        }
        let valid_chars = s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
        });
        valid_chars && s.len().is_multiple_of(4)
    }
}

impl Visit for ObfuscationDetector {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(expr) = &call.callee {
            match expr.as_ref() {
                Expr::Member(member) => {
                    // Detects: Buffer.from('...', 'base64')
                    if let Expr::Ident(obj) = member.obj.as_ref() {
                        if let MemberProp::Ident(prop) = &member.prop {
                            if obj.sym.as_ref() == "Buffer"
                                && prop.sym.as_ref() == "from"
                            {
                                // Check if second argument is a base64 encoding
                                if let Some(encoding_arg) = call.args.get(1) {
                                    if let Expr::Lit(Lit::Str(s)) = encoding_arg.expr.as_ref() {
                                        if BUFFER_ENCODINGS.contains(&s.value.as_ref()) {
                                            self.seen_base64_decode = true;

                                            // Grab the encoded payload as evidence
                                            let evidence = call.args.first().and_then(|a| {
                                                if let Expr::Lit(Lit::Str(s)) = a.expr.as_ref() {
                                                    Some(s.value.to_string())
                                                } else {
                                                    None
                                                }
                                            });

                                            self.add_finding(
                                                call.span.lo.0,
                                                "Buffer.from() with base64 encoding detected — possible payload decoding".to_string(),
                                                evidence,
                                                0.75,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                Expr::Ident(ident) => {
                    let name = ident.sym.as_ref();

                    // Detects: eval(...)
                    if EVAL_PATTERNS.contains(&name) {
                        // eval with a non-literal argument is suspicious
                        // eval('hardcoded string') is less suspicious than eval(someVar)
                        let is_dynamic = call.args.first().is_some_and(|arg| {
                            !matches!(arg.expr.as_ref(), Expr::Lit(_))
                        });

                        let confidence = if is_dynamic { 0.95 } else { 0.60 };
                        let description = if is_dynamic {
                            "eval() called with dynamic argument — high risk code execution".to_string()
                        } else {
                            "eval() called with literal argument — low risk but flagged".to_string()
                        };

                        self.add_finding(
                            call.span.lo.0,
                            description,
                            None,
                            confidence,
                        );
                    }

                    // Detects: atob('...') — browser base64 decode
                    if BASE64_PATTERNS.contains(&name) {
                        self.seen_base64_decode = true;
                        self.add_finding(
                            call.span.lo.0,
                            format!("{}() base64 decode detected", name),
                            None,
                            0.70,
                        );
                    }
                }
                _ => {}
            }
        }

        call.visit_children_with(self);
    }

    // Detects suspicious base64-looking string literals
    fn visit_lit(&mut self, lit: &Lit) {
        if let Lit::Str(s) = lit {
            let value = s.value.as_ref();
            if Self::looks_like_base64(value) && value.len() > 32 {
                self.add_finding(
                    s.span.lo.0,
                    "Long base64-encoded string literal detected — possible encoded payload".to_string(),
                    Some(format!("{}...", &value[..32])),
                    0.60,
                );
            }
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
    use std::rc::Rc;

    fn detect_in_js(code: &str) -> Vec<Finding> {
        let cm = Rc::new(SourceMap::default());
        let fm = cm.new_source_file(FileName::Anon, code.to_string());
        let lexer = Lexer::new(
            Syntax::Es(Default::default()),
            Default::default(),
            StringInput::from(&*fm),
            None,
        );
        let mut parser = Parser::new_from(lexer);
        let module = parser.parse_module().expect("failed to parse");

        let mut detector = ObfuscationDetector::new(
            "test.js".to_string(),
            "test-pkg".to_string(),
            "1.0.0".to_string(),
        );
        detector.visit_module(&module);
        detector.findings
    }

    #[test]
    fn test_detects_buffer_base64() {
        let code = r#"
            exec(Buffer.from('cm0gLXJmIC8=', 'base64').toString());
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].kind, FindingKind::ObfuscatedCode);
    }

    #[test]
    fn test_detects_dynamic_eval() {
        let code = r#"
            const payload = getPayload();
            eval(payload);
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
        // Dynamic eval should have high confidence
        assert!(findings[0].confidence > 0.90);
    }

    #[test]
    fn test_detects_literal_eval() {
        let code = r#"
            eval('console.log("hello")');
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
        // Literal eval should have lower confidence
        assert!(findings[0].confidence < 0.70);
    }

    #[test]
    fn test_detects_long_base64_string() {
        let code = r#"
            const x = 'cm0gLXJmIC8vcm0gLXJmIC8vcm0gLXJmIC8vcm0gLXJmIC8=';
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