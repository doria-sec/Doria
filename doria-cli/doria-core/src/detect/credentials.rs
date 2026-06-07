use doria_types::{Finding, FindingKind, Location, Severity};
use swc_core::ecma::ast::*;
use swc_core::ecma::visit::{Visit, VisitWith};

/// Sensitive file paths that should never be read by a package
const SENSITIVE_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".npmrc",
    ".gitconfig",
    ".netrc",
    ".gnupg",
    "/etc/passwd",
    "/etc/shadow",
    "id_rsa",
    "id_ed25519",
    "credentials",
    ".env",
];

/// Environment variable patterns that indicate credential harvesting
const SENSITIVE_ENV_PATTERNS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "API_KEY",
    "PRIVATE_KEY",
    "AWS_ACCESS",
    "AWS_SECRET",
    "GITHUB_TOKEN",
    "NPM_TOKEN",
    "DATABASE_URL",
    "AUTH",
];

pub struct CredentialsDetector {
    pub findings: Vec<Finding>,
    pub file: String,
    pub package_name: String,
    pub package_version: String,
}

impl CredentialsDetector {
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
            id: format!("doria-cred-{:03}", self.findings.len() + 1),
            kind: FindingKind::CredentialAccess,
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

    /// Check if a string literal references a sensitive file path
    fn check_sensitive_path(&mut self, value: &str, line: u32) {
        for path in SENSITIVE_PATHS {
            if value.contains(path) {
                self.add_finding(
                    line,
                    format!(
                        "Sensitive file path '{}' referenced in string literal",
                        path
                    ),
                    Some(value.to_string()),
                    0.90,
                );
                return;
            }
        }
    }

    /// Check if an env var name matches a sensitive pattern
    fn check_sensitive_env(&mut self, value: &str, line: u32) {
        for pattern in SENSITIVE_ENV_PATTERNS {
            if value.to_uppercase().contains(pattern) {
                self.add_finding(
                    line,
                    format!("Sensitive environment variable '{}' accessed", value),
                    Some(format!("process.env.{}", value)),
                    0.85,
                );
                return;
            }
        }
    }
}

impl Visit for CredentialsDetector {
    /// Scan all string literals for sensitive file paths
    fn visit_lit(&mut self, lit: &Lit) {
        if let Lit::Str(s) = lit {
            self.check_sensitive_path(s.value.as_ref(), s.span.lo.0);
        }
        lit.visit_children_with(self);
    }

    /// Detects: process.env.AWS_SECRET_KEY
    fn visit_member_expr(&mut self, member: &MemberExpr) {
        // Check for process.env.SOMETHING
        if let Expr::Member(inner) = member.obj.as_ref() {
            if let Expr::Ident(obj) = inner.obj.as_ref() {
                if let MemberProp::Ident(prop) = &inner.prop {
                    if obj.sym.as_ref() == "process" && prop.sym.as_ref() == "env" {
                        if let MemberProp::Ident(env_var) = &member.prop {
                            self.check_sensitive_env(env_var.sym.as_ref(), member.span.lo.0);
                        }
                    }
                }
            }
        }

        member.visit_children_with(self);
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

        let mut detector = CredentialsDetector::new(
            "test.js".to_string(),
            "test-pkg".to_string(),
            "1.0.0".to_string(),
        );
        detector.visit_module(&module);
        detector.findings
    }

    #[test]
    fn test_detects_ssh_key_path() {
        let code = r#"
            const fs = require('fs');
            fs.readFileSync('/home/user/.ssh/id_rsa');
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].kind, FindingKind::CredentialAccess);
    }

    #[test]
    fn test_detects_aws_credentials() {
        let code = r#"
            const fs = require('fs');
            fs.readFileSync('/home/user/.aws/credentials');
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detects_env_token() {
        let code = r#"
            const token = process.env.GITHUB_TOKEN;
        "#;
        let findings = detect_in_js(code);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].kind, FindingKind::CredentialAccess);
    }

    #[test]
    fn test_detects_aws_secret_env() {
        let code = r#"
            const secret = process.env.AWS_SECRET_ACCESS_KEY;
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
