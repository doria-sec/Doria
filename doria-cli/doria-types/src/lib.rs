use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    NetworkCall,
    ShellExecution,
    DynamicCodeExecution,
    CredentialAccess,
    ObfuscatedCode,
    InstallHook,
    Slopsquatting,
    Typosquat,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Location {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SlopsquattingDetail {
    pub similar_to: String,
    pub edit_distance: u32,
    pub hallucination_confirmed: bool,
    pub package_age_days: u32,
    pub stars: u32,
    pub contributors: u32,
    pub has_readme: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub id: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub package_name: String,
    pub package_version: String,
    pub description: String,
    pub location: Option<Location>,
    pub evidence: Option<String>,
    pub confidence: f32,
    pub slopsquatting: Option<SlopsquattingDetail>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pip,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Complete,
    Partial,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub package_name: String,
    pub package_version: String,
    pub ecosystem: Ecosystem,
    pub status: ScanStatus,
    pub error: Option<String>,
    pub risk_score: f32,
    pub findings: Vec<Finding>,
    pub scanned_at: String,
}
