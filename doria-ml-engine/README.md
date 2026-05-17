# Doria ML Engine

## Overview
Doria is an autonomous, AI-powered supply chain security agent designed to intercept and neutralize malicious open-source packages at the exact moment of installation. While traditional security tools rely on reactive CVE databases, Doria operates proactively. It utilizes a dual-model Machine Learning architecture to catch both traditional typosquatting attacks and novel "slopsquatting" vulnerabilities malicious packages registered under names predictably hallucinated by AI coding assistants.

This repository contains the Python-based Machine Learning Backend (The Intelligence), which acts as the analytical core of the Doria architecture. It evaluates package metadata and nomenclature, returning a deterministic threat report to the system's Rust-based static analysis scanner and React dashboard.

## System Architecture: The Dual-Model Pipeline

The Doria ML Engine bypasses the "Accuracy Paradox" common in cybersecurity datasets by utilizing a Defense-in-Depth strategy. It relies on two isolated Extreme Gradient Boosting (XGBoost) models that evaluate completely different risk vectors.

### Model 1: Behavioral & Metadata Anomalies
Analyzes registry metadata to detect suspicious publishing patterns.
* **Features Extracted:** Package age, maintainer account age, user count, number of active maintainers, documentation presence, version history, and repository validation.
* **Objective:** Catch compromised maintainer accounts, zero-day malware dumps, and packages attempting to hide their source code.

### Model 2: Natural Language Processing (NLP) & Naming Risk
Analyzes the package nomenclature against top downloaded packages to detect deception.
* **Features Extracted:** Levenshtein distance, homoglyph substitution detection, underscore/hyphen manipulation, prefix/suffix trickery, and conflation patterns.
* **Objective:** Catch traditional typosquatting and AI-generated slopsquatting hallucinations before they are installed.

## Project Structure & Workflow

The engine is modularized into distinct operational phases:

### 1. Data Ingestion (The Harvesters)
* **`harvester.py`**: Interacts with the NPM registry to download live metadata for top safe packages and generates theoretical typosquats to probe the registry for active threats.
* **`historical_harvester.py`**: Specifically hunts for "golden records" of known historical malware that have not yet been purged by NPM security placeholders.

### 2. Feature Engineering (The Translators)
* **`similarity.py`**: The NLP math engine. Calculates textual distances and detects obfuscation techniques between the scanned package and known safe packages.
* **`calculate_score.py`**: The metadata extraction engine. Parses raw JSON registry data, calculates time-deltas (e.g., age in days), validates repository links, and merges the NLP features into final training matrices (`model1_features.csv` and `model2_features.csv`).

### 3. Model Training
* **`train_model.py`**: Ingests the feature matrices, executes an 80/20 train-test split, and trains the dual XGBoost classifiers. It outputs precision/recall classification reports to the terminal to validate performance and serializes the trained models as `model1_behavior.json` and `model2_nlp.json`.

### 4. Inference & Integration (The Bridge)
* **`scanner.py`**: The nervous system of the ML backend. It exposes the `scan_package()` function, which takes a single package JSON file, routes it through the feature extractors, requests probabilities from the XGBoost models, and applies an OR-gate logic to determine the final verdict. It returns a structured JSON threat report for the UI and Rust backend.

## Installation & Setup

Ensure you have Python 3.10+ installed. It is highly recommended to run this engine within an isolated virtual environment.

1.  **Clone the repository and navigate to the ML directory.**
2.  **Initialize a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Running a Manual Scan
To test the inference engine on a local package JSON file, you can execute the scanner directly. It is pre-configured to output the JSON threat report to the terminal.

```bash
python scanner.py

```

### Integration with External Systems

For teammates integrating the ML engine into the broader Doria ecosystem (e.g., the Rust CLI or React Dashboard), simply import the scanning function into your bridge layer.

```python
from scanner import scan_package

# Pass the path of the downloaded package JSON
threat_report = scan_package("path/to/downloaded/package.json")

```

**Expected JSON Contract:**

```json
{
    "package_name": "target_package",
    "is_safe": false,
    "threat_details": {
        "model1_safe_proba": 7.45,
        "model2_safe_proba": 3.36,
        "model1_poisoned_proba": 92.54,
        "model2_poisoned_proba": 96.63,
        "model_1_trigger": true,
        "model_2_trigger": true
    }
}

```

## Future Roadmap (V2 Enrichment Pipeline)

* **Velocity Tracking:** Implementation of the NPM Bulk Downloads API to calculate `weekly_download_spike` ratios to catch artificially inflated download counts.
* **Lineage Verification:** GitHub API integration to check the `is_fork` boolean, catching lazy attackers copying legitimate repositories.
* **Active Threat Hunting:** Autonomous generation of homoglyph permutations for top packages to preemptively discover unregistered slopsquats.



