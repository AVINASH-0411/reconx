# ReconX

**ReconX** is a lightweight Python-based reconnaissance and security assessment CLI tool designed to help identify exposed network services, analyze web security configurations, and detect potential security issues.

It brings multiple reconnaissance and security assessment capabilities together through a single command-line interface.

## Features

- **TCP Port Scanning** – Scan default, selected, or full TCP port ranges.
- **Basic Service Detection** – Identify services running on discovered open ports.
- **HTTP Analysis** – Analyze HTTP responses and related information.
- **Security Header Analysis** – Inspect HTTP security headers.
- **Local File Inclusion (LFI) Detection** – Test for potential file inclusion vulnerabilities.
- **Directory Scanning** – Discover accessible directories and resources.
- **Exposed File Detection** – Check for potentially exposed files.
- **Aggregate Security Scanning** – Run combined security assessment checks.
- **JSON and CSV Report Export** – Save scan results in structured formats.
- **Scan Summary and Severity Counts** – Display findings and severity summaries.

## Requirements

- Kali Linux or another Linux distribution
- Python 3
- pipx
- Git

## Installation

### Method 1: Install using pipx (Recommended)

Install ReconX directly from GitHub:

```bash
pipx install git+https://github.com/AVINASH-0411/reconx.git
```

### Method 2: Install using Git

Clone the repository:

```bash
git clone https://github.com/AVINASH-0411/reconx.git
```

Navigate to the project directory:

```bash
cd reconx
```

Install ReconX:

```bash
pipx install .
```

### Force Reinstall

If ReconX is already installed and you want to reinstall it from GitHub:

```bash
pipx install --force git+https://github.com/AVINASH-0411/reconx.git
```

### Verify Installation

Check the installed version and available commands:

```bash
reconx --version
reconx --help
```

## Usage

Replace the example targets with systems you own or have explicit permission to assess.

### 1. TCP Port Scanner

Scan a target using the default port configuration:

```bash
reconx 127.0.0.1
reconx example.com
```

**Scan all TCP ports (1–65535):**

```bash
reconx -p- 127.0.0.1
reconx -p- example.com
```

**Scan specific ports:**

```bash
reconx -p 80 example.com
reconx example.com -p 80
reconx -p 22,80,443 example.com
```

**Scan a port range:**

```bash
reconx -p 1-1000 example.com
```

### 2. Aggregate Scan

Run the combined security scan:

```bash
reconx -a example.com
```

Specify ports for the aggregate scan:

```bash
reconx -a example.com -p 80,443
```

### 3. HTTP Analyzer

Analyze an HTTP target:

```bash
reconx web https://example.com
```

The HTTP analyzer examines response details, redirects, HTTPS availability, response time, and security headers.

### 4. LFI Detector

Test an authorized web application endpoint:

```bash
reconx lfi "https://authorized-target.example/page?file=test"
```

**Export results as JSON:**

```bash
reconx lfi "https://authorized-target.example/page?file=test" -o lfi-results.json
```

**Export results as CSV:**

```bash
reconx lfi "https://authorized-target.example/page?file=test" -o lfi-results.csv
```

### 5. Directory Scanner

Scan directories on an authorized target using a wordlist:

```bash
reconx dir https://authorized-target.example -w wordlist.txt
```

**Set the number of threads:**

```bash
reconx dir https://authorized-target.example -w wordlist.txt -t 20
```

**Check file extensions:**

```bash
reconx dir https://authorized-target.example -w wordlist.txt -x php,txt,bak
```

**Filter HTTP status codes:**

```bash
reconx dir https://authorized-target.example -w wordlist.txt -s 200,301,403
```

**Save scan results:**

```bash
reconx dir https://authorized-target.example -w wordlist.txt -o directory-results.json
```

### 6. Exposed File Detection

Check an authorized web application for potentially exposed files:

```bash
reconx files https://authorized-target.example
```

**Export results as JSON:**

```bash
reconx files https://authorized-target.example -o exposed-files.json
```

**Export results as CSV:**

```bash
reconx files https://authorized-target.example -o exposed-files.csv
```

### 7. Export Scan Reports

Save TCP port scan results in JSON format:

```bash
reconx example.com -p 80,443 -o report.json
```

Save TCP port scan results in CSV format:

```bash
reconx example.com -p 80,443 -o report.csv
```

## Help Commands

View the main help menu:

```bash
reconx --help
```

View help for individual modules:

```bash
reconx web --help
reconx lfi --help
reconx dir --help
reconx files --help
```

## Version

Check the installed ReconX version:

```bash
reconx --version
```

## Responsible Use

ReconX is intended for authorized security testing and defensive security assessments.

- Only scan systems for which you have explicit permission.
- Perform security assessments within an authorized scope.
- Follow applicable laws and organizational security policies.
- Use the tool responsibly and avoid disrupting services or systems.

The user is responsible for ensuring that all security testing is properly authorized.

## License

Copyright (c) 2026 Avinash. All rights reserved.

This repository is publicly available for viewing and cloning.
No permission is granted to use, modify, redistribute, or
incorporate this code into other projects without prior
written permission from the copyright holder.
