# ReconX

ReconX is a lightweight Python-based reconnaissance and security assessment CLI tool designed to help identify exposed services, web security issues, and potential misconfigurations.

## Features

- TCP Port Scanning
- Basic Service Detection
- HTTP Analysis
- Security Header Analysis
- Local File Inclusion (LFI) Detection
- Directory Scanning
- Exposed File Detection
- Aggregate Security Scanning
- JSON and CSV Report Export
- Scan Summary and Severity Counts

## Requirements

- Kali Linux or another Linux distribution
- Python 3
- pipx
- Git

## Installation

### Method 1: Install using pipx (Recommended)

```bash
pipx install git+https://github.com/AVINASH-0411/reconx.git
```

### Method 2: Install using Git

```bash
git clone https://github.com/AVINASH-0411/reconx.git
cd reconx
pipx install .
```

### Force Reinstall

If ReconX is already installed and you want to reinstall it from GitHub:

```bash
pipx install --force git+https://github.com/AVINASH-0411/reconx.git
```

### Verify Installation

```bash
reconx --version
reconx --help
```

## Usage

Replace the example targets with systems you own or have permission to assess.

### 1. TCP Port Scanner

```bash
reconx 127.0.0.1
reconx example.com
```

Scan specific ports:

```bash
reconx -p 80 example.com
reconx example.com -p 80
reconx example.com -p 22,80,443
reconx example.com -p 1-1000
```

### 2. Aggregate Scan

Run the combined scan:

```bash
reconx -a example.com
reconx -a example.com -p 80,443
```

### 3. HTTP Analyzer

```bash
reconx web https://example.com
```

Analyzes HTTP response details, redirects, HTTPS availability, response time, and security headers.

### 4. LFI Detector

```bash
reconx lfi "https://authorized-target.example/page?file=test"
```

Export results:

```bash
reconx lfi "https://authorized-target.example/page?file=test" -o lfi-results.json
reconx lfi "https://authorized-target.example/page?file=test" -o lfi-results.csv
```

### 5. Directory Scanner

```bash
reconx dir https://authorized-target.example -w wordlist.txt
```

Set the number of threads:

```bash
reconx dir https://authorized-target.example -w wordlist.txt -t 20
```

Check file extensions:

```bash
reconx dir https://authorized-target.example -w wordlist.txt -x php,txt,bak
```

Filter status codes:

```bash
reconx dir https://authorized-target.example -w wordlist.txt -s 200,301,403
```

Save results:

```bash
reconx dir https://authorized-target.example -w wordlist.txt -o directory-results.json
```

### 6. Exposed File Detection

```bash
reconx files https://authorized-target.example
```

Save results:

```bash
reconx files https://authorized-target.example -o exposed-files.json
reconx files https://authorized-target.example -o exposed-files.csv
```

### 7. Export Scan Reports

Save port scan results:

```bash
reconx example.com -p 80,443 -o report.json
reconx example.com -p 80,443 -o report.csv
```

## Help Commands

```bash
reconx --help
reconx web --help
reconx lfi --help
reconx dir --help
reconx files --help
```

## Version

```bash
reconx --version
```

## Responsible Use

ReconX is intended for authorized security testing and defensive security assessments. Only scan systems for which you have explicit permission. The user is responsible for complying with applicable laws and organizational policies.

## License

See the repository's license file for licensing terms.
