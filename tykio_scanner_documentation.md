# Tykio Image Vulnerability Scanner

## Overview

This Bash script automates the process of finding and scanning Docker images from the Tykio organization for security vulnerabilities. The script uses Trivy (a container vulnerability scanner) to identify vulnerabilities and generates a consolidated CSV report.

## Key Features

- Automatically discovers Tykio Docker images
- Scans selected images for vulnerabilities using Trivy
- Consolidates duplicate vulnerabilities across images
- Generates a CSV report with comprehensive vulnerability information
- Sorts vulnerabilities by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
- Provides a summary of vulnerability counts by severity

## Prerequisites

- Docker (installed and running)
- jq (JSON processor)
- Python 3
- Internet connection

## Usage

```bash
./tykio_scanner.sh [options]
```

### Options

- `-o FILE` - Output CSV file (default: vulnerabilities.csv)
- `-l NUM` - Limit the number of images to scan (default: 3)
- `-h` - Display help message

### Example

```bash
./tykio_scanner.sh -o report.csv -l 5
```

## Output Format

The script generates a CSV file with the following columns:

1. **Package Name** - Name of the vulnerable package
2. **Severity** - Vulnerability severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
3. **Version** - Installed version of the package
4. **Fixed in Version** - Version that fixes the vulnerability
5. **Description** - Description of the vulnerability
6. **CVE ID** - Common Vulnerabilities and Exposures identifier
7. **Source** - List of image names where the vulnerability was found

If the same vulnerability appears in multiple images, it will be consolidated into a single entry with all affected image names in the Source column.

## Implementation Details

The script follows these steps:

1. **Image Discovery** - Uses Docker search to find Tykio images
2. **Vulnerability Scanning** - Uses Trivy to scan each image
3. **Data Processing** - Extracts vulnerability information from JSON output
4. **Consolidation** - Groups vulnerabilities by CVE ID
5. **Output Generation** - Creates a sorted CSV with consolidated vulnerabilities

## CSV Processing Logic

The script uses Python's CSV module to process vulnerability data, which ensures:

- Proper handling of quoted fields
- Fields containing commas are correctly processed
- Descriptions with special characters are properly sanitized
- Proper consolidation of sources for duplicate vulnerabilities
- Vulnerability sorting by severity

## Example Output

```
"Package Name","Severity","Version","Fixed in Version","Description","CVE ID","Source"
"openssl","CRITICAL","1.1.1k","1.1.1l","Buffer overflow in the TLS implementation","CVE-2022-0778","tykio/gateway,tykio/tyk-pump"
"glibc","HIGH","2.31-13","2.31-14","Integer overflow in malloc implementation","CVE-2021-3326","tykio/gateway"
```

## Vulnerability Summary

After processing, the script displays a summary of vulnerabilities by severity level and provides a total count of unique vulnerabilities found.