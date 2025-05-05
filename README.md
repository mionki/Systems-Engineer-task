# Tykio Image Vulnerability Scanner

## Overview
This Bash script automates the process of finding and scanning Docker images from the Tykio organization for security vulnerabilities. The script uses Trivy to identify vulnerabilities and generates a consolidated CSV report.

## Prerequisites
Please ensure these dependencies are installed for the script to run successfully.
- [Docker](https://docs.docker.com/get-docker/) (installed and running)
- [jq](https://stedolan.github.io/jq/download/) (JSON processor)
- [Python 3](https://www.python.org/downloads/) (version 3.6 or higher)

NB: This script requires Docker permissions to run correctly. If you encounter permission issues, either run the script with sudo or add your user to the Docker group with the command `sudo usermod -aG docker $USER`

## Key Features
- Automatically discovers Tykio Docker images
- Scans selected images for vulnerabilities using Trivy
- Consolidates duplicate vulnerabilities across images
- Generates a CSV report with comprehensive vulnerability information
- Sorts vulnerabilities by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
- Provides a summary of vulnerability counts by severity

## Usage
```bash
chmod +x tykio_scanner.sh
./tykio_scanner.sh [options]
```

## Options
- `-o FILE` - Output CSV file (default: vulnerabilities.csv)
- `-l NUM` - Limit the number of images to scan (default: 3)
- `-h` - Display help message

## Example
```bash
chmod +x tykio_scanner.sh
./tykio_scanner.sh -o report.csv -l 5
```

## Output Format
The script generates a CSV file with the following columns:

- **Package Name** - Name of the vulnerable package
- **Severity** - Vulnerability severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
- **Version** - Installed version of the package
- **Fixed in Version** - Version that fixes the vulnerability
- **Description** - Description of the vulnerability
- **CVE ID** - Common Vulnerabilities and Exposures identifier
- **Source** - List of image names where the vulnerability was found

If the same vulnerability appears in multiple images, it will be consolidated into a single entry with all affected image names in the Source column.