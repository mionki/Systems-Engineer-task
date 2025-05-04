#!/bin/bash

# Tykio image vulnerability scanner
# This script scans the Tykio image for known vulnerabilities using Trivy
# and creates a consolidated CSV of vulnerabilities across images

usage () {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo " -o --output FILE  Output CSV file (default: vulnerabilities.csv)"
    echo " -l --limit NUM    Limit the number of images to scan (default: 15)"
    echo " -h --help         Display this help message"
    echo "Example: $0 -o output.csv -l 10"
    exit 1
}

OUTPUT_FILE="vulnerabilities.csv"
IMAGE_LIMIT=3

while getopts ":o:l:h" opt; do
  case ${opt} in
    o )
      OUTPUT_FILE="$OPTARG"
      ;;
    l )
      IMAGE_LIMIT="$OPTARG"
      ;;
    h )
      usage
      ;;
    \? )
      echo "Invalid option: -$OPTARG" 1>&2
      usage
      ;;
    : )
      echo "Option -$OPTARG requires an argument" 1>&2
      usage
      ;;
  esac
done
shift $((OPTIND -1))

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker could not be found. Please install Docker to use this script."
    exit 1
fi

# Test if Docker is running 
if ! docker info &> /dev/null; then
    echo "Docker is not running. Please start and try again."
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq could not be found. Please install jq to process JSON data."
    exit 1
fi

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 could not be found. Please install Python 3 to process CSV data."
    exit 1
fi

# Create a temporary directory for the scan
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "Searching for Tykio images..."

find_tykio_images(){
    local limit=$1
    if docker search --help | grep -q "\-\-format"; then
        if docker search --format json busybox 2>/dev/null | grep -q "Name"; then
          docker search --limit 100 --format json tykio 2>/dev/null |
          jq -r '.[] | select(.Name | contains("tykio")) | .Name' 2>/dev/null |
          head -n "$limit" > "$TEMP_DIR/images.txt"

          if [ -s "$TEMP_DIR/images.txt" ]; then
            cat "$TEMP_DIR/images.txt"
            return 0
          fi
        fi
    fi

    # Fallback if JSON format is not available
    docker search --limit 100 tykio 2>/dev/null |
    grep "tykio" |
    awk '{print $1}' |
    head -n "$limit" 
}

# Get tykio images
echo "Finding Tykio images using docker search..."
TYKIO_IMAGES=($(find_tykio_images "$IMAGE_LIMIT"))

if [ ${#TYKIO_IMAGES[@]} -eq 0 ]; then
    echo "No Tykio images found."
    exit 1
fi

echo "Found ${#TYKIO_IMAGES[@]} Tykio images:"
printf "  - %s\n" "${TYKIO_IMAGES[@]}"

process_vulnerability_json() {
    local json_file="$1"
    local image_name="$2"
    local temp_output="$3"

    # This ensures proper handling of commas and quotes in all fields
    jq -r --arg image "$image_name" '
    .Results[] | 
    select(.Vulnerabilities != null) | 
    .Vulnerabilities[] | 
    {
      "PkgName": .PkgName,
      "Severity": .Severity,
      "Version": .InstalledVersion,
      "FixedVersion": (.FixedVersion // "N/A"),
      "Description": (.Description // "N/A" | gsub("[\\n\\r]"; " ") | gsub("\""; "''") | gsub(","; ";")),
      "CVE": .VulnerabilityID,
      "Source": $image
    } | 
    [.PkgName, .Severity, .Version, .FixedVersion, .Description, .CVE, .Source] | 
    @csv
    ' "$json_file" >> "$temp_output"
}

# Pull Trivy image 
echo "Pulling Trivy image..."
docker pull aquasec/trivy:latest

# Scan each Tykio image for vulnerabilities
SUCCESSFUL_SCANS=0

for image in "${TYKIO_IMAGES[@]}"; do
    echo "Scanning $image..."

    # Run Trivy scan with Docker
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$TEMP_DIR:/tmp/trivy-results" \
        -e TRIVY_TIMEOUT=10m \
        aquasec/trivy:latest \
        image --format json --no-progress "$image" > "$TEMP_DIR/${image//\//_}.json"
    
    if [ $? -ne 0 ]; then
        echo "Failed to scan $image. Skipping..."
        continue
    fi

    echo "Scan completed for $image."

    # Process the JSON output
    process_vulnerability_json "$TEMP_DIR/${image//\//_}.json" "$image" "$TEMP_DIR/all_vulns.csv"

    ((SUCCESSFUL_SCANS++))
done

echo "Scan completed for $SUCCESSFUL_SCANS images."
echo "Consolidating results..."

# Combine all results into a single CSV file
consolidate_vulnerabilities() {
    local input_file="$1"
    local output_file="$2"
    
    if [ ! -f "$input_file" ] || [ ! -s "$input_file" ]; then
        echo "No vulnerabilities found."
        echo "Package Name,Severity,Version,Fixed in Version,Description,CVE ID,Source" > "$output_file"
        return
    fi
    
    # Create header for the output file
    echo "Package Name,Severity,Version,Fixed in Version,Description,CVE ID,Source" > "$output_file"
    
    # Python-based CSV processing for better field handling
    python3 -c "
import csv
import sys
import re

# Initialize storage
vulnerabilities = {}
severity_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'UNKNOWN': 5}

# Read input CSV file
with open('$input_file', 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        if len(row) < 7:
            continue  
            
        pkg_name, severity, version, fixed_version, description, cve_id, source = row
        
        # Skip rows with empty CVE IDs (could be malformed data)
        if not cve_id:
            continue
            
        # Use CVE ID as key for deduplication
        if cve_id not in vulnerabilities:
            vulnerabilities[cve_id] = {
                'pkg_name': pkg_name,
                'severity': severity,
                'version': version,
                'fixed_version': fixed_version,
                'description': description,
                'cve_id': cve_id,
                'sources': [source]
            }
        else:
            # Add source if not already present
            if source not in vulnerabilities[cve_id]['sources']:
                vulnerabilities[cve_id]['sources'].append(source)

# Sort by severity
sorted_vulns = sorted(vulnerabilities.values(), 
                     key=lambda x: severity_order.get(x['severity'], 999))

# Write to output file
with open('$output_file', 'a') as f:
    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
    for vuln in sorted_vulns:
        sources = ','.join(vuln['sources'])
        writer.writerow([
            vuln['pkg_name'], 
            vuln['severity'], 
            vuln['version'], 
            vuln['fixed_version'], 
            vuln['description'], 
            vuln['cve_id'], 
            sources
        ])

# Count vulnerabilities by severity
counts = {sev: 0 for sev in severity_order}
for vuln in sorted_vulns:
    counts[vuln['severity']] = counts.get(vuln['severity'], 0) + 1

print(f'\\nVulnerability summary by severity:')
print(f'  Critical: {counts.get(\"CRITICAL\", 0)}')
print(f'  High:     {counts.get(\"HIGH\", 0)}')
print(f'  Medium:   {counts.get(\"MEDIUM\", 0)}')
print(f'  Low:      {counts.get(\"LOW\", 0)}')
print(f'  Unknown:  {counts.get(\"UNKNOWN\", 0)}')
print(f'\\nTotal unique vulnerabilities: {len(sorted_vulns)}')
"
    
    echo "Output saved to: $output_file"
}

# Process and output vulnerabilities
if [ -f "$TEMP_DIR/all_vulns.csv" ] && [ -s "$TEMP_DIR/all_vulns.csv" ]; then
    # Check for malformed data in the raw vulnerabilities CSV
    echo "Validating vulnerability data format..."
    python3 -c "
import csv
import sys

invalid_lines = []
with open('$TEMP_DIR/all_vulns.csv', 'r') as f:
    reader = csv.reader(f)
    for i, row in enumerate(reader, 1):
        if len(row) != 7:
            invalid_lines.append(str(i))

if invalid_lines:
    print('Warning: Found potentially malformed data in the following lines:')
    print('\\n'.join(invalid_lines))
    print('These lines may cause issues in the final CSV. Check Trivy output format.')
"
    
    # Consolidate vulnerabilities and write to output file
    consolidate_vulnerabilities "$TEMP_DIR/all_vulns.csv" "$OUTPUT_FILE"
    echo "Script completed successfully."
else
    echo "No vulnerabilities found in any of the scanned images."
    echo "Package Name,Severity,Version,Fixed in Version,Description,CVE ID,Source" > "$OUTPUT_FILE"
fi

exit 0