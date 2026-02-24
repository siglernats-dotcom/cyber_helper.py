# Cyber Helper Toolkit

**Created by Nazivu**

## Description
Cyber Helper Toolkit is a Python tool designed for SOC analysts and CyberDefenders exercises. It extracts Indicators of Compromise (IoCs), detects Base64 strings, filters events by process, extracts URLs, and calculates SHA256 hashes from the terminal.

## Features
- Extract **IPs, URLs, MD5, SHA1, and SHA256** from log or text files.
- Detect and decode **Base64 strings**.
- Filter log lines by **process name**.
- Calculate **SHA256** of any file.

## Requirements
- Python 3.8 or higher
- Linux/Ubuntu, macOS, or Windows

## Usage
```bash
# Show help
python3 cyber_helper.py --help

# Extract IoCs
python3 cyber_helper.py --file log.txt --extract-ioc

# Detect Base64
python3 cyber_helper.py --file log.txt --detect-base64

# Filter by process
python3 cyber_helper.py --file log.txt --filter-process powershell

# Calculate SHA256 of a file
python3 cyber_helper.py --hash-file sample.exe
