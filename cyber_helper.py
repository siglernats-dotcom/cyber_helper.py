import re
import base64
import hashlib
import argparse
import sys
from pathlib import Path

# ==============================
# IOC EXTRACTION
# ==============================
def extract_iocs(text: str) -> dict:
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    url_pattern = r'https?://[^\s"\']+'
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

    return {
        "IPs": sorted(set(re.findall(ip_pattern, text))),
        "URLs": sorted(set(re.findall(url_pattern, text))),
        "MD5": sorted(set(re.findall(md5_pattern, text))),
        "SHA1": sorted(set(re.findall(sha1_pattern, text))),
        "SHA256": sorted(set(re.findall(sha256_pattern, text))),
    }

# ==============================
# BASE64 DETECTION & DECODE
# ==============================
def find_base64_strings(text: str) -> list:
    base64_pattern = r'\b[A-Za-z0-9+/]{20,}={0,2}\b'
    candidates = re.findall(base64_pattern, text)
    decoded_results = []

    for candidate in candidates:
        try:
            decoded = base64.b64decode(candidate, validate=True)
            decoded_text = decoded.decode("utf-8", errors="ignore")
            if decoded_text.strip():
                decoded_results.append((candidate, decoded_text))
        except Exception:
            continue

    return decoded_results

# ==============================
# PROCESS FILTER
# ==============================
def filter_by_process(text: str, process_name: str) -> list:
    lines = text.splitlines()
    matches = []

    for line in lines:
        if process_name.lower() in line.lower():
            matches.append(line)

    return matches

# ==============================
# SHA256 CALCULATOR
# ==============================
def calculate_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()

    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()

# ==============================
# MAIN FUNCTION
# ==============================
def main():
    parser = argparse.ArgumentParser(
        description="Cyber Helper Toolkit - SOC & CyberDefenders Assistant (Created by Nazivu)"
    )

    parser.add_argument("--file", type=str, help="Path to log/text file")
    parser.add_argument("--extract-ioc", action="store_true", help="Extract IPs, URLs, Hashes")
    parser.add_argument("--detect-base64", action="store_true", help="Detect and decode Base64 strings")
    parser.add_argument("--filter-process", type=str, help="Filter log lines by process name")
    parser.add_argument("--hash-file", type=str, help="Calculate SHA256 of a file")

    args = parser.parse_args()

    # SHA256 mode (separate from log reading)
    if args.hash_file:
        file_path = Path(args.hash_file)
        if not file_path.exists():
            print("[-] File not found.")
            sys.exit(1)
        hash_value = calculate_sha256(file_path)
        print(f"[+] SHA256: {hash_value}")
        sys.exit(0)

    if not args.file:
        print("[-] You must provide --file for log analysis.")
        sys.exit(1)

    file_path = Path(args.file)
    if not file_path.exists():
        print("[-] File not found.")
        sys.exit(1)

    try:
        text = file_path.read_text(errors="ignore")
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        sys.exit(1)

    # Extract IOCs
    if args.extract_ioc:
        iocs = extract_iocs(text)
        for category, values in iocs.items():
            print(f"\n=== {category} ===")
            for value in values:
                print(value)

    # Detect Base64
    if args.detect_base64:
        results = find_base64_strings(text)
        print("\n=== Base64 Detected ===")
        for original, decoded in results:
            print(f"\n[Encoded] {original}")
            print(f"[Decoded] {decoded}")

    # Filter by process
    if args.filter_process:
        matches = filter_by_process(text, args.filter_process)
        print(f"\n=== Lines containing '{args.filter_process}' ===")
        for line in matches:
            print(line)

if __name__ == "__main__":
    main()
