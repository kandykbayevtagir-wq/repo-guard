```python
#!/usr/bin/env python3
"""
repo-guard: Fast, zero-dependency security & disk bloat auditor for Git repositories.
"""

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Dict, Any

# Security Signatures
PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "RSA/OpenSSH Private Key": r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----",
    "Generic API Secret Assignment": r"(?i)(api[_-]?key|secret[_-]?key|password|auth[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{8,}['\"]",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
}

SUSPICIOUS_FILES = [".env", ".env.local", "id_rsa", "id_ed25519", "credentials.json"]
JUNK_DIRS = ["node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".cache"]

class RepoGuard:
    def __init__(self, target_dir: str, max_size_mb: float, ignore_dirs: List[str]):
        self.target_dir = Path(target_dir).resolve()
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.ignore_dirs = set(ignore_dirs)
        self.findings = {"secrets": [], "heavy_files": [], "suspicious_files": [], "junk_dirs": []}

    def is_ignored(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def scan_file_contents(self, file_path: Path):
        try:
            if file_path.stat().st_size > 2 * 1024 * 1024:  # Skip files > 2MB for secret parsing
                return
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for name, pattern in PATTERNS.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Mask sensitive secret in output
                        raw_val = match.group(0)
                        masked = raw_val[:4] + "*" * (len(raw_val) - 8) + raw_val[-4:] if len(raw_val) > 8 else "***"
                        self.findings["secrets"].append({
                            "type": name,
                            "file": str(file_path.relative_to(self.target_dir)),
                            "match": masked
                        })
        except Exception:
            pass

    def run_audit(self):
        files_to_scan = []
        
        for root, dirs, files in os.walk(self.target_dir):
            rel_root = Path(root).relative_to(self.target_dir)
            
            # Prune ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            # Detect Junk Directories
            for d in dirs:
                if d in JUNK_DIRS:
                    self.findings["junk_dirs"].append(str(rel_root / d))

            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.target_dir)

                if self.is_ignored(rel_path):
                    continue

                # Check Suspicious Files
                if file in SUSPICIOUS_FILES:
                    self.findings["suspicious_files"].append(str(rel_path))

                # Check Heavy Files
                try:
                    size = file_path.stat().st_size
                    if size > self.max_size_bytes:
                        self.findings["heavy_files"].append({
                            "file": str(rel_path),
                            "size_mb": round(size / (1024 * 1024), 2)
                        })
                except OSError:
                    continue

                files_to_scan.append(file_path)

        # Threaded scanning for secret patterns
        with ThreadPoolExecutor(max_workers=8) as executor:
            executor.map(self.scan_file_contents, files_to_scan)

        return self.findings

def print_cli_report(results: Dict[str, Any]):
    print("\n🔍 --- REPO-GUARD AUDIT REPORT ---\n")
    
    # Secrets
    secrets = results["secrets"]
    if secrets:
        print(f"🚨 EXPOSED SECRETS FOUND: {len(secrets)}")
        for s in secrets:
            print(f"  [!] {s['type']} -> {s['file']} ({s['match']})")
    else:
        print("✅ Secrets Check: Clean")

    # Suspicious Files
    susp = results["suspicious_files"]
    if susp:
        print(f"\n⚠️  SUSPICIOUS UNPROTECTED FILES: {len(susp)}")
        for f in susp:
            print(f"  [!] {f}")

    # Heavy Files
    heavy = results["heavy_files"]
    if heavy:
        print(f"\n🐘 HEAVY FILES EXCEEDING THRESHOLD: {len(heavy)}")
        for h in heavy:
            print(f"  [!] {h['file']} ({h['size_mb']} MB)")

    # Junk Dirs
    junk = results["junk_dirs"]
    if junk:
        print(f"\n🗑️  UNIGNORED ARTIFACT DIRECTORIES: {len(junk)}")
        for j in junk:
            print(f"  [!] {j}")

    print("\n-----------------------------------\n")

def main():
    parser = argparse.ArgumentParser(description="Audit Git repository for secrets and bloat.")
    parser.add_argument("path", nargs="?", default=".", help="Target directory (default: current)")
    parser.add_argument("--max-size-mb", type=float, default=10.0, help="Heavy file size threshold in MB")
    parser.add_argument("--secrets-only", action="store_true", help="Run only secret pattern scanner")
    parser.add_argument("--json", action="store_true", help="Print findings as JSON")
    parser.add_argument("--ignore-dirs", default=".git,.venv,venv", help="Comma-separated dirs to ignore")

    args = parser.parse_args()
    ignore_list = [d.strip() for d in args.ignore_dirs.split(",")]

    auditor = RepoGuard(args.path, args.max_size_mb, ignore_list)
    results = auditor.run_audit()

    if args.secrets_only:
        results = {"secrets": results["secrets"]}

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_cli_report(results)

    # Fail CI if secrets are detected
    if results["secrets"]:
        sys.exit(1)

if __name__ == "__main__":
    main()