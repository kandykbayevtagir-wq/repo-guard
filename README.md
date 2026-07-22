# 🛡️ repo-guard

> Fast, zero-dependency security & disk bloat auditor for local Git repositories and CI pipelines.

`repo-guard` scans your project for exposed API keys, private certificates, `.env` leaks, and unignored heavy artifacts (like `node_modules` or build caches) before they reach production or remote repositories.

---

## ✨ Features

- 🔐 **Secret Leak Detection**: Built-in regex engine for AWS, GitHub Tokens, RSA Private Keys, and generic secret assignments.
- 📦 **Junk & Bloat Auditor**: Identifies heavy directories (`node_modules`, `venv`, `build/`) and flags files exceeding size thresholds.
- ⚡ **Zero Dependencies**: Powered exclusively by Python standard library (`concurrent.futures`, `re`, `argparse`).
- 🤖 **CI/CD Ready**: Exits with non-zero status when critical findings occur. Supports `--json` output for parsing.

---

## 🚀 Quick Start

Run audit on the current directory:

```bash
python3 repoguard.py .
