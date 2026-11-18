#!/usr/bin/env bash
set -euo pipefail
git clone --depth 1 https://github.com/we45/Vulnerable-Flask-App.git target
git -C target checkout b6a4f97
mkdir -p evidence
pip install bandit pip-audit
bandit -r target/app/app.py -f txt -o evidence/bandit_report.txt || true
bandit -r target/app/app.py -f json -o evidence/bandit_report.json || true
pip-audit -r target/app/requirements.txt --no-deps --disable-pip -f json -o evidence/pip_audit.json || true
