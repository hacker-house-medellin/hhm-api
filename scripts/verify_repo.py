#!/usr/bin/env python3
import json, re
from pathlib import Path
root = Path(__file__).resolve().parents[1]
meta = json.loads((root / "project.json").read_text())
required = [
    "README.md",
    "AGENTS.md",
    "project.json",
    "docs/architecture.md",
    "src/presence.rs",
    *meta.get("required_paths", []),
]
missing = [path for path in required if not (root / path).exists()]
if missing: raise SystemExit(f"missing required paths: {missing}")
cargo_manifest = (root / "Cargo.toml").read_text()
required_pins = {
    "https://github.com/hacker-house-medellin/hhm-interfaces": "ffc1df71d1d89202b431f4830cc2a43e4a451da3",
    "https://github.com/shared-auth/shared-auth-lib": "4972cfd4eee43ddd9130b9c846caff1c5da7ae95",
    "https://github.com/ores-otel/ores.otel.log": "ca176fb6768a9750d262a536952268625ffd3a8a",
}
for repository, revision in required_pins.items():
    if repository not in cargo_manifest or revision not in cargo_manifest:
        raise SystemExit(f"missing immutable dependency pin: {repository}@{revision}")
for path in root.rglob("*"):
    if not path.is_file() or ".git" in path.parts or path.stat().st_size > 1_000_000: continue
    try: text = path.read_text()
    except UnicodeDecodeError: continue
    if any(marker in text for marker in ("<"*7, "="*7, ">"*7)): raise SystemExit(f"conflict marker in {path}")
    if re.search(r"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY", text):
        raise SystemExit(f"credential-shaped content in {path}")
print(f"validated {meta['organization']}/{meta['repository']}")
