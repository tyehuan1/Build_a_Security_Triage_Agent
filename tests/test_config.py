"""Setup checks: a fresh clone has every input file the run needs, and caches match their manifest."""

import hashlib
import json

import config


def test_settings_load_and_hold_no_secrets():
    s = config.load_settings()
    config.redacted(s)  # raises if a key value leaked into settings
    assert s["model"]["temperature"] == 0
    assert not any(v for k, v in s["fault_injection"].items() if not k.startswith("$"))


def test_all_input_and_cache_paths_exist():
    s = config.load_settings()
    paths = [s["inputs"]["threat_input"]["path"], s["inputs"]["environment_snapshot"]["path"],
             s["paths"]["schema"], s["paths"]["cache_manifest"]]
    paths += [src["cache"] for src in s["sources"].values() if "cache" in src]
    missing = [p for p in paths if not config.path(p).is_file()]
    assert not missing, f"missing files: {missing}"


def test_cache_files_match_manifest_hashes():
    s = config.load_settings()
    manifest = json.loads(config.path(s["paths"]["cache_manifest"]).read_text(encoding="utf-8"))
    for rel, meta in manifest["files"].items():
        digest = hashlib.sha256(config.path(rel).read_bytes()).hexdigest()
        assert digest == meta["sha256"], f"{rel} changed since it was cached"
