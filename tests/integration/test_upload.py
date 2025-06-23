import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

TESTDATA_PATH = Path(__file__).parent.parent / "data"

def test_upload_tpa_file_integration() -> None:
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    test_env = os.environ.copy()
    #test_env.update({
    #    "MOBSTER_TPA_SSO_TOKEN_URL": "https://test.token.url",
    #    "MOBSTER_TPA_SSO_ACCOUNT": "test-account",
    #    "MOBSTER_TPA_SSO_TOKEN": "test-token"
    #})

    result = subprocess.run([
        "mobster",
        "upload", "tpa",
        "--tpa-base-url", "http://localhost:8080",
        "--file", str(sbom_file)
    ], capture_output=True, text=True, env=test_env)

    assert result.returncode == 0, f"Command failed with stderr: {result.stderr}"
