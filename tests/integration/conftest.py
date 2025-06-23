import subprocess
from pathlib import Path


def build_and_push(cfile: Path, tag: str):
    bproc = subprocess.run(
        ["buildah", "bud", "-t", tag, "-f", str(cfile), str(cfile.parent)],
        capture_output=True,
        check=True,
    )

    pproc = subprocess.run(["buildah", "push", "--tls-verify=false", tag], check=True)
