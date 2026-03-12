
<b>Pattern 1: Keep domain-specific configuration selection and validation inside the owning module (e.g., cosign), and expose a single stable config/factory API to callers so higher-level code (CLI parsing, Tekton scripts) does not encode backend-specific branching.
</b>

Example code before:
```
# tekton/component.py
if args.use_keyless:
    cfg = KeylessConfig(fulcio_url=args.fulcio_url, token_file=args.oidc_token)
    cosign = KeylessCosign(cfg)
else:
    cfg = CosignConfig(sign_key=args.sign_key, verify_key=args.verify_key)
    cosign = CosignClient(cfg)
```

Example code after:
```
# cosign/__init__.py
def get_cosign(config: CosignConfig) -> SupportsFetch | SupportsSign:
    ...

# tekton/component.py
cosign = cosign.get_cosign(CosignConfig.from_args(args))
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/konflux-ci/mobster/pull/321#discussion_r2821732816
- https://github.com/konflux-ci/mobster/pull/321#discussion_r2820858669
- https://github.com/konflux-ci/mobster/pull/321#discussion_r2821751017
</details>


___

<b>Pattern 2: Avoid adding environment variables or extra CLI knobs that duplicate information already present in provided configs; instead, infer behavior (e.g., keyless vs static signing) from the presence/validity of required arguments and fail with a clear error when insufficient.
</b>

Example code before:
```
use_keyless = os.getenv("COSIGN_METHOD", "STATIC") == "KEYLESS"
if use_keyless:
    ...
```

Example code after:
```
def use_keyless(args: Namespace) -> bool:
    if args.oidc_token and args.fulcio_url and args.rekor_url:
        return True
    if args.sign_key and args.verify_key:
        return False
    raise ArgumentError(None, "Provide either static keys or keyless OIDC parameters.")
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/konflux-ci/mobster/pull/321#discussion_r2820839396
- https://github.com/konflux-ci/mobster/pull/321#discussion_r2820858669
</details>


___

<b>Pattern 3: Split interfaces/protocols by capability (fetch vs sign/attest vs provenance) so that types encode what an instance can do and callers do not need runtime "can_*" checks or null configs to gate behavior.
</b>

Example code before:
```
class Cosign(Protocol):
    async def fetch_sbom(...): ...
    async def attest_sbom(...): ...

if cosign.can_sign():
    await cosign.attest_sbom(...)
```

Example code after:
```
class SupportsFetch(Protocol):
    async def fetch_sbom(...): ...

class SupportsSign(Protocol):
    async def attest_sbom(...): ...

def get_fetcher(cfg) -> SupportsFetch: ...
def get_signer(cfg) -> SupportsSign: ...
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/konflux-ci/mobster/pull/321#discussion_r2821627022
- https://github.com/konflux-ci/mobster/pull/330#discussion_r2895028980
</details>


___

<b>Pattern 4: Remove development/debug logging before merging, and prefer appropriate log levels with non-sensitive payloads; do not log entire large inputs (e.g., full snapshot JSON) in warning/error logs unless explicitly justified.
</b>

Example code before:
```
snapshot_data = snapshot_file.read()
LOGGER.warning("Parsing snapshot %s", snapshot_data)
model = SnapshotModel.model_validate_json(snapshot_data)
```

Example code after:
```
snapshot_data = snapshot_file.read()
LOGGER.debug("Parsing snapshot file %s (%d bytes)", snapshot_spec, len(snapshot_data))
model = SnapshotModel.model_validate_json(snapshot_data)
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/konflux-ci/mobster/pull/330#discussion_r2903627827
</details>


___

<b>Pattern 5: Prefer tests that validate externally meaningful behavior and avoid brittle assertions on internal call ordering or overly implementation-specific details; remove or refactor "orchestration-only" tests that block refactors.
</b>

Example code before:
```
await cmd._execute_workflow(...)
assert expected_order == [
    mock_a, mock_b, mock_c  # manually constructed list
]
```

Example code after:
```
result = await cmd.execute()
assert "expected_field" in result_dict
assert mock_dependency.assert_awaited()  # only when it asserts a real contract
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/konflux-ci/mobster/pull/232#discussion_r2409914739
- https://github.com/konflux-ci/mobster/pull/232#discussion_r2413684369
- https://github.com/konflux-ci/mobster/pull/321#discussion_r2821814773
</details>


___

<b>Pattern 6: Centralize shared constants/formatting rules (e.g., SPDX "Tool:" creator string, timestamp formatting, naming conventions like SBOM vs Sbom) and reuse them across generate/augment/test code to prevent spec drift and inconsistent outputs.
</b>

Example code before:
```
sbom["creationInfo"]["creators"].append(f"Mobster-{version}")
annotation_date = dt.isoformat()  # may yield "+00:00"
```

Example code after:
```
sbom["creationInfo"]["creators"].append(get_mobster_tool_string())
annotation_date = format_spdx_timestamp(dt)  # e.g., "...Z"
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/konflux-ci/mobster/pull/109#discussion_r2219653001
- https://github.com/konflux-ci/mobster/pull/109#discussion_r2219656467
- https://github.com/konflux-ci/mobster/pull/287#discussion_r2581431191
</details>


___

<b>Pattern 7: Keep data-processing functions independent of file I/O by loading/validating inputs at the edges and passing in-memory objects downstream; refactor APIs that force passing paths (or require temp files) when adding preprocessing steps like filtering.
</b>

Example code before:
```
def merge_sboms(syft_paths: list[Path], hermeto_path: Path | None) -> dict: ...
merged = merge_sboms(paths, hermeto_path)  # forces filtering to happen "inside"
```

Example code after:
```
def merge_sboms(syft_docs: list[dict], hermeto_doc: dict | None) -> dict: ...
hermeto_doc = filter_by_arch(load_json(path), arch)
merged = merge_sboms(syft_docs, hermeto_doc)
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/konflux-ci/mobster/pull/307#discussion_r2693467306
- https://github.com/konflux-ci/mobster/pull/83#discussion_r2238796136
</details>


___
