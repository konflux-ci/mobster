# Integration testing in Konflux

This repository automatically deploys [integration tests within Konflux on contributions][1].
The tekton Pipeline responsible for running integration tests in located in
`hack/integration/mobster-test.yml`. The pytest instance run in the pipeline
can be customized by providing the `PYTEST_OPTS` parameter in the
`IntegrationTestScenario` custom resource.

## Existing Mobster integration tests
These are the two custom integration tests that Konflux currently executes for
Mobster.

For the `mobster-test-*` tests, the pipelinerun spins up sidecars needed for
integration testing:
  - Zot is used as an OCI registry
  - TPA to test SBOM manipulation
  - MinIO to provide a testing S3 bucket

### mobster-test
This test runs on every commit pushed to the Mobster repository. It executes
all Mobster integration tests, with the exception of slow tests (tests marked
with the `slow` pytest marker).

### mobster-test-slow
This test only runs on commits to the main branch, as it's slow and requires a
lot of resources to finish. It reuses the same pipelinerun to run the tests,
but specifies the `PYTEST_OPTS` param with `-m slow` to only run tests with the
`slow` pytest marker.

Currently this test only contains one test:
`test_process_component_sboms_big_release`. This performs an SBOM augmentation
for a large release. It's configured to augment 200 components with each SBOM
being large (5MiB).

This test is used to catch regressions in memory usage and augmentation speed.
For this reason it's critical that it's configured identically to the actual
SBOM augmentation Tekton task. The concurrency settings in the integration test
[conftest.py](../tests/integration/conftest.py) must match the concurrency used
in the [Tekton tasks](../tasks/) themselves.

Further, the resource requests and limits defined in the
[mobster-test](../hack/integration/mobster-test.yml) pipeline must match those
used in the Tekton tasks.

## Integration tests as a Pipeline

The integration test Pipeline uses Sidecars for dependencies (to reduce config needed).
To properly configure the Sidecars, the Pipeline first parses the Konflux SNAPSHOT,
locates the revision and clones the repository to a workspace `relevant-data` to
a folder `SOURCE_CODE`. Tests are then performed using the image referenced within
the SNAPSHOT and the cloned source code.

To correctly provision a Pipeline with a Workspace, this test must also define
a PipelineRun (`hack/integration/mobster-test-run.yml`). However, the default Konflux
integration test accounts for executing a Pipeline, therefore we have to modify
the IntegrationTestScenario object, to [change `spec.resolverRef.resourceKind` to
value `pipelinerun`][2].


**CAUTION**:
Currently, there is a discovered bug that reverts this change on every UI update
on the IntegrationTestScenario, so the Scenario should only be updated using
`oc apply`.

## Example of IntegrationTestScenario update

```bash
oc get integrationtestscenario mobster-test -o yaml > current_scenario.yml
```

then visit the document, increment the value of `metadata.generation`, change
the fields needed and use `oc apply -f modified_scenario.yml`.

## Used images

Mobster image used is the exact image built within the CI/CD in the previous step.
There are some other Sidecars with already pre-built images, like `minio` or `zot`,
but Mobster integration also requires a TPA image (preferably with a built-in database).

To do this, Mobster's GH CI/CD also builds a custom TPA image and publishes it as
a Konflux component.

## Updating the tests

Unfortunately the tests are sourced from a fixed revision, which is set to the main branch.
If you wish to update the tests, you have to change the revision in the Konflux UI. The
path in the repository should point to a PipelineRun, which should then refer to a Pipeline.

If you change the setup in the UI, it changes the target revision for the whole repository.
There is not an easy way to only experiment on a separate branch.

To change the integration tests, you have to commit your changes of the PipelineRun (including
the updated reference to a Pipeline) to a new branch, push it to the repository and change
the UI revision to this new branch. Just keep in mind that integration tests in all branches
will be affected, so you may want to disable the `mandatory` checkmark for the tests for the
duration of your testing.

[1]: https://konflux-ci.dev/docs/testing/integration/
[2]: https://konflux-ci.dev/docs/testing/integration/creating/#customize-pipelinerun-definition
