# Changelog

## [1.0.0](https://github.com/konflux-ci/mobster/compare/v0.7.0...v1.0.0) (2025-09-26)


### Features

* **ISV-5714:** Refactor SBOM modification code to reflect mapping mechanism imperfection finding ([972075e](https://github.com/konflux-ci/mobster/commit/972075e7210c26308d7d2fd4725feaee70103807))
* **ISV-5714:** Refactor SBOM modification code to reflect mapping mechanism imperfection finding ([b58eb7d](https://github.com/konflux-ci/mobster/commit/b58eb7d4b4b27ebac2c6fce20a2594ac27d4a80d))
* **ISV-5914:** utilize connection pooling in TPA client ([7fdac0f](https://github.com/konflux-ci/mobster/commit/7fdac0feb6f19c0892f9c626be52237c36ab3be5))
* **ISV-5914:** utilize connection pooling in TPA client ([63615c7](https://github.com/konflux-ci/mobster/commit/63615c7b7cd7897b2b40be0d0f4f5dd26d754cab))
* **ISV-6223:** Log S3 file uploads ([c82917b](https://github.com/konflux-ci/mobster/commit/c82917b19bd8fb1aff99e1f6f3993f32d4c1eb21))
* **ISV-6223:** Log S3 file uploads ([34ccf2b](https://github.com/konflux-ci/mobster/commit/34ccf2bc0bae2a1dbb42fb1fd36a775de4f790f3))
* **ISV-6260:** Support multiple target repositories in Konflux Snapshot. ([01f9cb0](https://github.com/konflux-ci/mobster/commit/01f9cb0589cc289a2bd061ae38a2fd12487057b5))
* **ISV-6260:** Support multiple target repositories in Konflux Snapshot. ([08f3c2b](https://github.com/konflux-ci/mobster/commit/08f3c2baa7b40a5739d0a04e30ff76a328488f61))


### Bug Fixes

* Add a license to the container. ([2e11008](https://github.com/konflux-ci/mobster/commit/2e110082bcee2e6022fecc2577a733619f20e2cc))
* **ISV-6219:** Glob pattern updated for ignoring the "tasks" dir. ([1609e42](https://github.com/konflux-ci/mobster/commit/1609e429f814b00299f3a48fe4a71cadde349e84))
* **ISV-6219:** Glob pattern updated for ignoring the "tasks" dir. ([688c71a](https://github.com/konflux-ci/mobster/commit/688c71a691235bb16689a695b9f1cae7067431e6))
* Update `deprecated-image-check` image ref. ([ea2e36a](https://github.com/konflux-ci/mobster/commit/ea2e36ac7f1eff424b214c5b2f174b0e8ae19764))
* Update `deprecated-image-check` image ref. ([533e70c](https://github.com/konflux-ci/mobster/commit/533e70c464a9db61066b9db231ca03d832a3c250))
* Update `task-clair-scan` image ref. ([5df22fb](https://github.com/konflux-ci/mobster/commit/5df22fb3d20df3af92ea5c2b2248b04a08a99cbc))


### Miscellaneous Chores

* release 1.0.0 ([30b4299](https://github.com/konflux-ci/mobster/commit/30b4299465f8542a71293c1181ac555cdfce5fa5))

## [0.7.0](https://github.com/konflux-ci/mobster/compare/v0.6.0...v0.7.0) (2025-09-03)


### Features

* add more logging statements to Tekton scripts ([9d8b880](https://github.com/konflux-ci/mobster/commit/9d8b8806c6238cb110f9875c90b21348b9498dc6))
* add support for specifying concurrency limits in tekton tasks ([22bbffd](https://github.com/konflux-ci/mobster/commit/22bbffde08fc227b0f93069ac69180b60d47d5db))
* address code review comments 2 ([b9da650](https://github.com/konflux-ci/mobster/commit/b9da650c30ce69ed024fa1e785c016a40134e473))
* address code review comments 3 ([9fb6f1e](https://github.com/konflux-ci/mobster/commit/9fb6f1e13aa1884d9701a8e94f9082453f36ff06))
* apply suggestions from code review ([2e17f5c](https://github.com/konflux-ci/mobster/commit/2e17f5ce8533fcaff10da119950b281ef5db5427))
* bump memory requests to 1Gi for tekton tasks ([68c4833](https://github.com/konflux-ci/mobster/commit/68c4833384d221e91c9cdbfe0c2badab0425c06e))
* bump mobster tasks to include improved concurrency ([85fcbb2](https://github.com/konflux-ci/mobster/commit/85fcbb2e65f2fb712dc59ea46da0140f497db29f))
* bump tekton task images for improved concurrency ([0867189](https://github.com/konflux-ci/mobster/commit/08671895267141cb814d146689ede738677071af))
* Bump up Mobster image in Tekton task ([a2af828](https://github.com/konflux-ci/mobster/commit/a2af8288b2c910b3c387eb118d52cf4b3b893b83))
* Bump up Mobster image in Tekton task ([72c0e99](https://github.com/konflux-ci/mobster/commit/72c0e994c953facc9d52be3e3c12306c0813b7c2))
* Fix assertion error, make Mobster log a warning instead. ([b38d917](https://github.com/konflux-ci/mobster/commit/b38d91752073dee6ca3284bfc875cd10e58e7f4a))
* Fix assertion error, make Mobster log a warning instead. ([0bab278](https://github.com/konflux-ci/mobster/commit/0bab278d7549211e91b3ada5dc8c6aa4bd6eeff0))
* improve SBOM processing concurrency ([63f69d9](https://github.com/konflux-ci/mobster/commit/63f69d989130fce1c48d5a84fd4c991281cd5a52))
* increase memory requirements for Tekton tasks ([3ac3da5](https://github.com/konflux-ci/mobster/commit/3ac3da5f1b2fefa2cd08f23223682063271a7368))
* increase memory requirements for Tekton tasks ([b85c1d2](https://github.com/konflux-ci/mobster/commit/b85c1d23773dcedf762b08e8b00907015b427a97))
* **ISV-6003:** Port contextual SBOM code to Mobster. ([ac2ab37](https://github.com/konflux-ci/mobster/commit/ac2ab370752714985b6219af98cd0f861560232d))
* **ISV-6003:** Port contextual SBOM code to Mobster. ([8019606](https://github.com/konflux-ci/mobster/commit/80196069a4c100e72ef331675d18ec358a2176ae))
* **ISV-6005:** Add a script to store SBOM regeneration data to S3. ([eafb5f4](https://github.com/konflux-ci/mobster/commit/eafb5f433aad277bd41da12c3df4bbf8da5c6f45))
* **ISV-6005:** Fix the integration tests. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Fix the integration tests. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Fix the rebased code changes. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Fix the tests. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Fix the tests. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Fix the tests. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Rebase the feature branch. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Remove the unnecessary parameter from tekton tasks. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Remove unnecessary code. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Store regeneration data in release-time SBOM Tasks. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Store regeneration data in release-time SBOM Tasks. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Update the python script to add entrypoints. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Update the script according recent Mobster code migration. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Update the script according recent Mobster code migration. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Update the script according recent Mobster code migration. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Update the script. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Update the script. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Update the script. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6005:** Update the script. ([9b86404](https://github.com/konflux-ci/mobster/commit/9b86404cd37a25beff6e84c1ba1716aed5fd5979))
* **ISV-6006:** component and product SBOM creation scripts store release_id ([8f31c2e](https://github.com/konflux-ci/mobster/commit/8f31c2e49f35864b3a46e9d9a3539a787aa5d4c4))
* **ISV-6006:** component and product SBOM creation scripts store release_id ([8f4549c](https://github.com/konflux-ci/mobster/commit/8f4549c47f487a369dac2f9766e22f0ec2f75238))
* **ISV-6014:** bump tekton tasks images ([b8622ca](https://github.com/konflux-ci/mobster/commit/b8622ca5c3261d6f15eac3a5e001cb71d507280c))
* **ISV-6014:** bump tekton tasks images ([c946ddc](https://github.com/konflux-ci/mobster/commit/c946ddc98b1afab6a26d51cd59c0f8f4f4df30ce))
* **ISV-6027:** Add arch identifier to image PURLs ([7d8efa1](https://github.com/konflux-ci/mobster/commit/7d8efa1d1e4ea77a9740568ad2d8348725b02cb9))
* **ISV-6027:** Add arch identifier to image PURLs ([f64da81](https://github.com/konflux-ci/mobster/commit/f64da81f5f710b83c8dfc3408f449f540f523a21))
* **ISV-6032:** add artifact datatype ([8c7e484](https://github.com/konflux-ci/mobster/commit/8c7e48434d2276301690ecf7198a8f562209aaca))
* **ISV-6032:** add SBOM URNs to upload report ([89d8a69](https://github.com/konflux-ci/mobster/commit/89d8a690e9e86f793661e043f9778871db11f6d5))
* **ISV-6032:** allow SBOM uploads to be verifiable in Konflux E2E ([9f837f0](https://github.com/konflux-ci/mobster/commit/9f837f03f1d863c69931128ba4b7477fb5f58e50))
* **ISV-6032:** bump mobster tekton task version ([9ad73bd](https://github.com/konflux-ci/mobster/commit/9ad73bd518d94e9879bc739c01c9bf2602392d53))
* **ISV-6032:** bump mobster tekton task version ([ecd7cb2](https://github.com/konflux-ci/mobster/commit/ecd7cb2160357d9ce697b48908897b4f97207f71))
* **ISV-6032:** pass results param to tekton scripts ([b75d951](https://github.com/konflux-ci/mobster/commit/b75d951583eea8351cf63a8132615bb3f6fb7cfd))
* **ISV-6032:** simplify tpa upload logic ([24bb2fd](https://github.com/konflux-ci/mobster/commit/24bb2fdbfc023341e8c7c160c1bab2f67dae3040))
* **ISV-6032:** tekton task scripts support writing upload results ([73cdf7f](https://github.com/konflux-ci/mobster/commit/73cdf7fa9226e6e206084484cf6bb910662af43a))
* **ISV-6053:** Use `cosign download attestation` for SBOM download. ([89e713d](https://github.com/konflux-ci/mobster/commit/89e713d44a6c20bd6a4513576299121c90615c43))
* **ISV-6053:** Use `cosign download attestation` for SBOM download. ([99be1f7](https://github.com/konflux-ci/mobster/commit/99be1f704a8f145306be28e02124c775d1a7289a))
* **ISV-6092:** Add integration test in Konflux ([36f6e91](https://github.com/konflux-ci/mobster/commit/36f6e91504486752dffff1383647165666b295d2))
* **ISV-6092:** Add integration test in Konflux. ([5c66b6e](https://github.com/konflux-ci/mobster/commit/5c66b6ec0533418d972ced69e5f0ed3cdd66890d))
* **ISV-6092:** Make TPA a new component in Mobster. ([50e29c5](https://github.com/konflux-ci/mobster/commit/50e29c578f28187238f83b167bb83a7d30c3bee9))
* **ISV-6128:** add concurrency limit to make_snapshot ([009bcad](https://github.com/konflux-ci/mobster/commit/009bcadbd5fa589c2bde3ab266b59117350af63b))
* **ISV-6128:** add concurrency limit to make_snapshot ([902490b](https://github.com/konflux-ci/mobster/commit/902490b4fa0672925e6592bfbf2d60a4d8bccebe))
* **ISV-6128:** add concurrency limit to make_snapshot ([d10e09d](https://github.com/konflux-ci/mobster/commit/d10e09dc1f4425d78907b15dc1c05643c4644b11))
* **ISV-6128:** bump tekton tasks ([c298b1b](https://github.com/konflux-ci/mobster/commit/c298b1b9d1395d2fdb207472f267011b8a7e936c))
* **ISV-6128:** bump tekton tasks ([444208c](https://github.com/konflux-ci/mobster/commit/444208c92431e56c5d01dccb571788f5ecbebd6d))
* **ISV-6129:** add is_bucket_empty() method to S3 client ([4b65144](https://github.com/konflux-ci/mobster/commit/4b65144a84f5141bdc8438cee84370b156231446))
* **ISV-6129:** add product SBOM happypath test prototype ([d8a799e](https://github.com/konflux-ci/mobster/commit/d8a799e8fa94d360b5aaf64fcb1d1c2c8cf5305e))
* **ISV-6129:** add release id datatype ([9b7ac01](https://github.com/konflux-ci/mobster/commit/9b7ac01f0bac6afbb35301a34f38f65adbf93a5e))
* **ISV-6129:** add release_id to tekton tasks ([42ef7b6](https://github.com/konflux-ci/mobster/commit/42ef7b6a75ac59a46695ee37b28d0200d51ef8c6))
* **ISV-6129:** bump tekton task image tags ([2901a5a](https://github.com/konflux-ci/mobster/commit/2901a5a7183225ceabbbb68191881c98c59b5d93))
* **ISV-6129:** bump tekton task images to include int test changes ([b8ae10c](https://github.com/konflux-ci/mobster/commit/b8ae10cc579f4b05e9b3cd13c44210adee64fe64))
* **ISV-6129:** generate release_ids in hack scripts ([567f16f](https://github.com/konflux-ci/mobster/commit/567f16f91e3227e5e1bc7d27ff911b2116a9bc64))
* **ISV-6129:** support printing SBOM digests in task scripts ([64be3c6](https://github.com/konflux-ci/mobster/commit/64be3c6b689236f3cb9c92e5609af62974044e48))
* **ISV-6147:** bump tekton task images ([a4249c7](https://github.com/konflux-ci/mobster/commit/a4249c7b266e0f6395d660924d1e05d45b5eda56))
* **ISV-6147:** bump tekton task images ([458d6bf](https://github.com/konflux-ci/mobster/commit/458d6bf7c6278514dbde6cd508bbda92a8cdc9ec))
* **ISV-6147:** ensure SBOMs with duplicate references do not overwrite ([b752c77](https://github.com/konflux-ci/mobster/commit/b752c773ba298d4be6f25d7a0e66b55cbfa17d94))
* **ISV-6147:** ensure SBOMs with duplicate references do not overwrite ([da0b855](https://github.com/konflux-ci/mobster/commit/da0b855e04a4bb71499d85fa2c3aee8b6f7e0252))
* **ISV-6147:** remove unneeded repository field from snapshot ([46b7148](https://github.com/konflux-ci/mobster/commit/46b7148dc41a0a9a14a6f6b787c8b3abb1350a6c))
* **ISV-6197:** add compute limits to mobster tests ([d0da0d6](https://github.com/konflux-ci/mobster/commit/d0da0d6422a09c99a62115ee1b1b917b5fea68d3))
* **ISV-6197:** bump cpu resources for test ([9bbf6ce](https://github.com/konflux-ci/mobster/commit/9bbf6ce58f84a72376d918baffc2cbf84a427f3b))
* **ISV-6197:** bump memory limits for TPA sidecar ([996c698](https://github.com/konflux-ci/mobster/commit/996c6989a150c9e813a849cec3cc603f52faa38f))
* **ISV-6197:** bump memory resources for test ([35015b1](https://github.com/konflux-ci/mobster/commit/35015b117ed7fc44ca30a36f0fd1e5486abca2dc))
* **ISV-6217:** Rework Atlas retries in release-time SBOM tekton scripts. ([7756d44](https://github.com/konflux-ci/mobster/commit/7756d4463ebd956d6b8b8e2b0c667f56beaf4d04))
* **ISV-6217:** Rework Atlas retries in release-time SBOM tekton scripts. ([6171497](https://github.com/konflux-ci/mobster/commit/617149788e5a1ba4cbae8bfb244c90e7c8f84a43))
* **ISV-6219:** Bump of Mobster image in Tekton tasks is automated. ([b61fe4d](https://github.com/konflux-ci/mobster/commit/b61fe4d164abc35a6e6098ece8437330c3950136))
* **ISV-6219:** Bump of Mobster image in Tekton tasks is automated. ([ad130f0](https://github.com/konflux-ci/mobster/commit/ad130f072d439be279fc8abd041938d43ecd0ed5))
* **KONFLUX-9780:** use normalized image names for SBOM ids ([2d9ba58](https://github.com/konflux-ci/mobster/commit/2d9ba58b2c3ffa9bade069af5e2d59d805cac49a))
* **KONFLUX-9780:** use normalized image names for SBOM ids ([e492666](https://github.com/konflux-ci/mobster/commit/e492666808ebaba20875ff060fdd3b10e03037ce))
* Make renovate PRs less frequent ([90d2e17](https://github.com/konflux-ci/mobster/commit/90d2e17c9761ef072540205076d0c31013643b57))
* Move run_async_subprocess to utils module ([5d34abd](https://github.com/konflux-ci/mobster/commit/5d34abd6567a4ef3306b3815f9663c019b93ce99))
* reduce image arch for pull request to x86_64 ([0046dca](https://github.com/konflux-ci/mobster/commit/0046dca9dbe8e0f250aa8eaf03fbf5bb13f2e9c1))
* reduce image arch for pull request to x86_64 ([65b0b7d](https://github.com/konflux-ci/mobster/commit/65b0b7ddc2cebd2d47acb7646e058c7b85c83498))
* **RELEASE-1832:** remove the use of workspaces ([423db31](https://github.com/konflux-ci/mobster/commit/423db31868bbecb6c934f2eca6ff6a31b4f2f003))
* **RELEASE-1832:** remove the use of workspaces ([971762c](https://github.com/konflux-ci/mobster/commit/971762c0b7d7c8dd7d46d078eb135f73ef65c82d))
* run GC manually in SBOM augmentation ([bb9a9ee](https://github.com/konflux-ci/mobster/commit/bb9a9eef7dcb6be4ec19d214dc29013bc92026fb))
* split augment and upload concurrency params ([c58e1c6](https://github.com/konflux-ci/mobster/commit/c58e1c6b1dc213c8cc16beb0cac042509126f958))
* stream augmented SBOMs to disk directly ([8a1f5a8](https://github.com/konflux-ci/mobster/commit/8a1f5a8762e725e152cc628f4d052603c2cd2ab5))
* use multiple workers for SBOM upload ([0947372](https://github.com/konflux-ci/mobster/commit/0947372598b5d59004b738aefba7c6bacb9bf94e))
* use uuid hex instead of urn ([292cd32](https://github.com/konflux-ci/mobster/commit/292cd327a7c1aa427376294bdf464bb8c571e822))


### Bug Fixes

* add missing parentheses in tasks ([f40007c](https://github.com/konflux-ci/mobster/commit/f40007c14eb337f229ec5a5f398cd54ac2a96e2d))
* add missing parentheses in tasks ([50d4d5b](https://github.com/konflux-ci/mobster/commit/50d4d5b4a0cf2a6d042a954e31f8466c456003c8))
* Fix quoting issue caused by `ARG foo="bar"` in image pullspec. ([7f5849c](https://github.com/konflux-ci/mobster/commit/7f5849c96a645c5948d4948803922491dc9e1b4f))
* Fix quoting issue caused by `ARG foo="bar"` in image pullspec. ([eb4ca28](https://github.com/konflux-ci/mobster/commit/eb4ca282fe0abf859959d56227b37ec8123be93b))
* **ISV-6014:** Capture just stdout for upload command ([7de0e88](https://github.com/konflux-ci/mobster/commit/7de0e88ed5cf00a77747d78ed401088a5ca0c988))
* **ISV-6014:** Capture just stdout for upload command ([ec43639](https://github.com/konflux-ci/mobster/commit/ec4363979ffe355d858d7ebf8cd1d7d9bed41544))
* **ISV-6032:** fix linter issues ([323cfb6](https://github.com/konflux-ci/mobster/commit/323cfb63333df9a38683822118ca8d0cea82364d))
* **ISV-6032:** fix rebase ([b63a888](https://github.com/konflux-ci/mobster/commit/b63a888929f6edf7da53d83a493ef9b30c9f5c44))
* **ISV-6032:** fix rebase ([5dbddb2](https://github.com/konflux-ci/mobster/commit/5dbddb26ee57a8bc4a8003220426c67860d6acd4))
* **ISV-6129:** ensure testing bucket is created ([bf5ed83](https://github.com/konflux-ci/mobster/commit/bf5ed83b0c8cefde927998c37d52bc6e3f16541a))
* **ISV-6129:** remove unused code ([26955bc](https://github.com/konflux-ci/mobster/commit/26955bce9a7163ca2356af96df02becffb3835dd))
* **ISV-6219:** Fix Renovate config according to consultation with Mintmaker team. ([3a8b2ed](https://github.com/konflux-ci/mobster/commit/3a8b2eddf697553e74c2f8026316f13d521a2d22))
* **ISV-6219:** Fix Renovate config according to consultation with Mintmaker team. ([ed79859](https://github.com/konflux-ci/mobster/commit/ed79859a833f770f8211bd7908c7c5f7becafd15))
* **ISV-6219:** Only release a new mobster image if Mobster, its dependencies or the Containerfile changes. ([d9ba9f7](https://github.com/konflux-ci/mobster/commit/d9ba9f750bcac26cf820f5a3fcedacf7ea5c2ef5))
* **ISV-6219:** Only release a new mobster image if some code changed outside the "tasks" dir. ([3c2a1b6](https://github.com/konflux-ci/mobster/commit/3c2a1b68a1922c127d09e87e5e6317f17624b055))
* **ISV-6219:** Use any-time schedule for both managers and rules. ([154ec90](https://github.com/konflux-ci/mobster/commit/154ec9065745fd4d2e24135b3c55c56cb2fca624))
* **ISV-6219:** Use any-time schedule for both managers and rules. ([9500471](https://github.com/konflux-ci/mobster/commit/9500471f4c10892a8f8cd0113aabe88285bfd8ea))
* **ISV-6219:** Use any-time schedule. ([16f02f2](https://github.com/konflux-ci/mobster/commit/16f02f2413b99e8a25ccbaf57bb1c47689477e06))
* **ISV-6219:** Use any-time schedule. ([d0bc217](https://github.com/konflux-ci/mobster/commit/d0bc2178ae7518bd54fe66b643b3013f690cf86e))
* Revert ISV-6053 due to fragility in release-time SBOMs. ([6f9ef07](https://github.com/konflux-ci/mobster/commit/6f9ef07aa6faa241deeb8dc363dfe9e79028b3fb))
* Revert ISV-6053 due to fragility in release-time SBOMs. ([eebae3f](https://github.com/konflux-ci/mobster/commit/eebae3f3e3b467e003e5fb63d9ece96c921c8ef5))
* use correct mobster image tags ([995b567](https://github.com/konflux-ci/mobster/commit/995b567655f73cbdda535f4a2ca1074a0b2504b8))
* use correct mobster image tags ([5bbd2d1](https://github.com/konflux-ci/mobster/commit/5bbd2d17940c39ec252dfb63f3b5e4113a415b73))
* warn on transient Atlas error ([d4efeeb](https://github.com/konflux-ci/mobster/commit/d4efeebf0557e86f2c37b192ee9464f20f860868))


### Documentation

* add comment pointing to Atlas deployment in Containerfile ([89d58a7](https://github.com/konflux-ci/mobster/commit/89d58a788039e6cdb58088eb1a0bebf35fc8d83b))
* **ISV-5874:** Add mkdoc config + github pages doc ([ac3d73f](https://github.com/konflux-ci/mobster/commit/ac3d73f487fe1e703d98a4a62064b2cd30580b3f))
* **ISV-5874:** Add mkdoc config + github pages doc ([0867e6c](https://github.com/konflux-ci/mobster/commit/0867e6c88cae9776a6754c66834285006c5f3078))
* **ISV-6197:** document current Konflux integration tests ([e356dce](https://github.com/konflux-ci/mobster/commit/e356dcec8b84bc71aef0a46795372326419fb8a3))
* update docstrings ([bf98330](https://github.com/konflux-ci/mobster/commit/bf9833073d0f89b38e98f5367b7891f967b52787))

## [0.6.0](https://github.com/konflux-ci/mobster/compare/v0.5.0...v0.6.0) (2025-07-22)


### Features

* add S3 client with integration tests ([c089798](https://github.com/konflux-ci/mobster/commit/c089798531b10f6788ec6cd09643027e706199e8))
* bump tekton task image version ([f5258c2](https://github.com/konflux-ci/mobster/commit/f5258c2737db1af2feb95891db07f27c26dad2a5))
* bump tekton task image version ([64d0e14](https://github.com/konflux-ci/mobster/commit/64d0e1408644e054fefc0990e4c3cf15dd01178e))
* clean up error handling ([32ea213](https://github.com/konflux-ci/mobster/commit/32ea2133f15aefebbf749b874604a9da76e98e85))
* handle testing AWS endpoint url correctly ([a584cf6](https://github.com/konflux-ci/mobster/commit/a584cf678baaffe347015c42fb25cdd78bfc2410))
* implement async S3 directory upload in tekton scripts ([aefd3ba](https://github.com/konflux-ci/mobster/commit/aefd3ba814003e577e85d1b8c23c9c849b3b5742))
* **ISV-5867:** Update parsing of SBOM inputs ([9f1c48e](https://github.com/konflux-ci/mobster/commit/9f1c48e0b39cacfff27a39a66cdbcb20ee6a1261))
* **ISV-5867:** Update parsing of SBOM inputs ([6781d3b](https://github.com/konflux-ci/mobster/commit/6781d3b745a52d9e7eba95077371508ffa71bb48))
* **ISV-6139:** Mobster TPA client raises an error related to the last exception. ([68baccf](https://github.com/konflux-ci/mobster/commit/68baccfeb8098cb0797c891395ca9c74b6cfd0db))
* **ISV-6139:** Mobster TPA client raises an error related to the last exception. ([70224fc](https://github.com/konflux-ci/mobster/commit/70224fc0de63a1eab867818f1302fef884c01c66))
* limit concurrency in S3 client ([0618749](https://github.com/konflux-ci/mobster/commit/0618749a75caf3522ab11a7430e74d69c8201130))
* refactor s3 client to use aioboto3 ([f54409b](https://github.com/konflux-ci/mobster/commit/f54409b00dbdd9fb6e70e4c5e62d6feee9c092b7))
* refactor tekton tasks to use python instead of bash ([8ee74b5](https://github.com/konflux-ci/mobster/commit/8ee74b5c9772ab5853c9629eaad5c0230db86d6e))
* remove awscli from Containerfile ([8eebe5f](https://github.com/konflux-ci/mobster/commit/8eebe5f9fc4344670b3974efc8c4baaeae56d9ed))
* temporarily disable coverage for tekton scripts ([f854ed9](https://github.com/konflux-ci/mobster/commit/f854ed9ffdbdbebf79fc84b4d09edcc6b4f64497))
* use migrated python script in tekton tasks ([c51435a](https://github.com/konflux-ci/mobster/commit/c51435a96d15aba7376c726502e375ff5be98e86))


### Bug Fixes

* clarify mypy ignore type ([ba9c319](https://github.com/konflux-ci/mobster/commit/ba9c319f952c3ee4aaf8e0c1e1064ccef8f3ddeb))
* fix typos ([0be62ed](https://github.com/konflux-ci/mobster/commit/0be62edf6d664c337b2f6505fbaf4fb35405fd34))


### Documentation

* add docstrings ([2a474b1](https://github.com/konflux-ci/mobster/commit/2a474b113a3e1414cf0495a0c047bc8dde19558f))

## [0.5.0](https://github.com/konflux-ci/mobster/compare/v0.4.0...v0.5.0) (2025-07-14)


### Features

* Add extra logging to get precise metrics ([433d83c](https://github.com/konflux-ci/mobster/commit/433d83c0e64d6895806ef6170a80e5d3937bde60))
* Add extra logging to get precise metrics ([af6a3e3](https://github.com/konflux-ci/mobster/commit/af6a3e3f9717260cfbcdc0a9fa6cd7e90685caca))
* Add integration tests for TPA interaction ([72e9444](https://github.com/konflux-ci/mobster/commit/72e9444fd0b74d13020601a9218238c737989c4d))
* add report to Tekton Atlas upload script ([85ca8e4](https://github.com/konflux-ci/mobster/commit/85ca8e43283e102b83cd8b8fbbaadc7dca2483dd))
* add SBOM download stub ([e7b2f5a](https://github.com/konflux-ci/mobster/commit/e7b2f5a7d4fc2d139f782516bb6a6202fcffcac5))
* add stubs for the TPA client ([3a52547](https://github.com/konflux-ci/mobster/commit/3a52547053e552059b0ec7bc22cd010310197211))
* add stubs for the TPA client ([691c2f6](https://github.com/konflux-ci/mobster/commit/691c2f680c9397ed39cd67d8d7628a18e09a4eb1))
* add TPA container to compose ([c2b5666](https://github.com/konflux-ci/mobster/commit/c2b5666ca5fd69ce3e985a6b7e7a699c8c014eb9))
* allow optionally disabling TPA auth ([5b4394e](https://github.com/konflux-ci/mobster/commit/5b4394e2d877cf626119ba969db8fb3aa5195a68))
* disable TPA auth in SBOM hack scripts ([88a355b](https://github.com/konflux-ci/mobster/commit/88a355b01070b959e62ed1f91cd0a3567e1db848))
* **ISV-5858:** Implement mobster generate oci-image. ([5ca11cb](https://github.com/konflux-ci/mobster/commit/5ca11cb49f2a20f1c959ef331509c32bc5ce8893))
* **ISV-5875:** add script to mimick tekton task process ([fafd8df](https://github.com/konflux-ci/mobster/commit/fafd8dfe5a9219d157895b8c7d5c0d3bedf1e718))
* **ISV-5875:** create release-time SBOM augmentation task ([ed4ae93](https://github.com/konflux-ci/mobster/commit/ed4ae93fadd870a17ed981ce8a754b1d178e8007))
* **ISV-5875:** don't embed tekton task scripts ([0583930](https://github.com/konflux-ci/mobster/commit/05839304299bbef0d17f7b8f725752c8f593c747))
* **ISV-5875:** handle nonexistent and empty dir in upload ([bdacd34](https://github.com/konflux-ci/mobster/commit/bdacd34c019363fb174eed0864eb7237aa00347f))
* **ISV-5875:** handle retry exhaustion error separately ([a5692a1](https://github.com/konflux-ci/mobster/commit/a5692a1877443a98585c3a204887d4774da7fe2b))
* **ISV-5875:** improve exit code handling ([548c9ce](https://github.com/konflux-ci/mobster/commit/548c9ce1f77f5f6cadb7ac0a3b49065626158215))
* **ISV-5875:** remove registry port restrictions ([ef16603](https://github.com/konflux-ci/mobster/commit/ef166033c55c3f3d1675606996dcbb9048343d8c))
* **ISV-5875:** support ports in image references ([5a9e258](https://github.com/konflux-ci/mobster/commit/5a9e2588038bfef8fb2856a09c0a42101ce9030b))
* **ISV-5875:** Tekton task scripts use long options ([f012ec2](https://github.com/konflux-ci/mobster/commit/f012ec22cd2606f9250cca60376e368b39a94a32))
* **ISV-5875:** use enum for upload exit codes ([8cbf681](https://github.com/konflux-ci/mobster/commit/8cbf681b2e1f6513338bebee0625055e9a31c515))
* **ISV-5875:** use upload report for S3 retry ([9bed081](https://github.com/konflux-ci/mobster/commit/9bed0814b215a081d84d9ca3a960e9115c725900))
* **ISV-5992:** add sbom-path arg to TKN scripts ([95b981b](https://github.com/konflux-ci/mobster/commit/95b981bb89e17ed21cc94f638aff09ca84659420))
* **ISV-5992:** add tkn task for product SBOMs ([3c59bc8](https://github.com/konflux-ci/mobster/commit/3c59bc8beadafee241e086f2a662156ae6f5e518))
* **ISV-5992:** create product SBOM creation task ([785d33f](https://github.com/konflux-ci/mobster/commit/785d33fdbd3429e06cbeeec216b7f1585b8693cf))
* **ISV-6007:** Implement list and download and delete TPA commands ([ee4f335](https://github.com/konflux-ci/mobster/commit/ee4f335c707799f0c2bcb0d3ae6256ffb0a53b8c))
* **ISV-6007:** Implement list and download and delete TPA commands ([e40f37a](https://github.com/konflux-ci/mobster/commit/e40f37a793ecead9766957a40dcc36c216e9db98))
* move tpa url to pytest param ([9d9e7c6](https://github.com/konflux-ci/mobster/commit/9d9e7c63d50b87f2f4c21d9e2decacf651464e30))
* prototype integration tests ([7fce317](https://github.com/konflux-ci/mobster/commit/7fce31746ee9605f40601e50be33edd0c65a6c6d))
* remove verbose debug logging ([e00b2ce](https://github.com/konflux-ci/mobster/commit/e00b2ce8a15cafba5df47319fe38dc3317be4487))
* Simplify the Github release process ([a13409f](https://github.com/konflux-ci/mobster/commit/a13409f956c811184ae76fc26fabc0fb98dcca82))
* Simplify the Github release process ([993046d](https://github.com/konflux-ci/mobster/commit/993046d28062893469cf3bec6b56991dddd57d55))
* skip int tests in tox github action ([1733d6b](https://github.com/konflux-ci/mobster/commit/1733d6b0142bccf3e1540c1b383098b8007ca273))
* specify commit digest for product task ([d898189](https://github.com/konflux-ci/mobster/commit/d898189abe9afdf3cb34fa149757b43cbc14334d))
* specify commit digest for product task ([abdc3de](https://github.com/konflux-ci/mobster/commit/abdc3de3cb750d38b3745abf0a9bb872f29ad615))
* Support multi-arch builds with all available arches ([8c923b0](https://github.com/konflux-ci/mobster/commit/8c923b0da039414675b6229f07c22e00d65f5b14))
* use newest commit in component tekton task ([490dea7](https://github.com/konflux-ci/mobster/commit/490dea7385540c86b6b69a84670150e88937ed14))
* use newest commit in component tekton task ([41328cd](https://github.com/konflux-ci/mobster/commit/41328cd5ccfdd03e8c1429ce902fb5373ace3f3d))


### Bug Fixes

* Add arch parameters to the right place ([96d0877](https://github.com/konflux-ci/mobster/commit/96d0877a960334b8ff7d60f025b67e1943f691e1))
* Add arch parameters to the right place ([b8df482](https://github.com/konflux-ci/mobster/commit/b8df48207f4e2b8608548457adb4b8eb3ebab10b))
* add missing arg ([0732611](https://github.com/konflux-ci/mobster/commit/073261142b8537ad1fe2729a394fbd6aa187ea22))
* add missing upload report to atlas upload script ([7d5da7c](https://github.com/konflux-ci/mobster/commit/7d5da7c6e3d3928acf130741f066cdf713739347))
* **ISV-5875:** remove extra pass ([8c94ba0](https://github.com/konflux-ci/mobster/commit/8c94ba091db471f7cfbd7d8d545ba44b78c21618))
* remove unused code branch ([487e985](https://github.com/konflux-ci/mobster/commit/487e985166039698cbc86db03bd19f2d2c8a2178))


### Documentation

* add docs to OCI client ([b43ed15](https://github.com/konflux-ci/mobster/commit/b43ed15b8e23f53cb05753b6215a97d22351ebd9))
* add docstrings ([e885128](https://github.com/konflux-ci/mobster/commit/e885128776889990177d28ed39957856f8d9e043))
* add integration test docs ([91e495f](https://github.com/konflux-ci/mobster/commit/91e495fd73647bc089dd26bc5448689658a41eaa))
* **ISV-5875:** expand trusted artifact references ([9a693f8](https://github.com/konflux-ci/mobster/commit/9a693f8bf041a527c4a7d34f496872aa3f00f0d4))
* **ISV-5992:** expand TA references ([4a30be7](https://github.com/konflux-ci/mobster/commit/4a30be77c6a2f05bdccf073a49796a33309fabd6))

## [0.4.0](https://github.com/konflux-ci/mobster/compare/v0.3.0...v0.4.0) (2025-06-24)


### Features

* add CLI arg for upload report ([e1deaf4](https://github.com/konflux-ci/mobster/commit/e1deaf4f3427bab69fdd2d27ecb891f590dfe373))
* Add version label to the Containerfile ([8ce1c4e](https://github.com/konflux-ci/mobster/commit/8ce1c4e9fdcf55cc580a9591fb6e20e9aa5e0484))
* Add version label to the Containerfile ([b0c82af](https://github.com/konflux-ci/mobster/commit/b0c82af6669edef22d1c4d94623b7014be09df5c))
* **ISV-5785:** add CLI arg for upload report ([e636c76](https://github.com/konflux-ci/mobster/commit/e636c76924b56cad364713666be65032ba291224))
* **ISV-5860:** implement generate product cmd ([43d498a](https://github.com/konflux-ci/mobster/commit/43d498a8d7908458527018cb1784f79fd6e3832d))
* **ISV-5875:** install AWS cli in mobster image ([a341a17](https://github.com/konflux-ci/mobster/commit/a341a1792d18bffe37d6d0f0c1010f3b176c4012))
* **ISV-5875:** install AWS cli in mobster image ([156aeea](https://github.com/konflux-ci/mobster/commit/156aeead66a03f5e8dfb313c537ffddc5581eea7))
* **ISV-6033:** limit concurrency in SBOM augmentation ([f34f457](https://github.com/konflux-ci/mobster/commit/f34f45797827c1549221134f60594974a4db5f3a))
* **ISV-6033:** limit concurrency in SBOM augmentation ([b64abb7](https://github.com/konflux-ci/mobster/commit/b64abb703f7b05649c1e45b1103cd648b29adc23))
* support symlinks in TPA upload ([bd71dc4](https://github.com/konflux-ci/mobster/commit/bd71dc4bcb86f69c462d1db88a81e2d7e05e538a))


### Bug Fixes

* Correct number of workers for TPA upload ([6092bd3](https://github.com/konflux-ci/mobster/commit/6092bd3059ee114c4c923d1baad57b69b89ca501))
* Correct number of workers for TPA upload ([bf74bf3](https://github.com/konflux-ci/mobster/commit/bf74bf3da8515312afe287d4cef1436aa1e211a0))
* exit with correct code on sbom augment ([ad7301f](https://github.com/konflux-ci/mobster/commit/ad7301fa8d01c7e58e3cdf44db8e92384f328d6e))
* exit with correct code on sbom augment ([70d45b5](https://github.com/konflux-ci/mobster/commit/70d45b5f106f4f751c4bc3420212c01d3a7b8f08))
* find SBOMs recursively ([27cad8d](https://github.com/konflux-ci/mobster/commit/27cad8de44704efa53a168b1a008d68fdea5eb7d))
* make status handling more explicit ([794d0c3](https://github.com/konflux-ci/mobster/commit/794d0c354a9055bc1777d3bcaf60a8bba9b1d21a))
* use directory path as prefix in upload ([d738aef](https://github.com/konflux-ci/mobster/commit/d738aefef86e284a4a51070b6d7ca52887589bae))
* use directory path as prefix in upload ([d3d5382](https://github.com/konflux-ci/mobster/commit/d3d53823db85e66865bdc0f4484eae7023f7771b))
* use old TypeVar syntax in merge module ([277a9e3](https://github.com/konflux-ci/mobster/commit/277a9e35678e19de054f6bb885891cdf97b027e5))


### Documentation

* **ISV-5860:** add docstring to save method ([816ea07](https://github.com/konflux-ci/mobster/commit/816ea07d16ed41af5398d793e4552fd03ed003e7))
* **ISV-5860:** add google style docstrings ([59688ac](https://github.com/konflux-ci/mobster/commit/59688ac6ad3f6e27318289edaf61f5c743dffde1))
* **ISV-5860:** fixup docstrings ([d87efce](https://github.com/konflux-ci/mobster/commit/d87efcea7ce70bb3f7941f491e6fe027429b1cc8))

## [0.3.0](https://github.com/konflux-ci/mobster/compare/v0.2.1...v0.3.0) (2025-06-10)


### Features

* Add code coverage github action ([2da25ae](https://github.com/konflux-ci/mobster/commit/2da25ae7fac3c22cee6ba2966a3fa4f654e534e2))
* **ISV-5870:** Generator for oci-artifact ([f297aa8](https://github.com/konflux-ci/mobster/commit/f297aa8ca66fa1cc4e252a0b62fa659d2f6e0705))
* **ISV-5870:** Generator for oci-artifact ([84f1bdf](https://github.com/konflux-ci/mobster/commit/84f1bdf6fffff7f960ede99bbdb75bed0588dde6))
* **ISV-5877:** Implement uploading to TPA ([fb7748f](https://github.com/konflux-ci/mobster/commit/fb7748f6b2eca860fdbb733d5a1d9f52c2bedc22))
* **ISV-5877:** Implement uploading to TPA ([0ff8d03](https://github.com/konflux-ci/mobster/commit/0ff8d0383cbad779493066f43442190d2650c381))


### Bug Fixes

* **ISV-5982:** link to arch-specific images ([2eecb63](https://github.com/konflux-ci/mobster/commit/2eecb63b5757309947fb3e199c2e566741d80ec6))
* Properly mock OIDC responses ([8e38a55](https://github.com/konflux-ci/mobster/commit/8e38a550e946b80ecabdec0a481687f92638c794))
* Properly mock OIDC responses ([6874935](https://github.com/konflux-ci/mobster/commit/68749351936429cfec30283d189ab5b575aabb5e))


### Documentation

* Update a release documentation ([0f071e5](https://github.com/konflux-ci/mobster/commit/0f071e53ad99d10252b3511e773527569e67ba88))

## 0.2.1 (2025-06-04)


### Features

* add binaries to Containerfile ([8d77ccf](https://github.com/konflux-ci/mobster/commit/8d77ccf155e00825f9ba540a44d4d1c8226e92b0))
* add binaries to Containerfile ([832747c](https://github.com/konflux-ci/mobster/commit/832747ce66b306441ea73ac79103c1763f9e3c84))
* add modelcar main component under components ([4de023e](https://github.com/konflux-ci/mobster/commit/4de023e78e05873a4d68607b14ade210c3a5cf86))
* add modelcar main component under components ([0f20854](https://github.com/konflux-ci/mobster/commit/0f20854bb036a90550d8c480a7621c2b2b69d98b))
* break generate commands to submodules ([44c250d](https://github.com/konflux-ci/mobster/commit/44c250d6cafdd782de16d32b32fef4eaadb5f1d7))
* break generate commands to submodules ([31ff5c2](https://github.com/konflux-ci/mobster/commit/31ff5c2de4a57f74aeb077de7fcb5618155b1d17))
* **ISV-5856:** Add CLI interface + generators ([aa27722](https://github.com/konflux-ci/mobster/commit/aa27722340d86ae8e9c82557c333b37894a030b2))
* **ISV-5856:** Add CLI interface + generators ([a95736b](https://github.com/konflux-ci/mobster/commit/a95736b414a72c72d959745314db7bc0be402f3a))
* **ISV-5857:** Port SBOM merging helper functions ([15e20be](https://github.com/konflux-ci/mobster/commit/15e20bec8623400fbb0115541f8c6aa7681dd93b))
* **ISV-5857:** SBOM merging helper functions ([d6c98ee](https://github.com/konflux-ci/mobster/commit/d6c98eeea8842c23ecff247335b033d20869002a))
* **ISV-5859:** Add index image SBOM generator ([81f31fd](https://github.com/konflux-ci/mobster/commit/81f31fd2b208d73176eab1ec0772ea2d2241250f))
* **ISV-5859:** Add index image SBOM generator ([795c1ef](https://github.com/konflux-ci/mobster/commit/795c1ef6cce1a3992cc0784373357b0c0914a089))
* **ISV-5861:** Add modelcar SBOM generator ([445724a](https://github.com/konflux-ci/mobster/commit/445724a65cecbe7f25ed692411e3de73d0a861a7))
* **ISV-5861:** Add modelcar SBOM generator ([ba8d971](https://github.com/konflux-ci/mobster/commit/ba8d9710995f8fe6970ae612f7fc916f3d4af3fd))
* **ISV-5878:** automate release of Mobster python package ([1100077](https://github.com/konflux-ci/mobster/commit/1100077da1a4d6135ce897b09eef251f21fb5d57))
* **ISV-5881:** implement "mobster augment" command ([144cadc](https://github.com/konflux-ci/mobster/commit/144cadc5fb031ce275c61467ccaed1d30787c8b6))
* **ISV-5881:** implement augment command ([3053186](https://github.com/konflux-ci/mobster/commit/30531865b21416892a9e8a141c08ab4039b23b45))
* **ISV-5881:** implement podman-login auth process ([a77b119](https://github.com/konflux-ci/mobster/commit/a77b119c19661504571b73143abfeea5249593b8))
* **ISV-5881:** simplify CLI API ([7796694](https://github.com/konflux-ci/mobster/commit/779669474995ca9070fd8809584134fea7956455))
* **ISV-5882:** install root package in tox ([b5d6367](https://github.com/konflux-ci/mobster/commit/b5d6367b79a6c99d28c9f6856caf8faafd94fd3c))
* **ISV-5882:** populate mobster version ([14522dd](https://github.com/konflux-ci/mobster/commit/14522dd00adf6b41db1c52af621a23fbd6a22daa))
* **ISV-5882:** set creationInfo when editing SBOMs ([f7e2a4d](https://github.com/konflux-ci/mobster/commit/f7e2a4dc56edec01050f8e36c2ab0309e7576ced))


### Bug Fixes

* delete release-please actions ([bec8ba4](https://github.com/konflux-ci/mobster/commit/bec8ba4970bbe3307b19c4b5c231bc87750c0691))
* delete release-please actions ([552b033](https://github.com/konflux-ci/mobster/commit/552b0332fa355d83ffaa93500af931638b093bce))
* **ISV-5857:** fix mypy and ruff check ([1f7b1c9](https://github.com/konflux-ci/mobster/commit/1f7b1c9628b8b2952a5ac84c67b100dd80c22e4a))
* **ISV-5881:** assert save returns True ([51ab34c](https://github.com/konflux-ci/mobster/commit/51ab34cb8d5ea70f5ea3a6d1c7a06dbf97a7698e))
* **ISV-5881:** ignore unimplemented code ([e943df3](https://github.com/konflux-ci/mobster/commit/e943df3ac64ee05cf6670a8e6b1d84676df7748d))
* **ISV-5881:** move output arg to stay consistent ([b9b4b11](https://github.com/konflux-ci/mobster/commit/b9b4b11728ff58dc5d3d2dc111980ab9aac81e8c))
* **ISV-5881:** resolve pylint suggestions ([98d9087](https://github.com/konflux-ci/mobster/commit/98d9087a1e1d01210c99c0ca7e02d3eae0a65045))
* **ISV-5881:** use __name__ in getLogger ([80f1cd8](https://github.com/konflux-ci/mobster/commit/80f1cd87b6aa44f31fbac90987fbcdd6e5c92963))
* **ISV-5881:** use ruff format to format ([7ed0da1](https://github.com/konflux-ci/mobster/commit/7ed0da1132bcf242cb410a4f1f897a1b59831bf9))


### Documentation

* **ISV-5881:** add augment oci-image doc ([4369ba3](https://github.com/konflux-ci/mobster/commit/4369ba3c0c0869ee4102219d8e251a3a4c99ba17))
* **ISV-5881:** augment docstrings ([1c8a465](https://github.com/konflux-ci/mobster/commit/1c8a46524b00768d3bfa8720cbb426d47a55752b))
* **ISV-5881:** elaborate on decisions ([6c17c3d](https://github.com/konflux-ci/mobster/commit/6c17c3d2cf65c9e4daf6d5befceea2000591f630))
* **ISV-5881:** make docstrings accurate ([3b495b0](https://github.com/konflux-ci/mobster/commit/3b495b0dc8cd3f1817a836fddc96123c83eee275))
