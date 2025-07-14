# Changelog

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
