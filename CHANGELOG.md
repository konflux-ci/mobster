# Changelog

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
