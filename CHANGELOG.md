# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.3.2](https://github.com/tari-project/bulletproofs-plus/compare/v0.3.1...v0.3.2) (2023-08-07)


### Features

* change precomputation `rc` to `arc` ([#44](https://github.com/tari-project/bulletproofs-plus/issues/44)) ([d495fb2](https://github.com/tari-project/bulletproofs-plus/commit/d495fb24f9c7c34e0bfb0a38598b67e216fc56bf))
* minor verifier optimizations ([#53](https://github.com/tari-project/bulletproofs-plus/issues/53)) ([7960214](https://github.com/tari-project/bulletproofs-plus/commit/796021499f3812908cfd0409951a1c944d4b71fc))
* simplify inner-product generator folding ([#52](https://github.com/tari-project/bulletproofs-plus/issues/52)) ([271892c](https://github.com/tari-project/bulletproofs-plus/commit/271892c7727547da7024500e5b77a2d5894eaa3f))


### Bug Fixes

* promise check in range statement ([#48](https://github.com/tari-project/bulletproofs-plus/issues/48)) ([3e0008e](https://github.com/tari-project/bulletproofs-plus/commit/3e0008e31a55a30ee1b9c1849cd3861a5687616f))
* reduce vector capacity ([#45](https://github.com/tari-project/bulletproofs-plus/issues/45)) ([9caa0c9](https://github.com/tari-project/bulletproofs-plus/commit/9caa0c9985ae85363ed2751042d14485c25f62a6))

### [0.3.1](https://github.com/tari-project/bulletproofs-plus/compare/v0.3.0...v0.3.1) (2023-07-18)

### [0.3.0](https://github.com/tari-project/bulletproofs-plus/compare/v0.2.3...v0.3.0) (2023-07-13)


### ⚠ BREAKING CHANGES

* Changes the way that seed nonces are used in mask
recovery. Existing range proofs will verify, but will fail to recover
the correct mask.

### Features

* simplify bit vector commitment ([#35](https://github.com/tari-project/bulletproofs-plus/issues/35)) ([f831d64](https://github.com/tari-project/bulletproofs-plus/commit/f831d64c1bc559c1603d375eae4b2c5b438a1c8b)), closes [/github.com/tari-project/bulletproofs-plus/blob/cd7588ee8eaebe862fe9cf5d7c3fd92981703e87/src/range_proof.rs#L265-L273](https://github.com/tari-project//github.com/tari-project/bulletproofs-plus/blob/cd7588ee8eaebe862fe9cf5d7c3fd92981703e87/src/range_proof.rs/issues/L265-L273)
* use precomputation on (most) fixed generators ([#19](https://github.com/tari-project/bulletproofs-plus/issues/19)) ([cd7588e](https://github.com/tari-project/bulletproofs-plus/commit/cd7588ee8eaebe862fe9cf5d7c3fd92981703e87)), closes [#18](https://github.com/tari-project/bulletproofs-plus/issues/18)


### Bug Fixes

* nonce index encoding ([#31](https://github.com/tari-project/bulletproofs-plus/issues/31)) ([394843f](https://github.com/tari-project/bulletproofs-plus/commit/394843fd84ed10fe240f8625b855ced4e953cb69))

### [0.2.3](https://github.com/tari-project/bulletproofs-plus/compare/v0.2.2...v0.2.3) (2023-04-03)

### [0.2.2](https://github.com/tari-project/bulletproofs-plus/compare/v0.2.1...v0.2.2) (2023-04-03)


### Bug Fixes

* fix rand_core inequality ([#26](https://github.com/tari-project/bulletproofs-plus/issues/26)) ([213f788](https://github.com/tari-project/bulletproofs-plus/commit/213f788cf6aba765dd49caefd40affe9aaddcc6e))

### [0.2.1](https://github.com/tari-project/bulletproofs-plus/compare/v0.2.0...v0.2.1) (2023-01-03)


### Features

* add status badges to readme ([2f063be](https://github.com/tari-project/bulletproofs-plus/commit/2f063beba9b2d15e41a2e31b866ce04a88654f6f))


### Bug Fixes

* exclude dalek from source test coverage ([7cae60b](https://github.com/tari-project/bulletproofs-plus/commit/7cae60b8656438c1de2793ab2c68abedb35c8b13))
* make test_coverage.sh executable ([cf1f46f](https://github.com/tari-project/bulletproofs-plus/commit/cf1f46f88ad01e6134f418dfb1ca4a2bac3ea6bb))
* update test coverage script ([5c36bdf](https://github.com/tari-project/bulletproofs-plus/commit/5c36bdfb422295dc1ff85967d7ff75e1989f0f3e))

## [0.2.0](https://github.com/tari-project/bulletproofs-plus/compare/v0.1.1...v0.2.0) (2022-12-14)


### ⚠ BREAKING CHANGES

* split batches for verification (#22)

### Features

* split batches for verification ([#22](https://github.com/tari-project/bulletproofs-plus/issues/22)) ([531bae6](https://github.com/tari-project/bulletproofs-plus/commit/531bae6cce6cae4cb78f8543d309ee71a7f14915))

### [0.1.1](https://github.com/tari-project/bulletproofs-plus/compare/v0.1.0...v0.1.1) (2022-11-24)


### Bug Fixes

* relax zeroize ([#20](https://github.com/tari-project/bulletproofs-plus/issues/20)) ([4e041dd](https://github.com/tari-project/bulletproofs-plus/commit/4e041dd6a34e87f2c197aa4f7e02c99e2806d8a6))

### [0.0.7](https://github.com/tari-project/bulletproofs-plus/compare/v0.0.6...v0.0.7) (2022-10-03)


### Features

* port to dalek for curve ([#16](https://github.com/tari-project/bulletproofs-plus/issues/16)) ([d756340](https://github.com/tari-project/bulletproofs-plus/commit/d7563404ca7bc6b47f2c5122a6c84667fe7daf05))

### [0.0.6](https://github.com/tari-project/bulletproofs-plus/compare/v0.0.5...v0.0.6) (2022-06-23)

### [0.0.5](https://github.com/tari-project/bulletproofs-plus/compare/v0.0.4...v0.0.5) (2022-06-13)


### Features

* add methods to retrieve extension degree ([#14](https://github.com/tari-project/bulletproofs-plus/issues/14)) ([670ebdf](https://github.com/tari-project/bulletproofs-plus/commit/670ebdf70ce2141ab90fc5a22ffb8fd98fe9f148))

### [0.0.4](https://github.com/tari-project/bulletproofs-plus/compare/v0.0.3...v0.0.4) (2022-06-03)

### [0.0.3](https://github.com/tari-project/bulletproofs-plus/compare/v0.0.2...v0.0.3) (2022-05-31)


### Bug Fixes

* avoids copying in the commit method ([#12](https://github.com/tari-project/bulletproofs-plus/issues/12)) ([ab4c432](https://github.com/tari-project/bulletproofs-plus/commit/ab4c4324e949822a741249360d97bec4a5684a59)), closes [/github.com/dalek-cryptography/curve25519-dalek/blob/0d49dfacf66bed4b41e445d0e6942b3c27f3b263/src/traits.rs#L114](https://github.com/tari-project//github.com/dalek-cryptography/curve25519-dalek/blob/0d49dfacf66bed4b41e445d0e6942b3c27f3b263/src/traits.rs/issues/L114)

### [0.0.2](https://github.com/tari-project/bulletproofs-plus/compare/v0.0.1...v0.0.2) (2022-05-31)


### Features

* relax commit bounds ([#10](https://github.com/tari-project/bulletproofs-plus/issues/10)) ([4ec07aa](https://github.com/tari-project/bulletproofs-plus/commit/4ec07aa89f5ef6388607e8407e9251225bf8cae3))
