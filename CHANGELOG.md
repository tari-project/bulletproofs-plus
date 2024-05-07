# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [0.4.0](https://github.com/tari-project/bulletproofs-plus/compare/v0.3.2...v0.4.0) (2024-05-07)


### ⚠ BREAKING CHANGES

* Changes the prover and verifier APIs to replace
transcript labels with Merlin transcripts. Changes how domain separation
is applied internally.
* Removes `verify_batch_with_rng` from the public API. No
longer requires that `verify_batch` have the `rand` feature enabled.
* Removes unused methods that were public, which is
technically a breaking change.
* Introduces a change to the `ExtensionDegree` public
API.
* Modifies the construction of commitment generators.
* Changes the batch verification API.
* Modifies the structure of serialized proofs.

### Features

* clean up serialization ([#66](https://github.com/tari-project/bulletproofs-plus/issues/66)) ([d45e062](https://github.com/tari-project/bulletproofs-plus/commit/d45e062f10cca07ea81054d0d41eb5ae0eaf5a3f)), closes [#65](https://github.com/tari-project/bulletproofs-plus/issues/65)
* compute verifier challenge sum more efficiently ([#59](https://github.com/tari-project/bulletproofs-plus/issues/59)) ([7315a61](https://github.com/tari-project/bulletproofs-plus/commit/7315a61bacab0f70013cbfb58358f27375e68a2c))
* generalize batch transcript labels ([#70](https://github.com/tari-project/bulletproofs-plus/issues/70)) ([4102dea](https://github.com/tari-project/bulletproofs-plus/commit/4102deaabecb5231133cffc0fa6784bb86697819)), closes [/github.com/tari-project/bulletproofs-plus/blob/d9d0cc9063f85684179908569227dda251981751/src/range_proof.rs#L432](https://github.com/tari-project//github.com/tari-project/bulletproofs-plus/blob/d9d0cc9063f85684179908569227dda251981751/src/range_proof.rs/issues/L432) [#64](https://github.com/tari-project/bulletproofs-plus/issues/64)
* improve zeroizing support ([#72](https://github.com/tari-project/bulletproofs-plus/issues/72)) ([c7b076f](https://github.com/tari-project/bulletproofs-plus/commit/c7b076fd11f1c79c1fc14402d636743ec7d27d1e)), closes [#71](https://github.com/tari-project/bulletproofs-plus/issues/71)
* move RNGs into `RangeProofTranscript` ([#111](https://github.com/tari-project/bulletproofs-plus/issues/111)) ([854dd88](https://github.com/tari-project/bulletproofs-plus/commit/854dd885859c5ef772e731d34dfe4de7f9cbe636)), closes [#109](https://github.com/tari-project/bulletproofs-plus/issues/109) [/github.com/tari-project/bulletproofs-plus/pull/109#discussion_r1449861417](https://github.com/tari-project//github.com/tari-project/bulletproofs-plus/pull/109/issues/discussion_r1449861417)
* refactor inner-product prover ([#57](https://github.com/tari-project/bulletproofs-plus/issues/57)) ([aa7593f](https://github.com/tari-project/bulletproofs-plus/commit/aa7593f5e25a9770bf82f9a922864648afb93f5e)), closes [/github.com/tari-project/bulletproofs-plus/blob/d9d0cc9063f85684179908569227dda251981751/src/inner_product_round.rs#L111-L112](https://github.com/tari-project//github.com/tari-project/bulletproofs-plus/blob/d9d0cc9063f85684179908569227dda251981751/src/inner_product_round.rs/issues/L111-L112) [#61](https://github.com/tari-project/bulletproofs-plus/issues/61) [#55](https://github.com/tari-project/bulletproofs-plus/issues/55) [#56](https://github.com/tari-project/bulletproofs-plus/issues/56)
* remove partial precomputation ([#129](https://github.com/tari-project/bulletproofs-plus/issues/129)) ([58409fa](https://github.com/tari-project/bulletproofs-plus/commit/58409fae76b9fcc17761b51052a2b200b6939127)), closes [#128](https://github.com/tari-project/bulletproofs-plus/issues/128) [#93](https://github.com/tari-project/bulletproofs-plus/issues/93) [#96](https://github.com/tari-project/bulletproofs-plus/issues/96)
* remove verifier RNG requirement ([#116](https://github.com/tari-project/bulletproofs-plus/issues/116)) ([8759a59](https://github.com/tari-project/bulletproofs-plus/commit/8759a59a1feaa9b4ae99475e107e49f7a0ca8ff5)), closes [#110](https://github.com/tari-project/bulletproofs-plus/issues/110)
* replace `lazy_static` with `once_cell` ([#69](https://github.com/tari-project/bulletproofs-plus/issues/69)) ([e01c380](https://github.com/tari-project/bulletproofs-plus/commit/e01c380186111c1fbe3fba213d1b492beff11b9d)), closes [/github.com/tari-project/bulletproofs-plus/blob/502ae9fa35a39afc5793210e4301023a7ca7ea60/src/ristretto.rs#L154-L179](https://github.com/tari-project//github.com/tari-project/bulletproofs-plus/blob/502ae9fa35a39afc5793210e4301023a7ca7ea60/src/ristretto.rs/issues/L154-L179) [#67](https://github.com/tari-project/bulletproofs-plus/issues/67)
* simplify dependencies ([#105](https://github.com/tari-project/bulletproofs-plus/issues/105)) ([21601db](https://github.com/tari-project/bulletproofs-plus/commit/21601dbffce6b4d46c0fcd926034c21dff659b62)), closes [#104](https://github.com/tari-project/bulletproofs-plus/issues/104) [#104](https://github.com/tari-project/bulletproofs-plus/issues/104)
* support `no-std` environments ([#107](https://github.com/tari-project/bulletproofs-plus/issues/107)) ([bce16c4](https://github.com/tari-project/bulletproofs-plus/commit/bce16c4f8a7dbdc5cb7792ad2d99df495ad2e95c))
* use Merlin's `TranscriptRng` for random number generation ([6f1aab6](https://github.com/tari-project/bulletproofs-plus/commit/6f1aab69942f04ec6c81263d9e173fe06eb009e6))
* use transcript composition ([#115](https://github.com/tari-project/bulletproofs-plus/issues/115)) ([6be2bda](https://github.com/tari-project/bulletproofs-plus/commit/6be2bda1dfe13b6e14ea14ac58e28250051640ef)), closes [/github.com/tari-project/bulletproofs-plus/blob/da71f7872f02a0e9d3000c316bb083181daa9942/src/transcripts.rs#L72](https://github.com/tari-project//github.com/tari-project/bulletproofs-plus/blob/da71f7872f02a0e9d3000c316bb083181daa9942/src/transcripts.rs/issues/L72) [#114](https://github.com/tari-project/bulletproofs-plus/issues/114)


### Bug Fixes

* add check for unused deserialization data ([#83](https://github.com/tari-project/bulletproofs-plus/issues/83)) ([55191b8](https://github.com/tari-project/bulletproofs-plus/commit/55191b83fddfca46f55205b49b7b90768d884392)), closes [/github.com/tari-project/bulletproofs-plus/blob/e01c380186111c1fbe3fba213d1b492beff11b9d/src/range_proof.rs#L1017-L1020](https://github.com/tari-project//github.com/tari-project/bulletproofs-plus/blob/e01c380186111c1fbe3fba213d1b492beff11b9d/src/range_proof.rs/issues/L1017-L1020) [#82](https://github.com/tari-project/bulletproofs-plus/issues/82)
* add missing dollar sign ([#121](https://github.com/tari-project/bulletproofs-plus/issues/121)) ([f9fec4d](https://github.com/tari-project/bulletproofs-plus/commit/f9fec4d99ee377d9decde1360b0608e6d8a7ec7b))
* audit updates ([#87](https://github.com/tari-project/bulletproofs-plus/issues/87)) ([5b87644](https://github.com/tari-project/bulletproofs-plus/commit/5b8764421447a935416b2336915740e866d514cf))
* clean up getter functions and remove clones ([#63](https://github.com/tari-project/bulletproofs-plus/issues/63)) ([502ae9f](https://github.com/tari-project/bulletproofs-plus/commit/502ae9fa35a39afc5793210e4301023a7ca7ea60))
* don't panic on inconsistent generators ([#100](https://github.com/tari-project/bulletproofs-plus/issues/100)) ([1f5c8a0](https://github.com/tari-project/bulletproofs-plus/commit/1f5c8a0cd1de5ec5c4322b5bbee11e1dd51fcf25)), closes [#99](https://github.com/tari-project/bulletproofs-plus/issues/99)
* improve prover consistency checks ([#98](https://github.com/tari-project/bulletproofs-plus/issues/98)) ([09ac06c](https://github.com/tari-project/bulletproofs-plus/commit/09ac06c1ca06a4000186ad3e4ce8cae996adb2bc)), closes [#97](https://github.com/tari-project/bulletproofs-plus/issues/97)
* pin nightly version on source cov workflow ([#120](https://github.com/tari-project/bulletproofs-plus/issues/120)) ([1aa7694](https://github.com/tari-project/bulletproofs-plus/commit/1aa769490ba96ba8d56e102b5cf079ba091134a9))
* prover cleanup ([#89](https://github.com/tari-project/bulletproofs-plus/issues/89)) ([7da7bbc](https://github.com/tari-project/bulletproofs-plus/commit/7da7bbc8fb0a5f7e1f6e023012a1a425822cbd83)), closes [#88](https://github.com/tari-project/bulletproofs-plus/issues/88)
* reduce verification vector allocation ([#127](https://github.com/tari-project/bulletproofs-plus/issues/127)) ([6c4bfe0](https://github.com/tari-project/bulletproofs-plus/commit/6c4bfe01b1f835a669d8e58790c8e01051290294)), closes [#126](https://github.com/tari-project/bulletproofs-plus/issues/126)
* update source coverage script ([#122](https://github.com/tari-project/bulletproofs-plus/issues/122)) ([e902989](https://github.com/tari-project/bulletproofs-plus/commit/e90298906f7709aa1ce913d8e4abb605d3279ed8))
* verifier overflow checks ([#62](https://github.com/tari-project/bulletproofs-plus/issues/62)) ([e71a275](https://github.com/tari-project/bulletproofs-plus/commit/e71a27505b7e0c7e288456bbf37e8a5997c86c18)), closes [#60](https://github.com/tari-project/bulletproofs-plus/issues/60) [#60](https://github.com/tari-project/bulletproofs-plus/issues/60)


* clean up `ExtensionDegree` ([#85](https://github.com/tari-project/bulletproofs-plus/issues/85)) ([da57859](https://github.com/tari-project/bulletproofs-plus/commit/da57859f8eac1596fb025223ab1897d2814e90ff))
* unused method cleanup ([#90](https://github.com/tari-project/bulletproofs-plus/issues/90)) ([48da00a](https://github.com/tari-project/bulletproofs-plus/commit/48da00aa3430af61b3f72ed15554e7638ac411d0)), closes [#87](https://github.com/tari-project/bulletproofs-plus/issues/87)

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
