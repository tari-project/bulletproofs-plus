[![Build](https://circleci.com/gh/tari-project/tari/tree/development.svg?style=svg)](https://circleci.com/gh/tari-project/tari/tree/development)
![](https://github.com/tari-project/bulletproofs-plus/workflows/Security%20audit/badge.svg)
![](https://github.com/tari-project/bulletproofs-plus/workflows/Clippy/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/tari-project/bulletproofs-plus/badge.svg?branch=main)](https://coveralls.io/github/tari-project/bulletproofs-plus?branch=main)


# Tari Bulletproofs+

A speedy implementation of the [Bulletproofs+](https://eprint.iacr.org/2020/735) range proving system that does fun tricks.

In particular, it supports:
- **Proof aggregation**. You can generate a proof containing multiple range assertions in an efficient way.
- **Extended commitments**. Commitments may contain multiple masks.
- **Batch verification**. Verifying a set of multiple proofs is extremely fast.
- **Minimum value promises**. You can additionally prove that a commitment binds to at least a specified value.
- **Mask extraction**. If the prover and verifier agree on a shared secret, the verifier can use it to recover the mask used for the commitment in a non-aggregated proof.

Unlike the original [Bulletproofs](https://eprint.iacr.org/2017/1066) range proving system, Bulletproofs+ is:
- **Smaller**. Regardless of the aggregation factor, a Bulletproofs+ proof is 96 bytes shorter.
- **Faster**. Compared to a [fork](https://github.com/tari-project/bulletproofs) of the `dalek-cryptography` [Bulletproofs](https://github.com/dalek-cryptography/bulletproofs) implementation, this implementation verifies non-aggregated proofs in only ~85% of the time.

As always, your mileage may vary.

## References

This implementation takes its cue from the `dalek-cryptography` [Bulletproofs](https://github.com/dalek-cryptography/bulletproofs) implementation, as well as the Monero [Bulletproofs+](https://www.getmonero.org/2020/12/24/Bulletproofs+-in-Monero.html) implementation.

Several of the features and optimizations used in this implementation are described in [Tari RFC-0181](https://rfc.tari.com/RFC-0181_BulletproofsPlus.html).

## Copyright

All original source code files are marked with
```
Copyright 2022 The Tari Project
SPDX-License-Identifier: BSD-3-Clause
```
All re-used and or adapted `dalek-cryptography` source code files are marked with
```
Copyright 2022 The Tari Project
SPDX-License-Identifier: BSD-3-Clause
  Modified from:
    Copyright (c) 2018 Chain, Inc.
    SPDX-License-Identifier: MIT
```
