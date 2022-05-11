[![Build](https://circleci.com/gh/tari-project/tari/tree/development.svg?style=svg)](https://circleci.com/gh/tari-project/tari/tree/development)

# Tari Bulletproofs+

## Overview

Tari Bulletproofs+ implements _Bulletproofs+: Shorter Proofs for Privacy-Enhanced Distributed Ledger_ [2],  
derived from the original _Bulletproofs: Short Proofs for Confidential Transactions and More_ [1]. The former  
offers a 96 bytes shorter proof size than the latter.

## Comparative performance

As we intend to move from Bulletproofs [1] to Bulletproofs+ [2] in our 
[blockchain project](https://github.com/tari-project), the natural benchmark comparison is with the experimental results 
in [2] and Dalek's Bulletproofs [4]. Compared with Dalek's Bulletproofs, our average proof creation and verification are 
25% and 1% slower. Compared with the experimental results in [2], we could not recreate the 16% reduction in prover 
time; however, our 1% increase in verification time is on par with their 3%. However, employing batch verification, 
immediate benefits are evident, with gains ranging from 40% to 77% for batch sizes from 2 to 64 proofs and 78% for 
batch sizes > 64 proofs.

Extended commitments add virtually no overhead in single or aggregated range proof creation or verification. Batched 
average verification time for one and two degrees of extended commitment range proofs are 4% and 9% slower when compared 
to using regular Pedersen commitments.   

**Note:** The test results listed here are relative; the numbers are not absolute. The tests were run on an Intel(R) 
Core(TM) i7-7820HQ CPU laptop without using the `simd_backend` feature.

### Aggregated 64-bit range proof creation

#### BP vs. BP+ (creation)

| Agg. size | BP mean (ms) | BP median (ms) | BP+ mean (ms) | BP+ median (ms) | Diff mean (%) | Diff median (%) |
|-----------|--------------|----------------|---------------|-----------------|---------------|-----------------|
| 1         | 17.15        | 16.29          | 20.68         | 20.67           | 121%          | 127%            |
| 2         | 31.91        | 31.63          | 40.19         | 40.08           | 126%          | 127%            |
| 4         | 60.81        | 60.47          | 78.85         | 78.61           | 130%          | 130%            |
| 8         | 118.53       | 119.18         | 152.12        | 152.31          | 128%          | 128%            |
| 16        | 240.47       | 240.18         | 299.34        | 298.62          | 124%          | 124%            |
| 32        | 471.71       | 460.67         | 583.20        | 581.92          | 124%          | 126%            |
|           |              |                |               | Average         | 125%          | 127%            |

<p align="center"><img src="./docs/assets/img_bp_vs_bp_plus_creation.png" width="550" /></p>

#### BP+ extension degrees (creation)

| Agg. size | BP+ ext_deg 0 (ms) | BP+ ext_deg 1 (ms) | BP+ ext_deg 2 (ms) | Diff ext_deg 0 vs. 1 (%) | Diff ext_deg 0 vs. 2 (%) |
|-----------|--------------------|--------------------|--------------------|--------------------------|--------------------------|
| 1         | 20.68              | 20.88              | 21.17              | 100.96%                  | 102.37%                  |
| 2         | 40.19              | 40.51              | 40.984             | 100.80%                  | 101.97%                  |
| 4         | 78.85              | 78.74              | 78.952             | 99.87%                   | 100.13%                  |
| 8         | 152.12             | 152.79             | 152.93             | 100.44%                  | 100.53%                  |
| 16        | 299.34             | 298.42             | 310.93             | 99.69%                   | 103.87%                  |
| 32        | 583.20             | 583.62             | 664.55             | 100.07%                  | 113.95%                  |
|           |                    |                    | Average            | 100%                     | 104%                     |

<p align="center"><img src="./docs/assets/img_bp_plus_creation_extension_degrees.png" width="550" /></p>

### Aggregated 64-bit range proof verification

#### BP vs. BP+ (verification)

| Agg. size | BP mean (ms) | BP median (ms) | BP+ mean (ms) | BP+ median (ms) | Diff Mean (%) | Diff Median (%) |
|-----------|--------------|----------------|---------------|-----------------|---------------|-----------------|
| 1         | 2.19         | 2.34           | 2.44          | 2.39            | 111%          | 102%            |
| 2         | 3.75         | 3.76           | 3.77          | 3.68            | 100%          | 98%             |
| 4         | 6.44         | 6.44           | 6.00          | 6.01            | 93%           | 93%             |
| 8         | 11.02        | 11.10          | 10.58         | 10.59           | 96%           | 95%             |
| 16        | 18.94        | 17.57          | 19.13         | 18.83           | 101%          | 107%            |
| 32        | 36.69        | 33.69          | 37.56         | 36.54           | 102%          | 108%            |
|           |              |                |               | Average         | 101%          | 101%            |

<p align="center"><img src="./docs/assets/img_bp_vs_bpplus_verification.png" width="550" /></p>

#### BP+ extension degrees (verification)

| Agg. size | BP+ ext_deg 0 (ms) | BP+ ext_deg 1 (ms) | BP+ ext_deg 2 (ms) | Diff ext_deg 0 vs.1 (%) | Diff ext_deg 0 vs. 2 (%) |
|-----------|--------------------|--------------------|--------------------|-------------------------|--------------------------|
| 1         | 2.44               | 2.33               | 2.25               | 96%                     | 92%                      |
| 2         | 3.77               | 4.04               | 3.59               | 107%                    | 95%                      |
| 4         | 6.00               | 6.08               | 6.05               | 101%                    | 101%                     |
| 8         | 10.58              | 10.53              | 10.67              | 100%                    | 101%                     |
| 16        | 19.13              | 18.84              | 20.07              | 98%                     | 105%                     |
| 32        | 37.56              | 35.68              | 38.05              | 95%                     | 101%                     |
|           |                    |                    | Average            | 100%                    | 99%                      |

<p align="center"><img src="./docs/assets/img_bp_plus_verification_extension_degrees.png" width="550" /></p>

### Batched 64-bit single range proof verification

| Batch size | BP+ linear (ms) | BP+ ext_deg 0 (ms) | BP+ ext_deg 1 (ms) | BP+ ext_deg 2 (ms) | Diff (%) | Gains (%) |
|------------|-----------------|--------------------|--------------------|--------------------|----------|-----------|
| 1          | 2.36            | 2.36               | 2.35               | 2.45               | 100%     | 0%        |
| 2          | 4.73            | 2.83               | 2.98               | 3.05               | 60%      | 40%       |
| 4          | 9.46            | 4.05               | 4.20               | 4.32               | 43%      | 57%       |
| 8          | 18.91           | 6.19               | 6.43               | 6.70               | 33%      | 67%       |
| 16         | 37.83           | 11.19              | 11.01              | 11.82              | 30%      | 70%       |
| 32         | 75.65           | 19.35              | 20.26              | 21.06              | 26%      | 74%       |
| 64         | 151.31          | 34.87              | 37.20              | 39.75              | 23%      | 77%       |
| 128        | 302.62          | 66.70              | 71.40              | 76.73              | 22%      | 78%       |
| 256        | 605.24          | 133.56             | 140.71             | 150.51             | 22%      | 78%       |

<p align="center"><img src="./docs/assets/img_bp_plus_batched_zoomed.png" width="550" /></p>

<p align="center"><img src="./docs/assets/img_bp_plus_batched.png" width="550" /></p>

## References

[1] [Bulletproofs: Short Proofs for Confidential Transactions and More](https://eprint.iacr.org/2017/1066/20220414:014622)

[2] [Bulletproofs+: Shorter Proofs for Privacy-Enhanced Distributed Ledger](https://eprint.iacr.org/2020/735/20200618:154806)

## Credits

[3] We used the proof of concept [Python implementation](https://github.com/AaronFeickert/pybullet-plus) by 
    [Aaron Feickert](https://github.com/AaronFeickert) as a verbatim algorithm reference.

[4] We are re-using generators and the transcript protocol from Dalek's
    [Bulletproofs](https://github.com/dalek-cryptography/bulletproofs), which in turn is built on top of Dalek's 
    [group operations on Ristretto and Curve25519](https://github.com/dalek-cryptography/curve25519-dalek).

[5] Another pre-cursor to this work is 
    [Monero's implementation](https://www.getmonero.org/2020/12/24/Bulletproofs+-in-Monero.html) of Bulletproofs+.

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
