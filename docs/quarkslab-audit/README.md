# Code audit by Quarkslab

A code audit of this library was conducted by [Quarkslab](https://www.quarkslab.com/), primarily focusing on determination of the correctness and soundness of the implementation, as well as optimizations and extensions.
As the audit was conducted at a [specific point](https://github.com/tari-project/bulletproofs-plus/releases/tag/pre-audit-commit) in the repository history, readers should carefully note that subsequent changes may not have been examined by the auditors.

The [full report](report.pdf) is available in this repository.

The report did not identify any particular security issues, but provided recommendations to improve the codebase and make it more robust against future changes.
An initial draft version of the report identified three findings: `LOW 1`, `INFO 1`, and `INFO 2`.
We provide context and responses to each finding here, but direct readers to the full report for details.

## `LOW 1`

This issue noted that the [`merlin`](https://crates.io/crates/merlin) crate used by the implementation for Fiat-Shamir transcripting appears to be unmaintained, as it had not been updated in over two years at the time of writing.
The report recommended that Tari produce a fork of this repository.

### Response

To our knowledge, no security-related issues have been reported that would render the use of the `merlin` crate unsafe.
Further, no particular dependency conflicts have been identified due to the lack of apparent maintenance.

For these reasons, producing a fork does not appear to be necessary, as this would merely increase complexity and technical debt.
As with any core dependency, any future security-related issues arising in `merlin` would be addressed as appropriate.

## `INFO 1`

This issue noted the curve library [fork](https://crates.io/crates/tari-curve25519-dalek) used in the implementation is not up to date with the [upstream](https://crates.io/crates/curve25519-dalek) repository.
The report recommended that Tari bring the fork up to date.

### Response

The fork was initially made due to the upstream repository being apparently unmaintained, which resulted in a number of dependency conflicts.
Additionally, the fork added support for multiscalar multiplication [partial precomputation](https://github.com/tari-project/curve25519-dalek/pull/1) that was not supported by upstream.
Since that time, upstream has undergone a flurry of activity and updates; during this process, the fork was rebased against the upstream [`4.0.0-rc.3`](https://github.com/dalek-cryptography/curve25519-dalek/releases/tag/4.0.0-rc.3) tag.
Subsequent to this rebase, the upstream repository was significantly restructured, and the fork has not been updated to reflect this.
We did not identify any particular security-related issues addressed since this time.
Unfortunately, the versioning scheme used in the fork conflicts somewhat with the upstream versioning; the fork currently is on the [`v4.0.3`](https://github.com/tari-project/curve25519-dalek/releases/tag/v4.0.3) tag.

Regardless of the lack of known security issues, Tari agreed that updating the fork would be beneficial.
Developers are in the process of testing an updated version of the fork, in order to ensure such an update does not introduce conflicts in Tari repositories.

Further, an open [upstream pull request](https://github.com/dalek-cryptography/curve25519-dalek/pull/546) would add partial precomputation support; if it is accepted, the implementation could change its curve library dependency to upstream.

*Update*: The library has removed support for partial precomputation in favor of a different design.
As a result, the curve library dependency has been changed to upstream.

## `INFO 2`

This issue ran the `clippy` linter against several lints, and identified a number of warnings arising from them.
These particularly dealt with arithmetic operation side effects, slicing, and indexing that could lead to unintended behavior or panics if triggered.
The report recommended that Tari address these warnings as appropriate, but noted that their testing and analysis did not identify particular circumstances under which unintended behavior or panics would occur.

### Response

Many of the identified lint warnings were for curve-related group and scalar operations, which do not introduce risk.
These warnings do not need to be addressed.

Even though it was determined that triggering the other warnings was unlikely, Tari agreed that mitigating the warnings (as feasible) is good practice as part of a defense-in-depth approach to design.
After an early discussion with the auditors and prior to the release of an initial draft version of the report, several updates were made to the implementation that mitigated many of the warnings, particularly relating to proof deserialization and verification.
Subsequent to the release of an initial draft version of the report, additional updates were made to the implementation for further mitigation.

There remain instances in the implementation that perform unchecked arithmetic operations or indexing where mitigation would be unwieldy, complex, and more likely to introduce errors at the expense of clarity.
These cases were examined and determined to be safe as written.
As the implementation is updated, existing and future such warnings will be carefully examined.

Additionally, the implementation's CI workflow already included a [list](https://github.com/tari-project/bulletproofs-plus/blob/main/lints.toml) of lints that are automatically flagged during the development process.
This list has been expanded in order to better identify coding practices that could introduce problems.
We note that the arithmetic side-effect lint in question has not been added to this list, as it flags curve-related operations that are not at risk of unintended behavior.

*Update*: The arithmetic side-effect lint has been added.
