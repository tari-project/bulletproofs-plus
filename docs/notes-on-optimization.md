# Optimizations

## Multi scalar multiplication

`RistrettoPoint::vartime_multiscalar_mul` has been used in favour of `RistrettoPoint::multiscalar_mul` as it has been 
optimized for multi-scalar multiplication by using Straus for vector lengths under 190 and Pippenger above (see
[dalek-cryptography/curve25519-dalek #249](https://github.com/dalek-cryptography/curve25519-dalek/pull/249). Vector 
lengths used for various multi-scalar multiplications for two different batches of 64-bit aggregated proofs are shown.

**Batch with increasing number of aggregated proofs:**
```
Batch: [1, 2, 4, 8]
prove:         multiscalar_mul lengths: 129
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
prove:         multiscalar_mul lengths: 257
inner product: multiscalar_mul lengths: 130
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
prove:         multiscalar_mul lengths: 513
inner product: multiscalar_mul lengths: 258
inner product: multiscalar_mul lengths: 130
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
prove:         multiscalar_mul lengths: 1025
inner product: multiscalar_mul lengths: 514
inner product: multiscalar_mul lengths: 258
inner product: multiscalar_mul lengths: 130
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
verify:        multiscalar_mul lengths: 1113
```

**Batch with single proofs:**
```
Batch: [1, 1, 1, 1, 1]
prove:         multiscalar_mul lengths: 129
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
prove:         multiscalar_mul lengths: 129
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
prove:         multiscalar_mul lengths: 129
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
prove:         multiscalar_mul lengths: 129
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
prove:         multiscalar_mul lengths: 129
inner product: multiscalar_mul lengths: 66
inner product: multiscalar_mul lengths: 34
inner product: multiscalar_mul lengths: 18
inner product: multiscalar_mul lengths: 10
inner product: multiscalar_mul lengths: 6
inner product: multiscalar_mul lengths: 4
verify:        multiscalar_mul lengths: 210
```

## Benches

Creating 

