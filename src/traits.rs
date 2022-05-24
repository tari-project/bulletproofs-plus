// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

/// Abstrations for any type that can be represented as 32 bytes
pub trait FixedBytesRepr {
    /// Returns a reference to the 32-byte representation
    fn as_fixed_bytes(&self) -> &[u8; 32];

    /// Converts a 32-byte representation to an instance of this type
    fn from_fixed_bytes(bytes: [u8; 32]) -> Self;
}

/// Abstraction for any type that can be constructed from 64 uniformly-random bytes.
pub trait FromUniformBytes {
    /// Convert uniformly random bytes to an instance of this type.
    fn from_uniform_bytes(bytes: &[u8; 64]) -> Self;
}

/// Abstraction for any type that has a compressed representation.
pub trait Compressable {
    /// The type resulting from the compression.
    type Compressed: Copy + Decompressable<Decompressed = Self>;

    /// Compress this instance.
    fn compress(&self) -> Self::Compressed;
}

/// Abstraction for any type that has a decompressed representation.
pub trait Decompressable {
    /// The type resulting from the decompression.
    type Decompressed: Compressable<Compressed = Self>;

    /// Try decompress this instance. None is returned if this fails.
    fn decompress(&self) -> Option<Self::Decompressed>;
}
