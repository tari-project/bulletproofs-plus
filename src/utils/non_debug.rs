// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ add 'Debug' functionality to other struct members that do not implement 'Debug'

use std::fmt;

use derive_more::{AsMut, AsRef, Deref, DerefMut, From};

/// A struct to add 'Debug' functionality to other struct members that do not implement 'Debug'
#[derive(Copy, Clone, From, Deref, DerefMut, AsRef, AsMut)]
pub struct NonDebug<T> {
    inner: T,
}

/// Custom implementation for 'Debug'
impl<T> fmt::Debug for NonDebug<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hidden<{}>", std::any::type_name::<T>())
    }
}
