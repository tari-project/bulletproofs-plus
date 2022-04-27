// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ add 'Debug' functionality to other struct members that do not implement 'Debug'

use std::fmt;

use derive_more::{Deref, DerefMut, From};

/// A struct to add 'Debug' functionality to other struct members that do not implement 'Debug'
#[derive(From, Deref, DerefMut)]
pub struct Hidden<T> {
    inner: T,
}

/// Custom implementation for 'Debug'
impl<T> fmt::Debug for Hidden<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hidden<{}>", std::any::type_name::<T>())
    }
}
