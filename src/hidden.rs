// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use derive_more::{Deref, DerefMut, From};
use std::fmt;

#[derive(From, Deref, DerefMut)]
pub struct Hidden<T> {
    inner: T,
}

impl<T> fmt::Debug for Hidden<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hidden<{}>", std::any::type_name::<T>())
    }
}
