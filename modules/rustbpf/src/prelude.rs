#[cfg(any(target_arch = "bpf", target_arch = "wasm32"))]
pub use crate::{eprint, eprintln, print, println};

#[cfg(not(any(target_arch = "bpf", target_arch = "wasm32")))]
extern crate std;
#[cfg(not(any(target_arch = "bpf", target_arch = "wasm32")))]
pub use std::{eprint, eprintln, print, println};

pub use alloc::{format, vec};
pub use alloc::vec::Vec;
pub use core::prelude::*;
