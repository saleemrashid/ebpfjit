#[cfg(target_arch = "bpf")]
pub use crate::{eprint, eprintln, print, println};

pub use alloc::{format, vec};
pub use alloc::vec::Vec;
pub use core::prelude::*;
