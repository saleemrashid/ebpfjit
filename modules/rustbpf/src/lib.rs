#![cfg_attr(target_arch = "bpf", feature(lang_items))]
#![cfg_attr(target_arch = "bpf", feature(panic_info_message))]
#![no_std]

extern crate alloc;

#[cfg(target_arch = "bpf")]
mod bpf;
#[cfg(target_arch = "bpf")]
pub use bpf::*;

pub mod prelude;
