#![feature(lang_items)]
#![no_std]

extern crate alloc;

use core::{
    alloc::{GlobalAlloc, Layout},
    fmt::{Debug, Write},
};

extern "C" {
    // XXX(saleem): for some reason, Rust drops the arguments when it does fastcc?
    // Use variadics to force it to keep them.
    fn malloc(size: usize, ...) -> *mut u8;
    fn free(ptr: *mut u8, ...);
    fn write(fd: i32, buf: *const u8, count: usize, ...);
}

struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { malloc(layout.size()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { free(ptr) }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[derive(Copy, Clone)]
pub struct FdWriter(i32);

impl Write for FdWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { crate::write(self.0, s.as_ptr(), s.len()) };
        Ok(())
    }
}

pub static STDOUT: FdWriter = FdWriter(1);
pub static STDERR: FdWriter = FdWriter(2);

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use ::core::fmt::Write;
        let _ = ::core::write!($crate::STDOUT.clone(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use ::core::fmt::Write;
        let _ = ::core::writeln!($crate::STDOUT.clone(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        use ::core::fmt::Write;
        let _ = ::core::write!($crate::STDERR.clone(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use ::core::fmt::Write;
        let _ = ::core::writeln!($crate::STDERR.clone(), $($arg)*);
    }};
}

#[lang = "termination"]
trait Termination {
    fn report(self) -> i32;
}

impl Termination for () {
    fn report(self) -> i32 {
        0
    }
}

impl<T: Termination, E: Debug> Termination for Result<T, E> {
    fn report(self) -> i32 {
        match self {
            Ok(val) => val.report(),
            Err(err) => {
                eprintln!("Error: {err:?}");
                1
            }
        }
    }
}

#[lang = "start"]
fn lang_start<T: Termination + 'static>(
    main: fn() -> T,
    _argc: isize,
    _argv: *const *const u8,
    _sigpipe: u8,
) -> isize {
    main().report() as isize
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // XXX(saleem): handling this any other way generates "too many args" compilation errors
    unsafe { core::hint::unreachable_unchecked() }
}

pub mod prelude;
