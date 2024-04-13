#![feature(lang_items)]
#![feature(panic_info_message)]
#![no_std]

extern crate alloc;

use linked_list_allocator::Heap;

use core::{
    alloc::{GlobalAlloc, Layout},
    fmt::{Debug, Write},
    ptr,
};

extern "C" {
    // XXX(saleem): for some reason, Rust drops the arguments when it does fastcc?
    // Use variadics to force it to keep them.
    fn shim_heap_start() -> *mut u8;
    fn shim_heap_size() -> usize;
    fn write(fd: i32, buf: *const u8, count: usize, ...);
}

static mut HEAP: Option<Heap> = None;

unsafe fn heap() -> &'static mut Heap {
    HEAP.get_or_insert_with(|| {
        unsafe { Heap::new(shim_heap_start(), shim_heap_size()) }
    })
}

struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { heap().allocate_first_fit(layout) }.unwrap().as_ptr()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { heap().deallocate(ptr::NonNull::new(ptr).unwrap(), layout) }
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
fn panic(info: &core::panic::PanicInfo) -> ! {
    // XXX(saleem): handling this any other way generates "too many args" compilation errors
    eprintln!("panic! at the {:?}", info.message());
    loop {}
    unsafe { core::hint::unreachable_unchecked() }
}

pub mod prelude;
