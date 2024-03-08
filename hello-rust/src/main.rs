#![no_std]
#![no_main]

#[macro_use]
extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write;

extern "C" {
    fn malloc(size: usize, ...) -> *mut u8;
    fn free(ptr: *mut u8, ...);
    fn write(fd: i32, buf: *const u8, count: usize, ...);
}

struct Allocator;

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { malloc(layout.size()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { free(ptr) }
    }
}

#[derive(Copy, Clone)]
struct FdWriter(i32);

impl Write for FdWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { write(self.0, s.as_ptr(), s.len()) };
        Ok(())
    }
}

#[allow(unused)]
static STDOUT: FdWriter = FdWriter(1);

#[allow(unused)]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = write!(STDOUT.clone(), $($arg)*);
    }};
}

#[allow(unused)]
macro_rules! println {
    ($($arg:tt)*) => {{
        let _ = writeln!(STDOUT.clone(), $($arg)*);
    }};
}

#[no_mangle]
extern "C" fn main() -> i32 {
    let s = format!("hello");
    println!("s = {s}");
    println!("{:?}", try_main());
    0
}

fn try_main() -> Result<(), httparse::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let buf = b"GET /index.html HTTP/1.1\r\nHost: example.domain\r\n\r\n";
    let _ = req.parse(buf)?.unwrap();

    println!(
        "method = {:?}, path = {:?}, version = {:?}",
        req.method,
        req.path.unwrap(),
        req.version.unwrap()
    );

    req.headers.iter().for_each(|&header| {
        println!(
            "name = {:?}, value = {:?}",
            header.name,
            core::str::from_utf8(header.value).unwrap()
        )
    });

    /*
    unsafe {
        my_puts(s.as_ptr(), s.len());
        //printf("s = %s\n\0".as_ptr(), s.as_ptr());
        printf("\nhello %s\n\0".as_ptr(), "world\0".as_ptr());
    }*/

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
