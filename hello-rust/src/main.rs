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

static STDOUT: FdWriter = FdWriter(1);

#[no_mangle]
extern "C" fn main() {
    let s = format!("hello");
    let _ = writeln!(STDOUT.clone(), "s = {s}");

    /*
    unsafe {
        printf("s = %p\n\0".as_ptr(), s.as_ptr());
    }*/
    if let Err(e) = try_main() {
        /*
        let s = format!("{:?}\0", e);
        unsafe {
            my_puts(s.as_ptr(), s.len());
        }*/
    }
}

fn try_main() -> Result<(), httparse::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let buf = b"GET /index.html HTTP/1.1\r\nHost: example.domain\r\n\r\n";
    let _ = req.parse(buf)?.unwrap();

    let s = req.path.unwrap();
    let _ = STDOUT.clone().write_str(s);
    let _ = STDOUT.clone().write_char('\n');

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
