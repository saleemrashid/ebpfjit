use core::fmt::Write;

extern "C" {
    // XXX(saleem): for some reason, Rust drops the arguments when it does fastcc?
    // Use variadics to force it to keep them.
    #[cfg(target_arch = "bpf")]
    fn write(fd: i32, buf: *const u8, count: usize, ...);

    #[cfg(not(target_arch = "bpf"))]
    fn write(fd: i32, buf: *const u8, count: usize);
}

#[derive(Copy, Clone)]
pub struct FdWriter(i32);

impl Write for FdWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { write(self.0, s.as_ptr(), s.len()) };
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
