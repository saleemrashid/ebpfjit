use core::{cmp::Ordering, fmt::Debug, iter, ops::Bound, alloc::{GlobalAlloc, Layout}};

extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
}
struct Allocator;

#[no_mangle]
pub static __rust_no_alloc_shim_is_unstable: u8 = 0;

#[no_mangle]
pub static __rust_alloc_error_handler_should_panic: u8 = 0;

#[no_mangle]
fn __rust_alloc_error_handler(size: usize, align: usize) -> ! {
    unsafe { core::hint::unreachable_unchecked() };
}

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

macro_rules! load_store {
    ($t: ty, $load:ident, $store:ident) => {
        #[no_mangle]
        extern "C" fn $load(src: *const $t) -> $t {
            unsafe { load(src) }
        }

        #[no_mangle]
        extern "C" fn $store(dst: *mut $t, src: $t) {
            unsafe { store(dst, src) }
        }
    }
}

load_store!(u8, load8, store8);
load_store!(u16, load16, store16);
load_store!(u32, load32, store32);
load_store!(u64, load64, store64);

const ADDR_BITS: u32 = 48;
const ADDR_MASK: u64 = (1 << ADDR_BITS) - 1;

const ENTRY_SHIFT: u32 = 24;
const ENTRY_MASK: u64 = (1 << ENTRY_SHIFT) - 1;

struct Region {
    start: u64,
    end: u64,
}

impl Region {
    const ADDR_BITS: u32 = 48;
    const ADDR_MASK: u64 = (1 << Self::ADDR_BITS) - 1;

    // const SIZE_BITS: u32 = u64::BITS - Self::ADDR_BITS;
    // const SIZE_MASK: u64 = (1 << Self::SIZE_BITS) - 1;

    pub fn new(start: u64, end: u64) -> Self {
        assert!(start & !Self::ADDR_MASK == 0);
        assert!(end & !Self::ADDR_MASK == 0);
        assert!(start < end);

        Self {
            start: start,
            end: end,
        }

        // let size = end - start;
        // assert!(size & !Self::SIZE_MASK == 0);

        // Self((start >> Self::ADDR_BITS) << Self::SIZE_BITS | size)
    }

    pub fn start(&self) -> u64 {
        // self.0 >> Self::SIZE_BITS
        self.start
    }

    pub fn end(&self) -> u64 {
        // self.start() + self.size()
        self.end
    }

    // pub fn size(&self) -> u64 {
    //     self.0 & Self::SIZE_MASK
    // }

    pub fn compare(&self, start: u64, end: u64) -> Ordering {
        if self.start() >= end {
            Ordering::Greater
        } else if self.end() < start {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }
}

impl Debug for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Region")
            .field("start", &format_args!("0x{:x}", self.start()))
            .field("end", &format_args!("0x{:x}", self.end()))
            .finish()
    }
}

#[derive(Debug)]
pub struct Regions {
    data: Vec<Region>
}

impl Regions {
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
        }
    }

    pub fn set(&mut self, start: u64, end: u64) {
        assert!(start < end);
        let (start_bound, start) = match self.data.binary_search_by(|region| region.start().cmp(&start)) {
            Ok(index) => (Bound::Included(index), self.data[index].start()),
            Err(index) => (Bound::Excluded(index), start),
        };
        let (end_bound, end) = match self.data.binary_search_by(|region| region.end().cmp(&(end - 1))) {
            Ok(index) => (Bound::Included(index), self.data[index].end()),
            Err(index) => (Bound::Excluded(index + 1), end),
        };
        match (start_bound, end_bound) {
            (Bound::Excluded(start_index), Bound::Excluded(end_index)) if start_index + 1 == end_index => {
                self.data.insert(start_index, Region::new(start, end));
            }
            _ => {
                self.data.splice((start_bound, end_bound), iter::once(Region::new(start, end)));
            }
        }
    }

    pub fn check(&mut self, start: u64, end: u64) -> bool {
        self.data.binary_search_by(|region| region.compare(start, end)).is_ok()
    }
}

static mut REGIONS: Regions = Regions::new();

#[no_mangle]
extern "C" fn my_malloc(mut size: usize) -> *mut u8 {
    if size & 7 != 0 {
        size += size & 7;
    }
    let ptr = unsafe { malloc(size) };
    // eprintln!("my_malloc({size}) = {:?}", ptr);
    let start = ptr as usize;
    allow_region(start, start + size);
    ptr
}

#[no_mangle]
extern "C" fn my_free(ptr: *mut u8) {
    // eprintln!("my_free");
    // let start = ptr as usize;
    // unsafe { free(ptr) };
}

#[no_mangle]
extern "C" fn allow_region(start: usize, end: usize) {
    // eprintln!("allowing 0x{start:x}-0x{end:x}");
    unsafe {
        REGIONS.set(start as u64, end as u64);
        // eprintln!("regions = {REGIONS:?}");
        /* assert!(REGIONS.check(start as u64, end as u64));
        for i in start..end {
            assert!(REGIONS.check(i as u64, (i+1) as u64));
        } */
    }
    // eprintln!("allowed: {}", unsafe { REGIONS.len() });
}

#[no_mangle]
extern "C" fn unallow_region(start: usize, end: usize) {
    // eprintln!("unallowing 0x{start:x}-0x{end:x}");
    // unsafe { REGIONS.unallow(start as u64, end as u64); assert!(!REGIONS.check(start as u64, end as u64)); }
    // eprintln!("allowed: {}", unsafe { REGIONS.len() });
}

unsafe fn load<T>(src: *const T) -> T {
    let start = src as usize as u64;
    let end = start + core::mem::size_of::<T>() as u64;

    if unsafe { !REGIONS.check(start, end) } {
        unsafe { eprintln!("{REGIONS:?}"); }
        eprintln!("access not permitted, 0x{:x}-0x{:x}", start, end);
        unsafe { core::arch::asm!("udf #0"); }
    }

    core::ptr::read(src)
}

unsafe fn store<T>(dst: *mut T, src: T) {
    let start = dst as usize as u64;
    let end = start + core::mem::size_of::<T>() as u64;

    if unsafe { !REGIONS.check(start, end) } {
        unsafe { eprintln!("{REGIONS:?}"); }
        eprintln!("access not permitted, 0x{:x}-0x{:x}", start, end);
        unsafe { core::arch::asm!("udf #0"); }
    }

    core::ptr::write(dst, src)
}
