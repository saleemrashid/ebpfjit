use std::{collections::BTreeSet, default, mem::size_of};

use bitvec::{bitbox, boxed::BitBox};

extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
}

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

const ADDR_BITS: u32 = 48;
const ADDR_MASK: u64 = (1 << ADDR_BITS) - 1;

const ENTRY_SHIFT: u32 = 24;
const ENTRY_MASK: u64 = (1 << ENTRY_SHIFT) - 1;

pub struct Regions {
    entries: [Option<BitBox>; 1 << (ADDR_BITS - ENTRY_SHIFT)]
}

impl Regions {
    const ARRAY_REPEAT_VALUE: Option<BitBox> = None;

    pub const fn new() -> Self {
        Self {
            entries: [Self::ARRAY_REPEAT_VALUE; 1 << (ADDR_BITS - ENTRY_SHIFT)]
        }
    }

    #[inline]
    fn indices(addr: u64) -> (usize, usize) {
        assert!(addr & !ADDR_MASK == 0);
        ((addr >> ENTRY_SHIFT) as usize, (addr & ENTRY_MASK) as usize)
    }

    #[inline]
    fn entry_mut(&mut self, idx: usize) -> &mut BitBox {
        self.entries[idx].get_or_insert_with(|| bitbox![0; (1 << ENTRY_SHIFT)])
    }

    fn set(&mut self, start: u64, end: u64, value: bool) {
        assert!(start <= end);
        let (start_entry, start_offset) = Self::indices(start);
        let (end_entry, end_offset) = Self::indices(end);

        if start_entry == end_entry {
            self.entry_mut(start_entry)[start_offset..end_offset].fill(value);
        } else {
            self.entry_mut(start_entry)[start_offset..].fill(value);
            for entry in start_entry + 1..end_entry {
                self.entry_mut(entry).fill(value);
            }
            self.entry_mut(end_entry)[..end_offset].fill(value)
        }
    }

    pub fn allow(&mut self, start: u64, end: u64) {
        self.set(start, end, true)
    }

    pub fn unallow(&mut self, start: u64, end: u64) {
        self.set(start, end, false)
    }

    pub fn check(&self, start: u64, end: u64) -> bool {
        assert!(start <= end);
        let (start_entry, start_offset) = Self::indices(start);
        let (end_entry, end_offset) = Self::indices(end);

        if start_entry == end_entry {
            self.entries[start_entry].as_ref().map_or(false, |x| x[start_offset..end_offset].all())
        } else {
            if self.entries[start_entry].as_ref().map_or(true, |x| x[start_offset..].not_all()) {
                return false
            }
            for entry in start_entry + 1..end_entry {
                if self.entries[entry].as_ref().map_or(true, |x| x.not_all()) {
                    return false
                }
            }
            if self.entries[end_entry].as_ref().map_or(true, |x| x[..end_offset].not_all()) {
                return false
            }
            true
        }
    }
}

static mut REGIONS: Regions = Regions::new();

#[no_mangle]
extern "C" fn my_malloc(size: usize) -> *mut u8 {
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
        REGIONS.allow(start as u64, end as u64);
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

    /*if unsafe { !REGIONS.check(start, start + 1) } {
        eprintln!("access not permitted, 0x{:x}-0x{:x}", start, end);
        unsafe { core::arch::asm!("udf #0"); }
    }*/
    
    core::ptr::read(src)
}

unsafe fn store<T>(dst: *mut T, src: T) {
    let start = dst as usize as u64;
    let end = start + core::mem::size_of::<T>() as u64;

    /*if unsafe { !REGIONS.check(start, start + 1) } {
        eprintln!("access not permitted, 0x{:x}-0x{:x}", start, end);
        unsafe { core::arch::asm!("udf #0"); }
    }*/

    core::ptr::write(dst, src)
}

load_store!(u8, load8, store8);
load_store!(u16, load16, store16);
load_store!(u32, load32, store32);
load_store!(u64, load64, store64);
