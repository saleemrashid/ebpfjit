use smoltcp::{
    phy::{self, Device, Medium, RxToken, TunTapInterface, TxToken},
    time::{Duration, Instant},
};
use std::env;
use std::error::Error;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::process;
use std::slice;

#[cfg(feature = "wasmtime")]
use wasmtime::*;

#[allow(unused_imports)]
#[cfg(feature = "native")]
use netstack::*;

static mut TAP_INTERFACE: Option<TunTapInterface> = None;

#[cfg(not(feature = "wasmtime"))]
extern "C" {
    fn netstack_loop();
}

const USAGE: &'static str = "usage: ./runner INTERFACE\n";

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args = env::args().collect::<Vec<_>>();

    if args.len() != 2 {
        eprint!("{}", USAGE);
        process::exit(1);
    }

    let interface = &args[1];

    unsafe {
        TAP_INTERFACE = Some(TunTapInterface::new(interface, Medium::Ethernet)?);
    }

    run_loop()
}

#[cfg(not(feature = "wasmtime"))]
fn run_loop() -> Result<(), Box<dyn Error>> {
    unsafe {
        netstack_loop();
    }
    Ok(())
}

#[cfg(feature = "wasmtime")]
fn get_memory<'a, T>(caller: &mut Caller<'a, T>) -> Option<Memory> {
    caller.get_export("memory")?.into_memory()
}

#[cfg(feature = "wasmtime")]
fn run_loop() -> Result<(), Box<dyn Error>> {
    let engine = Engine::new(Config::default().profiler(ProfilingStrategy::PerfMap))?;
    let module = Module::new(
        &engine,
        include_bytes!("../../modules/target/wasm32-unknown-unknown/release/netstack.wasm"),
    )?;

    let mut linker = Linker::new(&engine);
    linker.func_wrap("env", "micros", || micros())?;
    linker.func_wrap("env", "tap_rx_wait", |micros| tap_rx_wait(micros))?;
    linker.func_wrap(
        "env",
        "tap_rx",
        |mut caller: Caller<'_, _>, addr: u32, len: u32| -> u32 {
            let memory = get_memory(&mut caller).unwrap();

            unsafe {
                let ptr = memory.data_ptr(caller).add(addr as usize);
                tap_rx(ptr, len as usize) as u32
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "tap_tx",
        |mut caller: Caller<'_, _>, addr: u32, len: u32| {
            let memory = get_memory(&mut caller).unwrap();

            unsafe {
                let ptr = memory.data_ptr(caller).add(addr as usize);
                tap_tx(ptr, len as usize)
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "write",
        |mut caller: Caller<'_, _>, fd: i32, addr: u32, len: u32| {
            let memory = get_memory(&mut caller).unwrap();

            let start = addr as usize;
            let end = start + len as usize;
            let buf = &memory.data(&caller)[start..end];

            match fd {
                1 => {
                    io::stdout().write(buf);
                }
                2 => {
                    io::stderr().write(buf);
                }
                _ => {}
            };
        },
    )?;

    let mut store = Store::new(&engine, ());
    let instance = linker.instantiate(&mut store, &module)?;

    let netstack_loop = instance.get_typed_func::<(), ()>(&mut store, "netstack_loop")?;
    netstack_loop.call(&mut store, ())?;

    Ok(())
}

#[no_mangle]
extern "C" fn micros() -> i64 {
    Instant::now().total_micros()
}

#[no_mangle]
extern "C" fn tap_rx_wait(micros: u64) {
    let Some(tap) = (unsafe { TAP_INTERFACE.as_mut() }) else {
        return;
    };
    let duration = Duration::from_micros(micros);
    phy::wait(
        tap.as_raw_fd(),
        bool::then_some(duration != Duration::MAX, duration),
    )
    .unwrap();
}

#[no_mangle]
extern "C" fn tap_rx(ptr: *mut u8, len: usize) -> usize {
    let dst = unsafe { slice::from_raw_parts_mut(ptr, len) };

    let Some(tap) = (unsafe { TAP_INTERFACE.as_mut() }) else {
        return 0;
    };
    let Some((rx_token, _tx_token)) = tap.receive(Instant::ZERO) else {
        return 0;
    };

    rx_token.consume(|buf| {
        let n = buf.len();
        dst[..n].copy_from_slice(&buf);
        n
    })
}

#[no_mangle]
extern "C" fn tap_tx(ptr: *const u8, len: usize) {
    let src = unsafe { slice::from_raw_parts(ptr, len) };

    let Some(tap) = (unsafe { TAP_INTERFACE.as_mut() }) else {
        return;
    };

    let tx_token = tap.transmit(Instant::ZERO).unwrap();

    tx_token.consume(src.len(), |buf| {
        buf.copy_from_slice(&src);
    })
}
