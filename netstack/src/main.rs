use std::error::Error;

use smoltcp::{
    phy::{self, Device, Medium, RxToken, TunTapInterface, TxToken},
    time::{Duration, Instant},
};
use std::os::fd::AsRawFd;
use std::slice;

//mod netstack;

static mut TAP_INTERFACE: Option<TunTapInterface> = None;

#[link(name = "netstack", kind = "static")]
extern "C" {
    fn netstack_loop();
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    unsafe {
        TAP_INTERFACE = Some(TunTapInterface::new("tap0", Medium::Ethernet)?);
    }

    unsafe {
        netstack_loop();
    }
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
