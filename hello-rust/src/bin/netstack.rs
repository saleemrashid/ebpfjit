#![no_std]
#![no_main]
extern crate alloc;

use rustbpf::prelude::*;

use core::num::NonZeroUsize;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, AnySocket},
    time::{Duration, Instant},
    wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, IpCidr, IpEndpoint, IpProtocol,
        Ipv4Address, Ipv4Packet, TcpPacket,
    },
};

extern "C" {
    fn tap_rx_wait(micros: u64, ...);
    fn tap_rx(ptr: *mut u8, len: usize, ...) -> usize;
    fn tap_tx(ptr: *const u8, len: usize, ...);
    fn micros() -> i64;
}

fn now() -> Instant {
    Instant::from_micros(unsafe { micros() })
}

fn parse_tcp_syn(buf: &mut [u8]) -> Option<IpEndpoint> {
    let mut frame = EthernetFrame::new_checked(buf).ok()?;
    if frame.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }

    let mut ipv4_packet = Ipv4Packet::new_checked(frame.payload_mut()).ok()?;
    if ipv4_packet.next_header() != IpProtocol::Tcp {
        return None;
    }
    let dst_addr = ipv4_packet.dst_addr();

    let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload_mut()).ok()?;
    if !tcp_packet.syn() || tcp_packet.ack() {
        return None;
    }
    let dst_port = tcp_packet.dst_port();

    Some(IpEndpoint::new(dst_addr.into(), dst_port))
}

#[no_mangle]
extern "C" fn netstack_loop() {
    println!("ready from eBPF!");
    let mut device = Phy::<1536>::new();
    let config = Config::new(EthernetAddress([0xde, 0xad, 0xbe, 0xef, 0x12, 0x34]).into());

    let mut iface = Interface::new(config, &mut device, now());
    let addr = Ipv4Address::new(0, 0, 0, 0);
    iface.routes_mut().add_default_ipv4_route(addr).unwrap();
    iface.update_ip_addrs(|ip_addrs| {
        let ip_addr = IpCidr::new(addr.into(), 0);
        ip_addrs.push(ip_addr).unwrap();
    });
    iface.set_any_ip(true);

    let mut sockets = SocketSet::new(Vec::new());
    loop {
        if let Some(endpoint) = device.peek().and_then(parse_tcp_syn) {
            let rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
            let tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
            let mut sock = tcp::Socket::new(rx_buffer, tx_buffer);
            sock.listen(endpoint).unwrap();
            sockets.add(sock);
        }

        iface.poll(now(), &mut device, &mut sockets);

        let mut closed_sockets = vec![];
        sockets
            .iter_mut()
            .filter_map(|(handle, sock)| {
                let tcp_sock = tcp::Socket::downcast_mut(sock)?;
                if let tcp::State::Listen | tcp::State::Closed = tcp_sock.state() {
                    closed_sockets.push(handle);
                    None
                } else if tcp_sock.state() == tcp::State::TimeWait {
                    tcp_sock.abort();
                    None
                } else {
                    bool::then_some(tcp_sock.can_send(), tcp_sock)
                }
            })
            .for_each(|sock| {
                while sock.can_recv() {
                    sock.recv(|buf| (buf.len(), ())).unwrap();
                }
                sock.send_slice(b"HTTP/1.1 200 OK\r\n\r\nHello\n").unwrap();
                sock.close();
            });

        closed_sockets.into_iter().for_each(|handle| {
            sockets.remove(handle);
        });

        if let Some(delay) = iface.poll_delay(now(), &mut sockets) {
            if delay.total_micros() > 0 {
                device.wait(delay);
            }
        } else {
            device.wait(Duration::MAX);
        }
    }
}

struct Phy<const MTU: usize> {
    rx_buffer: [u8; MTU],
    tx_buffer: [u8; MTU],
    rx_length: Option<NonZeroUsize>,
}

impl<const MTU: usize> Phy<MTU> {
    fn new() -> Self {
        Phy {
            rx_buffer: [0; MTU],
            tx_buffer: [0; MTU],
            rx_length: None,
        }
    }

    fn wait(&self, delay: Duration) {
        unsafe { tap_rx_wait(delay.total_micros()) };
    }

    fn peek(&mut self) -> Option<&mut [u8]> {
        let len = self.rx_length.or_else(|| {
            NonZeroUsize::new(unsafe { tap_rx(self.rx_buffer.as_mut_ptr(), self.rx_buffer.len()) })
        });
        self.rx_length = len;
        len.map(|len| &mut self.rx_buffer[..len.get()])
    }
}

impl<const MTU: usize> Device for Phy<MTU> {
    type RxToken<'a> = PhyRxToken<'a>;
    type TxToken<'a> = PhyTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_length.take().map(|len| {
            (
                PhyRxToken(&mut self.rx_buffer[..len.get()]),
                PhyTxToken(&mut self.tx_buffer),
            )
        })
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(PhyTxToken(&mut self.tx_buffer))
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = MTU;
        caps.medium = Medium::Ethernet;
        caps
    }
}

struct PhyRxToken<'a>(&'a mut [u8]);

impl<'a> RxToken for PhyRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(self.0)
    }
}

struct PhyTxToken<'a>(&'a mut [u8]);

impl<'a> TxToken for PhyTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let buf: &mut [u8] = &mut self.0[..len];
        let result = f(buf);
        unsafe {
            tap_tx(buf.as_ptr(), buf.len());
        }
        result
    }
}
