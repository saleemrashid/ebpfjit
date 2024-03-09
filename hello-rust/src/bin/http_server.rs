#![no_std]

use rustbpf::prelude::*;

fn main() -> Result<(), httparse::Error> {
    let mut headers = vec![httparse::EMPTY_HEADER; 64];
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

    Ok(())
}
