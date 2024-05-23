use std::env;

const PACKAGES: &'static [&'static str] = &["netstack"];

#[derive(Clone, Copy)]
enum Mode {
    Default,
    Native,
    Unchecked,
    FourGB,
    Wasmtime,
}

fn main() {
    let native = env::var("CARGO_FEATURE_NATIVE").is_ok();
    let unchecked = env::var("CARGO_FEATURE_UNCHECKED").is_ok();
    let fourgb = env::var("CARGO_FEATURE_4GB").is_ok();
    let wasmtime = env::var("CARGO_FEATURE_WASMTIME").is_ok();

    let modes = [
        native.then(|| Mode::Native),
        unchecked.then(|| Mode::Unchecked),
        fourgb.then(|| Mode::FourGB),
        wasmtime.then(|| Mode::Wasmtime),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    let mode = match modes[..] {
        [] => Mode::Default,
        [x] => x,
        _ => panic!("mutually exclusive features"),
    };

    match mode {
        Mode::Native | Mode::Wasmtime => {}
        _ => {
            let mut target = env::current_dir().unwrap();
            target.push("../modules/target");
            println!("cargo:rustc-link-search=native={}", target.display());

            for package in PACKAGES {
                let (library, dylib) = match mode {
                    Mode::Default => (package.to_string(), false),
                    Mode::Native | Mode::Wasmtime => unreachable!(),
                    Mode::Unchecked => (format!("{package}-unchecked"), false),
                    Mode::FourGB => (format!("{package}-4gb"), true),
                };

                let filename = if dylib {
                    format!("{}/lib{library}.so", target.display())
                } else {
                    format!("{}/lib{library}.a", target.display())
                };
                println!("cargo:rerun-if-changed={filename}");

                if dylib {
                    println!("cargo:rustc-link-lib=dylib={library}");
                } else {
                    println!("cargo:rustc-link-lib=static={library}");
                }
            }
        }
    }
}
